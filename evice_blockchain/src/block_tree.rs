// evice_blockchain/src/block_tree.rs

use crate::blockchain::{Block, Blockchain, BlockchainError};
use crate::consensus::VelocityVote;
use crate::state::Account;
use crate::Address;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum BlockProcessingResult {
    Success {
        block_hash: Vec<u8>,
        post_state_root: Vec<u8>,
        changed_accounts: BTreeMap<Address, Account>,
    },
    Failure {
        block_hash: Vec<u8>,
        error: BlockchainError,
        is_fatal: bool,
    },
    ParentStateNotReady {
        block_hash: Vec<u8>,
        parent_hash: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockNodeStatus {
    ProcessingDependencies,
    ProcessingSelf, 
    StateReady, 
    Failed,     
}

#[derive(Clone, Debug)]
pub struct BlockNode {
    pub block: Block,
    pub parent_hash: Vec<u8>,
    pub status: BlockNodeStatus,
    pub post_state_root: Vec<u8>,
    pub weight: u64,
    pub children_ref_count: Arc<AtomicUsize>,
}

pub struct BlockTree {
    nodes: HashMap<Vec<u8>, Arc<BlockNode>>,
    height_to_hashes: HashMap<u64, Vec<Vec<u8>>>,
    latest_votes: HashMap<Address, Vec<u8>>,
    finalized_head: Arc<BlockNode>,
    finalized_height: u64,
    processing_result_tx: mpsc::Sender<BlockProcessingResult>,
    children_map: HashMap<Vec<u8>, Vec<Vec<u8>>>,
}

impl BlockTree {
    pub fn new(genesis_block: Block, processing_result_tx: mpsc::Sender<BlockProcessingResult>) -> Self {
        let genesis_hash = genesis_block.header.calculate_hash();
        let genesis_node = Arc::new(BlockNode {
            status: BlockNodeStatus::StateReady,
            post_state_root: genesis_block.header.state_root.clone(),
            parent_hash: genesis_block.header.prev_hash.clone(),
            block: genesis_block,
            weight: 0,
            children_ref_count: Arc::new(AtomicUsize::new(0)),
        });

        let mut nodes = HashMap::new();
        nodes.insert(genesis_hash.clone(), genesis_node.clone());

        let mut height_to_hashes = HashMap::new();
        height_to_hashes.insert(0, vec![genesis_hash]);

        Self {
            nodes,
            height_to_hashes,
            latest_votes: HashMap::new(),
            finalized_head: genesis_node,
            finalized_height: 0,
            processing_result_tx, 
            children_map: HashMap::new(),
        }
    }

    pub async fn insert_and_process_block(
        &mut self,
        block: Block,
        blockchain: Arc<tokio::sync::RwLock<Blockchain>>,
    ) -> Result<(), BlockchainError> {
        let block_hash = block.header.calculate_hash();
        if self.nodes.contains_key(&block_hash) {
            return Ok(());
        }

        let parent_hash = block.header.prev_hash.clone(); 
        let parent_node = self
            .nodes
            .get(&parent_hash) 
            .cloned() 
            .ok_or_else(|| BlockchainError::MissingParent {
                parent_hash: parent_hash.clone(),
            })?;

        let block_height = block.header.index;
        let new_node_status;

        match parent_node.status {
            BlockNodeStatus::StateReady => {
                new_node_status = BlockNodeStatus::ProcessingSelf; 
            }
            BlockNodeStatus::ProcessingDependencies | BlockNodeStatus::ProcessingSelf => {
                let _ = self.processing_result_tx.send(BlockProcessingResult::ParentStateNotReady {
                    block_hash: block_hash.clone(),
                    parent_hash: parent_hash.clone(),
                }).await;

                new_node_status = BlockNodeStatus::ProcessingDependencies; 
            }
            BlockNodeStatus::Failed => {
                return Err(BlockchainError::LogicError(
                    "Mencoba membangun di atas blok induk yang state-nya gagal diproses.".into(),
                ));
            }
        }

        let new_node = Arc::new(BlockNode {
            block: block.clone(),
            parent_hash: parent_hash.clone(),
            status: new_node_status.clone(), 
            post_state_root: vec![],
            weight: parent_node.weight, 
            children_ref_count: Arc::new(AtomicUsize::new(0)),
        });

        parent_node.children_ref_count.fetch_add(1, Ordering::Relaxed);

        self.children_map.entry(parent_hash.clone()).or_default().push(block_hash.clone());

        self.nodes.insert(block_hash.clone(), Arc::clone(&new_node)); 
        self.height_to_hashes.entry(block_height).or_default().push(block_hash.clone());

        if new_node_status == BlockNodeStatus::ProcessingSelf {
            let parent_state_root = parent_node.post_state_root.clone();
            self.spawn_processing_task(blockchain, new_node, parent_state_root).await; 
        }

        Ok(())
    }

    async fn spawn_processing_task(
        &self,
        blockchain: Arc<tokio::sync::RwLock<Blockchain>>,
        node_to_process: Arc<BlockNode>, 
        parent_state_root: Vec<u8>,
    ) {
        let result_tx = self.processing_result_tx.clone();
        let block_hash = node_to_process.block.header.calculate_hash(); 
        let block_clone = node_to_process.block.clone(); 

        tokio::spawn(async move {
            let expected_state_root = block_clone.header.state_root.clone();
            let result = tokio::task::spawn_blocking(move || {
    
                let rt = tokio::runtime::Handle::current();
                rt.block_on(async {
                    let blockchain_guard = blockchain.read().await;
                    let parent_session_result = blockchain_guard.state.create_trie_session(
                        parent_state_root.as_slice().try_into().unwrap(), 
                        crate::state::COL_TRIE,
                    );

                    let validators = blockchain_guard.state.validators.clone();
                    let sequencers = blockchain_guard.state.active_sequencers.clone();
                    let l2_root = blockchain_guard.state.l2_state_root.clone();

                    blockchain_guard.apply_transactions_to_session(
                        parent_session_result,
                        &block_clone.header,
                        &block_clone.transactions,
                        &validators,
                        &sequencers,
                        &l2_root,
                    ).await
                })

            }).await; 

            match result {
                Ok(Ok((final_session, _final_valid_txs, changed_accounts))) => {
                    let post_state_root = final_session.root().to_vec();
                    if post_state_root != expected_state_root {
                        let _ = result_tx.send(BlockProcessingResult::Failure {
                            block_hash,
                            error: BlockchainError::StateRootMismatch {
                                expected: hex::encode(&expected_state_root),
                                got: hex::encode(&post_state_root),
                            },
                            is_fatal: true, 
                        }).await;
                    } else {
                        match final_session.commit() {
                            Ok(_root) => {
                                let _ = result_tx.send(BlockProcessingResult::Success {
                                    block_hash,
                                    post_state_root,
                                    changed_accounts, 
                                }).await;
                            }
                            Err(e) => {
                                log::error!("Gagal commit TrieSession untuk blok {}: {:?}", hex::encode(&block_hash[..4]), e);
                                let _ = result_tx.send(BlockProcessingResult::Failure {
                                    block_hash,
                                    error: BlockchainError::Trie(format!("Commit failed: {:?}", e)),
                                    is_fatal: true, 
                                }).await;
                            }
                        }
                    }
                }
                Ok(Err(e)) => { 
                    log::error!("Gagal apply_transactions_to_session untuk blok {}: {}", hex::encode(&block_hash[..4]), e);
                    let is_fatal = !matches!(e, BlockchainError::TransactionInvalid(_)); 
                    let _ = result_tx.send(BlockProcessingResult::Failure {
                        block_hash,
                        error: e,
                        is_fatal,
                    }).await;
                }
                Err(join_err) => { 
                    log::error!("Task pemrosesan state untuk blok {} gagal (panic?): {}", hex::encode(&block_hash[..4]), join_err);
                    let error_msg = if join_err.is_panic() {
                        match join_err.into_panic().downcast::<String>() {
                            Ok(s) => format!("Panic: {}", s),
                            Err(_) => "Panic: Pesan tidak diketahui".to_string(),
                        }
                    } else {
                        "Task dibatalkan".to_string()
                    };
                    let _ = result_tx.send(BlockProcessingResult::Failure {
                        block_hash,
                        error: BlockchainError::LogicError(error_msg),
                        is_fatal: true, 
                    }).await;
                }
            }
        });
    }

    pub fn update_node_status(
        &mut self, 
        result: BlockProcessingResult,
        blockchain: Arc<tokio::sync::RwLock<Blockchain>>,
    ) {
        match result {
            BlockProcessingResult::Success { block_hash, post_state_root, .. } => {
                let mut node_updated = false;
                if let Some(node_arc) = self.nodes.get_mut(&block_hash) {
                    if let Some(node) = Arc::get_mut(node_arc) {
                        if node.status != BlockNodeStatus::StateReady { 
                            node.status = BlockNodeStatus::StateReady;
                            node.post_state_root = post_state_root;
                            node_updated = true;
                        }
                    } else {
                        let mut cloned_node = (**node_arc).clone();
                        if cloned_node.status != BlockNodeStatus::StateReady {
                            cloned_node.status = BlockNodeStatus::StateReady;
                            cloned_node.post_state_root = post_state_root;
                            *node_arc = Arc::new(cloned_node); 
                            node_updated = true;
                        }
                    }
                }
                if node_updated {
                    self.process_dependent_children(&block_hash, blockchain);
                }
            }
            BlockProcessingResult::Failure { block_hash, error, is_fatal } => {
                if is_fatal {
                    if let Some(node_arc) = self.nodes.get_mut(&block_hash) {
                        if let Some(node) = Arc::get_mut(node_arc) {
                            if node.status != BlockNodeStatus::Failed {
                                node.status = BlockNodeStatus::Failed;
                                self.prune_failed_branch(&block_hash);
                            }
                        } else {
                            let mut cloned_node = (**node_arc).clone();
                            if cloned_node.status != BlockNodeStatus::Failed {
                                cloned_node.status = BlockNodeStatus::Failed;
                                *node_arc = Arc::new(cloned_node);
                                self.prune_failed_branch(&block_hash);
                            }
                        }
                    }
                } else {
                    if let Some(node_arc) = self.nodes.get_mut(&block_hash) {
                        if let Some(node) = Arc::get_mut(node_arc) {
                            node.status = BlockNodeStatus::Failed;
                        } else {
                            let mut cloned_node = (**node_arc).clone();
                            cloned_node.status = BlockNodeStatus::Failed;
                            *node_arc = Arc::new(cloned_node);
                        }
                    }
                    log::warn!("Blok {} gagal diproses (tidak fatal): {}", hex::encode(&block_hash[..4]), error);
                }
            }
            BlockProcessingResult::ParentStateNotReady { .. } => {
                // Tidak ada yang perlu dilakukan di sini
            }
         }
    }

    fn process_dependent_children(
        &mut self, 
        parent_hash: &[u8],
        blockchain: Arc<tokio::sync::RwLock<Blockchain>>,
    ) {
        if let Some(children_hashes) = self.children_map.get(parent_hash).cloned() {
            let parent_node = self.nodes.get(parent_hash).cloned();
            if parent_node.is_none() || parent_node.as_ref().unwrap().status != BlockNodeStatus::StateReady {
                return;
            }
            let parent_state_root = parent_node.unwrap().post_state_root.clone();

            for child_hash in children_hashes {
                let node_to_process_opt = self.nodes.get(&child_hash).cloned(); 
                if let Some(node_to_process) = node_to_process_opt {
                    let mut needs_spawn = false;
                    if let Some(node_mut) = Arc::get_mut(&mut self.nodes.get_mut(&child_hash).unwrap()) {
                        if node_mut.status == BlockNodeStatus::ProcessingDependencies {
                            node_mut.status = BlockNodeStatus::ProcessingSelf;
                            needs_spawn = true;
                        }
                    } else {
                        let mut cloned_node = (*node_to_process).clone();
                        if cloned_node.status == BlockNodeStatus::ProcessingDependencies {
                            cloned_node.status = BlockNodeStatus::ProcessingSelf;
                            self.nodes.insert(child_hash.clone(), Arc::new(cloned_node));
                            needs_spawn = true;
                        }
                    }

                    if needs_spawn {
                        log::info!("Parent {} state ready, spawning processing for child {}", hex::encode(&parent_hash[..4]), hex::encode(&child_hash[..4]));
                        let blockchain_clone = Arc::clone(&blockchain);
                        let tx_clone = self.processing_result_tx.clone();
                        let parent_state_root_clone = parent_state_root.clone();
                        let node_to_process_clone = self.nodes.get(&child_hash).unwrap().clone();

                        tokio::spawn(async move {
                            BlockTree::spawn_processing_task_static(
                                blockchain_clone,
                                node_to_process_clone,
                                parent_state_root_clone,
                                tx_clone
                            ).await;
                        });
                    }
                }
            }
        }
    }

    async fn spawn_processing_task_static(
        blockchain: Arc<tokio::sync::RwLock<Blockchain>>,
        node_to_process: Arc<BlockNode>,
        parent_state_root: Vec<u8>,
        result_tx: mpsc::Sender<BlockProcessingResult> 
    ) {
        let block_hash = node_to_process.block.header.calculate_hash();
        let block_clone = node_to_process.block.clone();
        let expected_state_root = block_clone.header.state_root.clone();

        tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Handle::current();
                rt.block_on(async {
                    let blockchain_guard = blockchain.read().await;

                    let parent_root_h256: crate::state::TrieRoot = parent_state_root
                        .as_slice()
                        .try_into()
                        .map_err(|_| BlockchainError::LogicError("Invalid parent root length in spawn_processing_task".to_string()))?;

                    let parent_session = blockchain_guard.state.create_trie_session( 
                        parent_root_h256,
                        crate::state::COL_TRIE,
                    );

                    let validators = blockchain_guard.state.validators.clone();
                    let sequencers = blockchain_guard.state.active_sequencers.clone();
                    let l2_root = blockchain_guard.state.l2_state_root.clone();

                    blockchain_guard.apply_transactions_to_session(
                        parent_session, 
                        &block_clone.header,
                        &block_clone.transactions,
                        &validators,
                        &sequencers,
                        &l2_root,
                    ).await
                })
            }).await; 

            match result {
                Ok(Ok((final_session, _final_valid_txs, changed_accounts))) => {
                    let post_state_root_vec = final_session.root().to_vec();
                    if post_state_root_vec != expected_state_root {
                        let _ = result_tx.send(BlockProcessingResult::Failure {
                            block_hash,
                            error: BlockchainError::StateRootMismatch {
                                expected: hex::encode(&expected_state_root),
                                got: hex::encode(&post_state_root_vec),
                            },
                            is_fatal: true,
                        }).await;
                    } else {
                        match final_session.commit() {
                            Ok(_root) => {
                                let _ = result_tx.send(BlockProcessingResult::Success {
                                    block_hash,
                                    post_state_root: post_state_root_vec, 
                                    changed_accounts, 
                                }).await;
                            }
                            Err(e) => {
                                log::error!("Gagal commit TrieSession untuk blok {}: {:?}", hex::encode(&block_hash[..4]), e);
                                let _ = result_tx.send(BlockProcessingResult::Failure {
                                    block_hash,
                                    error: BlockchainError::Trie(format!("Commit failed: {:?}", e)),
                                    is_fatal: true,
                                }).await;
                            }
                        }
                    }
                }
                Ok(Err(BlockchainError::State(e))) => { 
                    log::error!("Gagal membuat TrieSession untuk blok {}: {}", hex::encode(&block_hash[..4]), e);
                    let _ = result_tx.send(BlockProcessingResult::Failure {
                        block_hash,
                        error: BlockchainError::State(e),
                        is_fatal: true,
                    }).await;
                }
                Ok(Err(e)) => {
                    log::error!("Gagal apply_transactions_to_session untuk blok {}: {}", hex::encode(&block_hash[..4]), e);
                    let is_fatal = !matches!(e, BlockchainError::TransactionInvalid(_));
                    let _ = result_tx.send(BlockProcessingResult::Failure {
                        block_hash,
                        error: e,
                        is_fatal,
                    }).await;
                }
                Err(join_err) => {
                    log::error!("Task pemrosesan state untuk blok {} gagal (panic?): {}", hex::encode(&block_hash[..4]), join_err);
                    let error_msg = if join_err.is_panic() {
                        match join_err.into_panic().downcast::<String>() {
                            Ok(s) => format!("Panic: {}", s),
                            Err(p1) => match p1.downcast::<&str>() { 
                                Ok(s) => format!("Panic: {}", s),
                                Err(_) => "Panic: Pesan tidak diketahui".to_string(),
                            }
                        }
                    } else {
                        "Task dibatalkan".to_string()
                    };
                    let _ = result_tx.send(BlockProcessingResult::Failure {
                        block_hash,
                        error: BlockchainError::LogicError(error_msg),
                        is_fatal: true,
                    }).await;
                }
            }
        });
    }

    pub fn prune_failed_branch(&mut self, failed_block_hash: &[u8]) {
        let mut queue = VecDeque::new();
        queue.push_back(failed_block_hash.to_vec());
        let mut removed_hashes = HashSet::new();

        while let Some(hash_to_remove) = queue.pop_front() {
            if removed_hashes.contains(&hash_to_remove) {
                continue;
            }

            if let Some(removed_node) = self.nodes.remove(&hash_to_remove) {
                removed_hashes.insert(hash_to_remove.clone());
                log::warn!("[BlockTree] Memangkas blok yang gagal atau turunannya: 0x{}", hex::encode(&hash_to_remove[..4]));

                if let Some(hashes_at_height) = self.height_to_hashes.get_mut(&removed_node.block.header.index) {
                    hashes_at_height.retain(|h| h != &hash_to_remove);
                }

                if let Some(parent_node) = self.nodes.get(&removed_node.parent_hash) {
                    parent_node.children_ref_count.fetch_sub(1, Ordering::Relaxed);
                }
        
                if let Some(parent_children) = self.children_map.get_mut(&removed_node.parent_hash) {
                    parent_children.retain(|h| h != &hash_to_remove);
                }

                if let Some(children) = self.children_map.remove(&hash_to_remove) {
                    for child_hash in children {
                        queue.push_back(child_hash);
                    }
                }
            }
        }
    }
    
    pub fn apply_vote(&mut self, vote: &VelocityVote) {
        let voter = vote.voter_address;
        let new_vote_hash = vote.block_hash.clone();

        let old_vote_hash_owned = self.latest_votes.get(&voter).cloned();

        if let Some(old_vote_hash) = old_vote_hash_owned {
            if old_vote_hash != new_vote_hash {
                self.update_branch_weight(&old_vote_hash, -1);
            }
        }
        
        self.update_branch_weight(&new_vote_hash, 1);
        self.latest_votes.insert(voter, new_vote_hash);
    }
    
    fn update_branch_weight(&mut self, start_hash: &[u8], delta: i64) {
        let mut current_hash = start_hash.to_vec();
        while let Some(node_arc) = self.nodes.get_mut(&current_hash) {
            let node = Arc::make_mut(node_arc);
            if delta > 0 {
                node.weight = node.weight.saturating_add(delta as u64);
            } else {
                node.weight = node.weight.saturating_sub(delta.abs() as u64);
            }

            if current_hash == self.finalized_head.block.header.calculate_hash() {
                break; 
            }
            current_hash = node.parent_hash.clone();
        }
    }

    pub fn find_head(&self) -> Arc<BlockNode> {
        let mut head = self.finalized_head.clone();
        loop {
            let children = self.nodes.values().filter(|node| {
                node.parent_hash == head.block.header.calculate_hash() 
                && node.status == BlockNodeStatus::StateReady
            });
            
            if let Some(best_child) = children.max_by_key(|child| child.weight) {
                head = best_child.clone();
            } else {
                return head;
            }
        }
    }
    
    pub fn finalize(&mut self, finalized_hash: &[u8]) -> Result<(), BlockchainError> {
        let finalized_node = match self.nodes.get(finalized_hash).cloned() {
            Some(node) => node,
            None => return Err(BlockchainError::LogicError("Blok yang akan difinalisasi tidak ditemukan di BlockTree".into())),
        };

        if finalized_node.status != BlockNodeStatus::StateReady {
            return Err(BlockchainError::LogicError(format!(
                "Mencoba memfinalisasi blok 0x{} yang state-nya belum siap ({:?})",
                hex::encode(&finalized_hash[..4]), finalized_node.status
            )));
        }

        let mut nodes_to_keep = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(finalized_hash.to_vec());
        nodes_to_keep.insert(finalized_hash.to_vec());

        let mut current_ancestor_hash = finalized_node.parent_hash.clone();
        while finalized_node.block.header.index != 0 { 
            if let Some(ancestor_node) = self.nodes.get(&current_ancestor_hash) {
                if !nodes_to_keep.insert(current_ancestor_hash.clone()) {
                    break; 
                }
                if ancestor_node.block.header.index == 0 { break; } 
                current_ancestor_hash = ancestor_node.parent_hash.clone();
            } else {
                return Err(BlockchainError::LogicError(format!("Leluhur 0x{} tidak ditemukan saat finalisasi", hex::encode(&current_ancestor_hash[..4]))));
            }
        }

        let mut bfs_queue = VecDeque::new();
        bfs_queue.push_back(finalized_hash.to_vec());

        while let Some(parent_hash_bfs) = bfs_queue.pop_front() {
            if let Some(children) = self.children_map.get(&parent_hash_bfs) {
                for child_hash in children {
                    if nodes_to_keep.insert(child_hash.clone()) {
                        bfs_queue.push_back(child_hash.clone());
                    }
                }
            }
        }

        let mut parents_to_decrement = Vec::new();
        let mut removed_count = 0;

        let hashes_to_remove: Vec<Vec<u8>> = self.nodes.iter()
            .filter(|(hash, _)| !nodes_to_keep.contains(*hash))
            .map(|(hash, node)| {
                parents_to_decrement.push(node.parent_hash.clone());
                hash.clone()
            })
            .collect();

        for hash in &hashes_to_remove {
            if self.nodes.remove(hash).is_some() {
                log::trace!("[BlockTree Finalize] Memangkas node 0x{}", hex::encode(&hash[..4]));
                removed_count += 1;
            }
        }

        for parent_hash in parents_to_decrement {
            if let Some(parent_node) = self.nodes.get(&parent_hash) {
                parent_node.children_ref_count.fetch_sub(1, Ordering::Relaxed);
            }
        }

        self.children_map.retain(|_, children| { 
            children.retain(|child_hash| nodes_to_keep.contains(child_hash));
            !children.is_empty()
        });
        self.height_to_hashes.retain(|&height, hashes| { 
            hashes.retain(|h| nodes_to_keep.contains(h));
            height >= finalized_node.block.header.index && !hashes.is_empty()
        });

        log::info!(
            "[BlockTree Finalize] Finalisasi ke blok #{}, memangkas {} node.",
            finalized_node.block.header.index, removed_count
        );

        self.finalized_head = finalized_node; 
        self.finalized_height = self.finalized_head.block.header.index;

        Ok(())
    }

    pub fn get_ancestor_path(&self, start_hash: &[u8], end_ancestor_hash: &[u8]) -> Result<Vec<Block>, BlockchainError> {
        let mut path = VecDeque::new();
        let mut current_hash = start_hash.to_vec();

        while current_hash != end_ancestor_hash {
            if let Some(node) = self.nodes.get(&current_hash) {
                path.push_front(node.block.clone());
                current_hash = node.parent_hash.clone();
                if node.block.header.index == 0 && current_hash != end_ancestor_hash {
                    return Err(BlockchainError::LogicError("Jalur terputus, mencapai genesis sebelum menemukan leluhur akhir".into()));
                }
            } else {
                return Err(BlockchainError::LogicError(format!("Blok 0x{} tidak ditemukan saat menelusuri path", hex::encode(&current_hash[..4]))));
            }
        }
        Ok(path.into())
    }

    pub fn contains(&self, block_hash: &[u8]) -> bool {
        self.nodes.contains_key(block_hash)
    }

    pub fn is_block_ready(&self, block_hash: &[u8]) -> bool {
        self.nodes.get(block_hash)
            .map_or(false, |node| node.status == BlockNodeStatus::StateReady)
    }

    pub fn get_node(&self, block_hash: &[u8]) -> Option<&Arc<BlockNode>> {
        self.nodes.get(block_hash)
    }

    pub fn get_node_by_index(&self, index: u64) -> Option<&Arc<BlockNode>> {
        self.height_to_hashes
            .get(&index)
            .and_then(|hashes| hashes.first()) 
            .and_then(|hash| self.nodes.get(hash))
    }

    pub fn get_finalized_head(&self) -> Arc<BlockNode> {
        self.finalized_head.clone()
    }
}