// src/main.rs

use async_recursion::async_recursion;
use sha2::Digest;
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, Notify, mpsc, broadcast, oneshot};
use tokio::time::interval;
use tokio::select;
use tracing_log::LogTracer;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use log::{error, info, warn, debug};
use libp2p::PeerId;
use libp2p::identity::{Keypair as P2pKeypair, ed25519};
use clap::Parser;
use rand::{RngCore, SeedableRng, Rng, seq::SliceRandom};
use rpassword::read_password;
use blst::min_pk::SecretKey as BlsSecretKey;
use schnorrkel::SecretKey as SchnorrkelSecretKey;
use evice_blockchain::{
    blockchain::{
        Block, Blockchain, BlockchainError,
        ChainMessage, BlockHeader
    },
    consensus::{
        ConsensusMessage, VelocityVote, FinalityCertificate,
        FinalityVote, QuorumCertificate, ConsensusState, PendingBlock,
    },
    crypto::{self, KeyPair, ValidatorKeys, DkgState, public_key_to_address},
    p2p::{self, P2pCommand, SyncRequest, SyncResponse, AddressBook},
    block_tree::{BlockProcessingResult, BlockTree, BlockNodeStatus},
    state::COL_TRIE,
    genesis::{Genesis, GenesisAccount},
    snapshot::{self, SnapshotMetadata},
    keystore::Keystore,
    mempool::Mempool,
    metrics::self,
    rpc, Address, FullPublicKey,
    Transaction, TransactionData,
};

type ConsensusMsgTuple = (ConsensusMessage, PeerId, Option<Vec<Transaction>>);

const MAX_TRANSACTIONS_PER_BLOCK: usize = 500;
const SNAPSHOT_SYNC_THRESHOLD: u64 = 100;
const AEGIS_SUB_COMMITTEE_SIZE: usize = 6;
const PROPOSER_TIMEOUT: Duration = Duration::from_millis(1200);
const SYNC_MODERATE_GAP_THRESHOLD: u64 = 10;
const MAX_PARALLEL_BODY_DOWNLOADS: usize = 30;

struct FinalizerWorker {
    blockchain: Arc<RwLock<Blockchain>>,
    mempool: Arc<Mempool>,
    block_tree: Arc<RwLock<BlockTree>>,
    new_block_notifier: broadcast::Sender<()>,
    snapshot_dir: PathBuf,
    finalization_rx: mpsc::Receiver<FinalityCertificate>,
}

impl FinalizerWorker {
    async fn run(mut self) {
        info!("[FINALIZER] Finalizer Worker dimulai, menunggu tugas...");
        while let Some(cert) = self.finalization_rx.recv().await {
            info!("[FINALIZER] Menerima tugas finalisasi untuk Epoch #{}", cert.epoch);
            // 1. Dapatkan daftar blok untuk di-commit dari BlockTree
            let blocks_to_commit = {
                let tree = self.block_tree.read().await;
                let last_finalized_hash = tree.get_finalized_head().block.header.calculate_hash();
                if last_finalized_hash == cert.checkpoint_hash {
                    debug!("[FINALIZER] Tugas finalisasi duplikat untuk epoch #{}. Diabaikan.", cert.epoch);
                    continue; 
                }
                match tree.get_ancestor_path(&cert.checkpoint_hash, &last_finalized_hash) {
                    Ok(blocks) => blocks,
                    Err(e) => {
                        error!("[FINALIZER] KRITIS: Gagal mengambil rantai untuk finalisasi: {}", e);
                        continue;
                    }
                }
            };

            if blocks_to_commit.is_empty() {
                continue;
            }

            info!("[FINALIZER] Akan mem-finalisasi {} blok untuk Epoch #{}", blocks_to_commit.len(), cert.epoch);
            let last_block_in_batch = blocks_to_commit.last().cloned();

            // 2. Proses penulisan DB 
            let committed_transactions = {
                let mut chain = self.blockchain.write().await;
                match chain.write_finalized_blocks_to_db(blocks_to_commit).await {
                    Ok(txs) => txs,
                    Err(e) => {
                        error!("[FINALIZER] KRITIS: Gagal commit batch blok final ke DB: {}", e);
                        continue;
                    }
                }
            };

            // 3. Pemicu pembuatan snapshot 
            if let Some(last_block) = last_block_in_batch {
                let db_clone = Arc::clone(&self.blockchain.read().await.state.db);
                let state_root = last_block.header.state_root.clone().try_into().unwrap();
                let height = last_block.header.index;
                let snapshot_dir_clone = self.snapshot_dir.clone();
                
                info!("[FINALIZER] Memicu pembuatan snapshot di background untuk blok #{}.", height);
                tokio::task::spawn_blocking(move || {
                    match snapshot::create_snapshot(db_clone, height, state_root, snapshot_dir_clone) {
                        Ok(metadata) => info!("[SNAPSHOT_TASK] Snapshot pasca-finalitas berhasil. File: {}", metadata.file_name),
                        Err(e) => error!("[SNAPSHOT_TASK] Gagal membuat snapshot pasca-finalitas: {:?}", e),
                    }
                });
            }

            // 4. Bersihkan mempool dari transaksi yang sudah final
            if !committed_transactions.is_empty() {
                self.mempool.remove_transactions(&committed_transactions);
            }
            
            // 5. Finalisasi BlockTree 
            {
                let mut tree = self.block_tree.write().await;
                if let Err(e) = tree.finalize(&cert.checkpoint_hash) {
                    error!("[FINALIZER] KRITIS: Gagal memfinalisasi BlockTree: {}", e);
                    continue; 
                }
            }

            // 6. Kirim notifikasi blok baru ke komponen lain
            if self.new_block_notifier.send(()).is_err() {
                warn!("[FINALIZER] Gagal mengirim notifikasi blok final (tidak ada yang mendengarkan).");
            }

            info!("[FINALIZER] Tugas finalisasi untuk Epoch #{} selesai.", cert.epoch);
        }
        warn!("[FINALIZER] Channel finalisasi ditutup. Worker berhenti.");
    }
}

#[derive(Clone)]
struct ConsensusEngine {
    my_address: Address,
    validator_keys: Arc<ValidatorKeys>,
    blockchain: Arc<tokio::sync::RwLock<Blockchain>>,
    mempool: Arc<Mempool>,
    p2p_cmd_tx: mpsc::Sender<P2pCommand>,
    state: ConsensusState,
    consensus_ready: Arc<AtomicBool>,
    dkg_state: DkgState,
    address_book: Arc<Mutex<AddressBook>>,
    pending_tx_requests: Arc<RwLock<HashMap<u64, oneshot::Sender<Vec<Transaction>>>>>,
    pacesetter_notifier: Arc<Notify>,
    is_syncing_flag: Arc<AtomicBool>,
    sync_trigger_tx: mpsc::Sender<()>,
    block_tree: Arc<RwLock<BlockTree>>,
    tx_gossip: mpsc::Sender<ChainMessage>,
    chain_id: String,
    aegis_gravity_epoch_length: u64,
    finalization_tx: mpsc::Sender<FinalityCertificate>,
    finalization_lock: Arc<Mutex<()>>,
}

#[derive(Debug)]
enum ConsensusOffense {
    StateRootMismatch {
        header: BlockHeader,
        computed_state_root: Vec<u8>
    },
    FailedSimulation {
        header: BlockHeader,
        error: String
    },
    InvalidSignature {
        header: BlockHeader
    },
    TransactionsRootMismatch {
        header: BlockHeader
    },
    UnknownProposer {
        header: BlockHeader
    },
    MissingParent {
        parent_hash: Vec<u8>
    },
}

impl ConsensusEngine {
    pub async fn run(
        self,
        mut p2p_msg_rx: mpsc::Receiver<ConsensusMsgTuple>,
        mut txs_response_from_p2p_rx: mpsc::Receiver<SyncResponse>,
        mut block_processing_rx: mpsc::Receiver<BlockProcessingResult>,
    ) {
        info!("[AEGIS] Mesin Konsensus Aegis dimulai, menunggu sinyal ConsensusReady...");
        loop {
            if self.consensus_ready.load(Ordering::SeqCst) {
                info!("[AEGIS] Sinyal ConsensusReady diterima. Memulai protokol konsensus.");
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        let message_handler_engine = self.clone();
        tokio::spawn(async move {
            while let Some((msg, source_peer, transactions_opt)) = p2p_msg_rx.recv().await {
                if message_handler_engine.is_syncing_flag.load(Ordering::SeqCst) {
                    if !matches!(msg, ConsensusMessage::AegisFinalityCertificate(_)) {
                        debug!("[AEGIS] Mengabaikan pesan konsensus karena node sedang sinkronisasi.");
                        continue; 
                    }
                }

                let engine_clone = message_handler_engine.clone();
                tokio::spawn(async move {
                    engine_clone.handle_consensus_message(msg, source_peer, transactions_opt).await;
                });
            }
        });

        let block_handler_engine = self.clone();
        tokio::spawn(async move {
            while let Some(result) = block_processing_rx.recv().await {
                match &result {
                    BlockProcessingResult::Success { block_hash, .. } => {
                        info!("[AEGIS] Menerima hasil pemrosesan state untuk blok 0x{}.", hex::encode(&block_hash[..4]));
                        
                        let block_to_check = {
                            let tree = block_handler_engine.block_tree.read().await;
                            tree.get_node(block_hash).map(|n| n.block.clone())
                        };

                        if let Some(block) = block_to_check {
                            let current_height = block.header.index;
                            if (current_height + 1) % self.aegis_gravity_epoch_length == 0 {
                                let epoch = (current_height + 1) / self.aegis_gravity_epoch_length - 1;
                                let gravity_engine = block_handler_engine.clone();
                                tokio::spawn(async move {
                                    gravity_engine.handle_gravity_epoch(epoch, block).await;
                                });
                            }
                        }

                        block_handler_engine.reprocess_dependant_proposals(block_hash).await;
                        block_handler_engine.pacesetter_notifier.notify_one();
                    }
                    BlockProcessingResult::Failure { block_hash, error, is_fatal: _ } => {
                        warn!("[AEGIS] Gagal memproses state untuk blok 0x{}: {}. Blok akan dipangkas.", hex::encode(&block_hash[..4]), error);
                        let block_header_opt = {
                            let tree = block_handler_engine.block_tree.read().await;
                            tree.get_node(block_hash).map(|node| node.block.header.clone())
                        };

                        if let Some(header) = block_header_opt {
                            if let BlockchainError::StateRootMismatch { expected: _, got } = error {
                                if let Ok(computed_root_bytes) = hex::decode(got) {
                                    let offense = ConsensusOffense::StateRootMismatch {
                                        header,
                                        computed_state_root: computed_root_bytes,
                                    };
                                    block_handler_engine.handle_consensus_offense(offense).await;
                                }
                            }
                        }

                        let mut tree = block_handler_engine.block_tree.write().await;
                        tree.prune_failed_branch(block_hash); 
                    }
                    BlockProcessingResult::ParentStateNotReady { block_hash, parent_hash } => {
                        // Tidak ada yang perlu dilakukan
                        debug!("[AEGIS] Pemrosesan untuk blok 0x{} ditunda karena menunggu state induk 0x{}", hex::encode(&block_hash[..4]), hex::encode(&parent_hash[..4]));
                    }
                }

                let mut tree = block_handler_engine.block_tree.write().await;
                tree.update_node_status(result, Arc::clone(&block_handler_engine.blockchain));
            }
        });

        let tx_response_handler_engine = self.clone();
        tokio::spawn(async move {
            while let Some(response) = txs_response_from_p2p_rx.recv().await {
                if let SyncResponse::TxsByHash { request_id, txs } = response {
                    let mut pending_requests = tx_response_handler_engine.pending_tx_requests.write().await;
                    if let Some(sender) = pending_requests.remove(&request_id) {
                        if sender.send(txs).is_err() {
                            warn!("[AEGIS] Gagal mengirim transaksi yang diterima ke task yang menunggu untuk request_id: {}.", request_id);
                        }
                    }
                }
            }
        });

        let mut pacesetter_ticker = interval(Duration::from_millis(500));
        let mut fallback_ticker = interval(Duration::from_secs(5));
        let mut current_step_task: Option<tokio::task::JoinHandle<()>> = None;

        loop {
            tokio::select! {
                _ = self.pacesetter_notifier.notified() => {
                    info!("[AEGIS DRIVER] Pemicu manual diterima, menjalankan pemeriksaan konsensus segera.");
                },

                _ = fallback_ticker.tick() => {
                    let mut queues = self.state.proposal_queues.write().await;
                    let mut requests_to_broadcast = Vec::new();
                    queues.stale_qc_request.retain(|hash, (_view, timestamp)| {
                        if timestamp.elapsed() > Duration::from_secs(4) {
                            requests_to_broadcast.push(hash.clone());
                            false
                        } else {
                            true
                        }
                    });
                    drop(queues);

                    for hash in requests_to_broadcast {
                        let _ = self.p2p_cmd_tx.send(P2pCommand::BroadcastMissingBlockRequest(hash)).await;
                    }
                },

                _ = pacesetter_ticker.tick() => {},
            }
            if !self.consensus_ready.load(Ordering::SeqCst) {
                continue;
            }

            let (highest_qc_view, highest_qc_hash, current_round, current_step, step_start_time) = {
                let core = self.state.core_state.read().await;
                (core.highest_seen_qc.view_number, core.highest_seen_qc.block_hash.clone(), core.current_round, core.current_step, core.step_start_time)
            };

            let parent_block_status = {
                let chain = self.blockchain.read().await;
                let block_tree = chain.block_tree.read().await;
                if highest_qc_view == 0 {
                    Some(BlockNodeStatus::StateReady)
                } else if let Some(node) = block_tree.get_node(&highest_qc_hash) {
                    Some(node.status.clone())
                } else if chain.get_block_by_hash(&highest_qc_hash).is_some() {
                    Some(BlockNodeStatus::StateReady)
                } else {
                    None
                }
            };

            match parent_block_status {
                Some(BlockNodeStatus::StateReady) => {
                    // Blok induk sudah siap, lanjutkan konsensus
                }
                Some(BlockNodeStatus::ProcessingDependencies | BlockNodeStatus::ProcessingSelf) => {
                    debug!("[AEGIS DRIVER] Ditahan sementara: Menunggu pemrosesan state untuk blok 0x{} selesai.", hex::encode(&highest_qc_hash[..4]));
                    continue;
                }
                Some(BlockNodeStatus::Failed) => {
                    error!("[AEGIS DRIVER] KRITIS: Berhenti karena blok induk 0x{} yang dirujuk oleh QC gagal diproses.", hex::encode(&highest_qc_hash[..4]));
                    continue;
                }
                None => {
                    warn!("[AEGIS DRIVER] Ditahan: Menunggu sinkronisasi blok 0x{} yang dirujuk oleh QC#{}.", hex::encode(&highest_qc_hash[..4]), highest_qc_view);
                    continue;
                }
            }

            let mut start_new_task = false;
            let mut next_round = current_round;
            let mut next_step = current_step;

            if highest_qc_view >= current_round {
                next_round = highest_qc_view + 1;
                next_step = 0;
                info!("[AEGIS DRIVER] QC#{} diterima & blok induk ada. Maju ke Ronde #{}, Langkah #0.", highest_qc_view, next_round);
                start_new_task = true;
            } else if step_start_time.elapsed() > PROPOSER_TIMEOUT {
                next_step = current_step + 1;
                warn!("[AEGIS DRIVER] Proposer untuk Ronde #{}, Langkah #{} timeout. Maju ke Langkah #{}.", current_round, current_step, next_step);
                start_new_task = true;

                if next_step >= AEGIS_SUB_COMMITTEE_SIZE as u64 {
                    warn!("[AEGIS DRIVER] Semua proposer gagal untuk Ronde #{}. Memaksa maju ke Ronde berikutnya.", current_round);
                    next_round = current_round + 1;
                    next_step = 0;
                }
            }

            if start_new_task {
                if let Some(task) = current_step_task.take() {
                    task.abort();
                }

                {
                    let mut core = self.state.core_state.write().await;
                    core.current_round = next_round;
                    core.current_step = next_step;
                    core.step_start_time = Instant::now();
                }

                let premature_proposals_for_round = self.state.proposal_queues.write().await
                    .premature_proposals.remove(&next_round);

                if let Some(proposals) = premature_proposals_for_round {
                    info!("[AEGIS DRIVER] Memproses ulang {} proposal prematur yang diantrekan untuk Ronde #{}", proposals.len(), next_round);
                    for (msg, source_peer, txs) in proposals {
                        let engine_clone = self.clone();
                        tokio::spawn(async move {
                            engine_clone.handle_consensus_message(msg, source_peer, txs).await;
                        });
                    }
                }

                current_step_task = Some(tokio::spawn(self.clone().handle_round_step(next_round, next_step)));
            }
        }
    }

    async fn handle_round_step(self, round: u64, step: u64) {
        let (current_round, current_step, seed_hash) = {
            let core = self.state.core_state.read().await;
            if core.current_round != round || core.current_step != step {
                info!("[AEGIS] Membatalkan tugas usang untuk Ronde #{}, Langkah #{}.", round, step);
                return;
            }
            (core.current_round, core.current_step, core.highest_seen_qc.block_hash.clone())
        };

        info!("[AEGIS] Menjalankan tugas untuk Ronde #{}, Langkah #{}", current_round, current_step);

        let sub_committee = self.determine_sub_committee(round, &seed_hash).await;
        if sub_committee.is_empty() { return; }

        let proposer_address = match sub_committee.get(step as usize) {
            Some(addr) => addr,
            None => {
                warn!("[AEGIS] Langkah #{} di luar batas untuk sub-komite Ronde #{}.", step, round);
                return;
            }
        };

        if self.my_address == *proposer_address {
            info!("[AEGIS PROPOSER] Saya adalah pemimpin untuk Ronde #{}, Langkah #{}.", round, step);
            self.run_proposer_flow(round).await;
        }
    }

    async fn run_proposer_flow(&self, round: u64) {
        info!("[AEGIS PROPOSER] Memulai alur kerja sebagai proposer untuk Ronde #{}.", round);

        let parent_node = self.block_tree.read().await.find_head();
        if parent_node.status != BlockNodeStatus::StateReady {
            error!("[AEGIS PROPOSER] KRITIS: Mencoba membuat blok di atas induk '0x{}' yang state-nya belum siap. Membatalkan proposal.", hex::encode(&parent_node.block.header.calculate_hash()[..4]));
            return;
        }
        let parent_post_state_root = parent_node.post_state_root.clone();

        let parent_header = &parent_node.block.header;
        info!("[AEGIS PROPOSER] Membangun di atas blok #{} (hash: 0x{})", parent_header.index, hex::encode(&parent_header.calculate_hash()[..4]));

        let txs_to_propose = self.mempool.peek_transactions(MAX_TRANSACTIONS_PER_BLOCK);
        let chain_guard = self.blockchain.read().await;
        let base_fee_per_gas = chain_guard.calculate_next_base_fee(parent_header);
        
        let preliminary_header = BlockHeader {
            index: parent_header.index + 1,
            authority: self.my_address,
            base_fee_per_gas,
            ..Default::default()
        };

        let (final_session, valid_txs, _changed_accounts) = match chain_guard.apply_transactions_to_session(
            chain_guard.state.create_trie_session(parent_post_state_root.as_slice().try_into().unwrap(), COL_TRIE),
            &preliminary_header,
            &txs_to_propose,
            &chain_guard.state.validators,
            &chain_guard.state.active_sequencers,
            &chain_guard.state.l2_state_root,
        ).await {
            Ok(result) => result,
            Err(e) => {
                error!("[AEGIS PROPOSER] Simulasi blok gagal: {}. Membatalkan proposal.", e);
                metrics::CONSENSUS_BLOCKS_PRODUCED.with_label_values(&["simulation_failed"]).inc();
                return;
            }
        };
        
        let final_state_root = final_session.root().to_vec();

        let parent_qc = {
            let core = self.state.core_state.read().await;
            core.highest_seen_qc.clone()
        };

        let block_proposal = chain_guard.create_block(
            &self.validator_keys.signing_keys,
            valid_txs.clone(),
            final_state_root,
            vec![], 
            vec![], 
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(),
            round,
            round, 
            parent_qc.clone(),
            Some(parent_header),
        );
        
        let block_hash = block_proposal.header.calculate_hash();
        info!("[AEGIS PROPOSER] Mengusulkan blok baru #{} (hash: 0x{}) dengan {} transaksi.", block_proposal.header.index, hex::encode(&block_hash[..4]), valid_txs.len());
        metrics::CONSENSUS_BLOCKS_PRODUCED.with_label_values(&["success"]).inc();

        let pending_block = PendingBlock {
            header: block_proposal.header.clone(),
            transactions: valid_txs.clone(),
            parent_qc,
            round,
        };
        self.state.pending_proposals.write().await.insert(block_hash.clone(), pending_block);

        if let Err(e) = self.block_tree.write().await.insert_and_process_block(block_proposal.clone(), Arc::clone(&self.blockchain)).await {
            error!("[AEGIS PROPOSER] KRITIS: Gagal memasukkan blok sendiri ke BlockTree: {}", e);
            return;
        }

        if self.p2p_cmd_tx.send(P2pCommand::BroadcastConsensusMessage(
            ConsensusMessage::AegisBlockProposal(Box::new(block_proposal.clone()))
        )).await.is_err() {
            error!("[AEGIS PROPOSER] Gagal menyiarkan proposal blok ke P2P.");
        }
        
        let self_vote = {
            let vote = VelocityVote {
                round_id: round,
                block_hash: block_hash.clone(),
                voter_address: self.my_address,
                signature: [0; crypto::SIGNATURE_SIZE],
            };
            vote.sign(&self.validator_keys.signing_keys)
        };

        self.state.core_state.write().await
            .velocity_votes
            .entry(block_hash.clone())
            .or_default()
            .push(self_vote);
        
        self.process_votes_for_block(&block_hash).await;
    }

    #[async_recursion]
    async fn handle_consensus_message(&self, msg: ConsensusMessage, source_peer: PeerId, _transactions_opt: Option<Vec<Transaction>>) {
        let message_hash = msg.hash();

        if self.state.recently_processed_hashes.read().await.contains(&message_hash) {
            return;
        }

        {
            let mut cache = self.state.recently_processed_hashes.write().await;
            if cache.contains(&message_hash) {
                return;
            }
            cache.put(message_hash, ());
        }

        if self.is_syncing_flag.load(Ordering::SeqCst) {
            if !matches!(msg, ConsensusMessage::AegisBlockProposal(_) | ConsensusMessage::AegisFinalityCertificate(_)) {
                let msg_type_str = match &msg {
                    ConsensusMessage::AegisVelocityVote(_) => "AegisVelocityVote",
                    ConsensusMessage::AegisNewQuorumCertificate(_) => "AegisNewQuorumCertificate",
                    ConsensusMessage::AegisInitiateFinality { .. } => "AegisInitiateFinality",
                    ConsensusMessage::AegisFinalityVote(_) => "AegisFinalityVote",
                    ConsensusMessage::AegisBlockProposal(_) => "AegisBlockProposal",
                    ConsensusMessage::AegisFinalityCertificate(_) => "AegisFinalityCertificate",
                };
                debug!("[AEGIS] Mengabaikan pesan konsensus '{}' karena node sedang sinkronisasi.", msg_type_str);
                return;
            }
        } else {
            let core = self.state.core_state.read().await;
            let received_round = match &msg {
                ConsensusMessage::AegisBlockProposal(b) => b.round,
                ConsensusMessage::AegisNewQuorumCertificate(qc) => qc.view_number,
                _ => 0,
            };

            if received_round > core.current_round + SYNC_MODERATE_GAP_THRESHOLD {
                warn!("[AEGIS] Mendeteksi kesenjangan konsensus (lokal: {}, diterima: {}). Memicu SyncManager untuk menilai ulang.", core.current_round, received_round);
                if self.sync_trigger_tx.try_send(()).is_err() {
                    debug!("[AEGIS] Gagal mengirim pemicu sinkronisasi ke SyncManager (mungkin channel penuh atau sedang tidak aktif).");
                }
            }
        }

        match msg {
            ConsensusMessage::AegisBlockProposal(block) => {
                self.handle_block_proposal(*block, source_peer).await;
            }
            ConsensusMessage::AegisVelocityVote(vote) => {
                self.handle_velocity_vote(vote).await;
            }
            ConsensusMessage::AegisNewQuorumCertificate(qc) => {
                self.handle_new_quorum_certificate(qc, source_peer).await;
            }
            ConsensusMessage::AegisFinalityVote(vote) => {
                self.handle_finality_vote(vote).await;
            }
            ConsensusMessage::AegisFinalityCertificate(cert) => {
                self.handle_finality_certificate(cert).await;
            }
            _ => {
                warn!("[AEGIS] Menerima jenis pesan konsensus yang tidak ditangani.");
            }
        }
    }

    async fn handle_block_proposal(&self, block: Block, source_peer: PeerId) {
        let block_hash = block.header.calculate_hash();
        
        if self.blockchain.read().await.block_tree.read().await.contains(&block_hash) {
            debug!("[AEGIS] Mengabaikan proposal blok 0x{} yang sudah ada di BlockTree.", hex::encode(&block_hash[..4]));
            return;
        }
        
        let highest_qc_view = self.state.core_state.read().await.highest_seen_qc.view_number;

        if !self.is_syncing_flag.load(Ordering::SeqCst) {
            if block.round > highest_qc_view + 1 {
                self.state.proposal_queues.write().await
                    .premature_proposals
                    .entry(block.round)
                    .or_default()
                    .push((ConsensusMessage::AegisBlockProposal(Box::new(block.clone())), source_peer, None));
                info!("[AEGIS] Proposal prematur untuk ronde #{} dari {} diantrekan (menunggu QC#{}+).", block.round, source_peer, block.round - 1);
                return;
            }
        }

        match self.pre_validate_proposal_concurrently(&block).await {
            Ok(_) => {
                let blockchain_guard = self.blockchain.read().await;
                let mut block_tree = blockchain_guard.block_tree.write().await;
                let blockchain_clone = Arc::clone(&self.blockchain);

                info!("[AEGIS] Proposal blok 0x{} lulus pra-validasi, diserahkan ke BlockTree untuk pemrosesan state.", hex::encode(&block.header.calculate_hash()[..4]));

                if let Err(e) = block_tree.insert_and_process_block(block.clone(), blockchain_clone).await {
                    warn!("[AEGIS] Gagal memasukkan blok 0x{} ke BlockTree: {}", hex::encode(&block.header.calculate_hash()[..4]), e);
                    match e {
                        BlockchainError::MissingParent { parent_hash } => {
                            self.handle_missing_parent(block, source_peer, parent_hash).await;
                        }
                        BlockchainError::LogicError(msg) if msg.contains("induk yang state-nya belum siap") => {
                            warn!("[AEGIS] Induk blok 0x{} sedang diproses. Menunda proposal 0x{}.", hex::encode(&block.header.prev_hash[..4]), hex::encode(&block.header.calculate_hash()[..4]));
                            let mut queues = self.state.proposal_queues.write().await;
                            queues.pending_proposals_awaiting_parent_state
                                .entry(block.header.prev_hash.clone())
                                .or_default()
                                .push((ConsensusMessage::AegisBlockProposal(Box::new(block)), source_peer, None));
                        }
                        _ => {} 
                    }
                } else {
                    self.cast_vote_for_block(&block.header, block.round).await;
                }
            },
            Err(offense) => {
                warn!("[AEGIS] Proposal untuk blok 0x{} gagal pra-validasi: {:?}", hex::encode(&block_hash[..4]), offense);
                if let ConsensusOffense::MissingParent { parent_hash } = offense {
                    self.handle_missing_parent(block, source_peer, parent_hash).await;
                } else {
                    self.handle_consensus_offense(offense).await;
                }
                return;
            }
        };
    }

    async fn handle_missing_parent(&self, block: Block, source_peer: PeerId, parent_hash: Vec<u8>) {
        warn!("[AEGIS] Induk blok 0x{} untuk proposal 0x{} tidak ditemukan. Menunda dan meminta sinkronisasi.",
            hex::encode(&parent_hash[..4]), hex::encode(&block.header.calculate_hash()[..4]));

        let pending_tuple = (ConsensusMessage::AegisBlockProposal(Box::new(block)), source_peer, None);
        self.state.proposal_queues.write().await
            .pending_proposals_waiting_for_parent
            .entry(parent_hash.clone())
            .or_default()
            .push(pending_tuple);

        let cmd = P2pCommand::SendDirectRequest {
            destination: source_peer,
            request: SyncRequest::GetFullProposal(parent_hash),
        };
        let _ = self.p2p_cmd_tx.send(cmd).await;
    }

    #[async_recursion]
    async fn pre_validate_proposal_concurrently(&self, block: &Block) -> Result<(), ConsensusOffense> {
        let parent_exists_task = tokio::spawn({
            let blockchain_clone = Arc::clone(&self.blockchain);
            let parent_hash = block.header.prev_hash.clone();
            async move {
                let chain_guard = blockchain_clone.read().await;
                chain_guard.block_tree.read().await.contains(&parent_hash) || chain_guard.get_block_by_hash(&parent_hash).is_some()
            }
        });

        // Task 1: Verifikasi semua tanda tangan (CPU-Bound)
        let signature_verification_task = tokio::spawn({
            let blockchain_clone = Arc::clone(&self.blockchain);
            let block_clone = block.clone();
            async move {
                let chain_guard = blockchain_clone.read().await;
                if !chain_guard.verify_velocity_qc(&block_clone.justify) {
                    return Err(ConsensusOffense::InvalidSignature { header: block_clone.header.clone() });
                }

                let proposer_account = match chain_guard.state.get_account(&block_clone.header.authority) {
                    Ok(Some(acc)) => acc,
                    _ => return Err(ConsensusOffense::UnknownProposer { header: block_clone.header.clone() }),
                };

                if !crypto::verify(&proposer_account.signing_public_key, &block_clone.header.canonical_bytes_for_signing(), &block_clone.header.signature) {
                    return Err(ConsensusOffense::InvalidSignature { header: block_clone.header.clone() });
                }

                if Block::calculate_transactions_root(&block_clone.transactions) != block_clone.header.transactions_root {
                    return Err(ConsensusOffense::TransactionsRootMismatch { header: block_clone.header.clone() });
                }
                Ok(())
            }
        });
        
        // Task 2: Verifikasi semua ZK Proofs (CPU-Bound di thread terpisah)
        let zk_proofs_verification_task = tokio::spawn({
            let blockchain_clone = Arc::clone(&self.blockchain);
            let block_clone = block.clone();
            async move {
                let chain_guard = blockchain_clone.read().await;
                let futures = block_clone.transactions.iter()
                    .filter(|tx| matches!(tx.data, TransactionData::SubmitRollupBatch { .. }))
                    .map(|tx| chain_guard.verify_rollup_proof_async(tx));

                futures::future::join_all(futures).await
            }
        });

        // Jalankan semua task secara bersamaan
        let (parent_exists_result, sig_result, zk_results) = tokio::try_join!(
            parent_exists_task,
            signature_verification_task,
            zk_proofs_verification_task
        ).map_err(|e| ConsensusOffense::FailedSimulation { header: block.header.clone(), error: e.to_string() })?;

        // Periksa hasil dari setiap task
        if !parent_exists_result {
            return Err(ConsensusOffense::MissingParent { parent_hash: block.header.prev_hash.clone() });
        }
        sig_result?;
        for result in zk_results {
            result.map_err(|e| ConsensusOffense::FailedSimulation { header: block.header.clone(), error: e.to_string() })?;
        }

        Ok(())
    }

    async fn process_votes_for_block(&self, block_hash: &[u8]) {
        let (votes_for_block, pending_proposal, is_already_processed) = {
            let core = self.state.core_state.read().await;
            if core.processed_optimistic_blocks.contains(block_hash) {
                (Vec::new(), None, true)
            } else {
                let votes = core.velocity_votes.get(block_hash).cloned().unwrap_or_default();
                let pending_proposals = self.state.pending_proposals.read().await;
                (votes, pending_proposals.get(block_hash).cloned(), false)
            }
        };

        if is_already_processed || pending_proposal.is_none() {
            return; 
        }

        let proposal = pending_proposal.unwrap();

        let chain = self.blockchain.read().await;
        let verified_signatures_opt = VelocityVote::collect_verified_votes(votes_for_block.iter(), &chain, proposal.round);

        if let Some(verified_signatures) = verified_signatures_opt {
            let velocity_threshold = (AEGIS_SUB_COMMITTEE_SIZE * 2 / 3) + 1;
            if verified_signatures.len() < velocity_threshold {
                return; 
            }

            let should_continue = {
                let mut core = self.state.core_state.write().await;
                if core.processed_optimistic_blocks.contains(block_hash) {
                    false 
                } else {
                    core.processed_optimistic_blocks.insert(block_hash.to_vec());
                    true
                }
            };

            if !should_continue {
                return;
            }
  
            let new_qc = QuorumCertificate {
                block_hash: block_hash.to_vec(),
                view_number: proposal.round,
                signatures: verified_signatures,
            };

            info!("[AEGIS] QC untuk Ronde #{} terbentuk. MENYIARKAN ke jaringan...", new_qc.view_number);
            let qc_broadcast_message = ConsensusMessage::AegisNewQuorumCertificate(new_qc.clone());
            if self.p2p_cmd_tx.send(P2pCommand::BroadcastConsensusMessage(qc_broadcast_message)).await.is_err() {
                error!("[AEGIS QC] Gagal menyiarkan Quorum Certificate ke jaringan.");
            }

            let mut core = self.state.core_state.write().await;
            if new_qc.view_number > core.highest_seen_qc.view_number {
                info!("[AEGIS KIBLAT] Diperbarui dari Ronde #{} ke Ronde #{}", core.highest_seen_qc.view_number, new_qc.view_number);
                core.highest_seen_qc = new_qc;
            }
        
            core.velocity_votes.remove(block_hash);
            self.state.pending_proposals.write().await.remove(block_hash);
        }
    }

    async fn handle_velocity_vote(&self, vote: VelocityVote) {
        let block_hash = vote.block_hash.clone();

        if self.state.core_state.read().await.processed_optimistic_blocks.contains(&block_hash) {
            return;
        }

        {
            let mut core = self.state.core_state.write().await;
            let votes_for_block = core.velocity_votes.entry(block_hash.clone()).or_default();
            if !votes_for_block.iter().any(|v| v.voter_address == vote.voter_address) {
                votes_for_block.push(vote);
            }
        }

        self.process_votes_for_block(&block_hash).await;
    }

    async fn handle_new_quorum_certificate(&self, qc: QuorumCertificate, source_peer: PeerId) {
        let is_fully_valid = self.blockchain.read().await.verify_velocity_qc(&qc);
        if !is_fully_valid {
            warn!("[AEGIS] Menerima QC dengan TANDA TANGAN TIDAK VALID dari peer {}. Memberikan penalti.", source_peer);
            let _ = self.p2p_cmd_tx.send(P2pCommand::ApplyPenalty { peer_id: source_peer, penalty: -50 }).await;
            return;
        }

        let new_block_hash = qc.block_hash.clone();
        let parent_exists_locally;

        {
            let mut core = self.state.core_state.write().await;
            if qc.view_number > core.highest_seen_qc.view_number {
                info!("[AEGIS KIBLAT] Menerima QC baru yang VALID dari jaringan untuk Ronde #{}. Memperbarui kiblat.", qc.view_number);
                core.highest_seen_qc = qc.clone();

                let chain = self.blockchain.read().await;
                parent_exists_locally = chain.get_block_by_hash(&new_block_hash).is_some()
                                    || chain.speculative_chain.read().await.get_block_header_by_hash(&new_block_hash).is_some()
                                    || chain.block_tree.read().await.contains(&new_block_hash);
            } else {
                return; 
            }
        }

        if !parent_exists_locally {
            warn!("[AEGIS SYNC PROAKTIF] Menerima QC untuk blok 0x{} yang tidak kita miliki. Meminta data lengkap.", hex::encode(&new_block_hash[..4]));
            
            self.state.proposal_queues.write().await
                .stale_qc_request
                .insert(new_block_hash.clone(), (qc.view_number, Instant::now()));

            let cmd = P2pCommand::SendDirectRequest {
                destination: source_peer,
                request: SyncRequest::GetFullProposal(new_block_hash),
            };
            if self.p2p_cmd_tx.send(cmd).await.is_err() {
                error!("[AEGIS] Gagal mengirim permintaan blok yang hilang ke P2P.");
            }
        }
    }

    async fn handle_finality_vote(&self, vote: FinalityVote) {
        let epoch_num = vote.epoch;
        let threshold = self.dkg_state.threshold;

        let should_aggregate = {
            let mut gravity = self.state.gravity_layer.write().await;
            let votes_map = gravity.finality_votes.entry(epoch_num).or_default();

            if votes_map.insert(vote.voter_address, vote.clone()).is_none() {
                info!(
                    "[AEGIS GRAVITY] Suara untuk Epoch #{} berhasil ditambahkan. Progres: {}/{} suara.",
                    epoch_num,
                    votes_map.len(),
                    threshold
                );
            }

            votes_map.len() >= threshold
        }; 

        if should_aggregate {
            self.try_aggregate_and_broadcast_certificate(epoch_num).await;
        }
    }

    async fn try_aggregate_and_broadcast_certificate(&self, epoch_num: u64) {
        let mut gravity = self.state.gravity_layer.write().await;

        if let Some(votes_map) = gravity.finality_votes.get(&epoch_num) {
            if votes_map.len() >= self.dkg_state.threshold {
                let votes_to_process: Vec<FinalityVote> = votes_map.values().cloned().collect();

                if let Some(finality_cert) = crate::crypto::aggregate_finality_votes(&votes_to_process, self.dkg_state.threshold) {
                    // 1. Langsung panggil handler lokal sebagai tugas berprioritas tinggi
                    // Ini memastikan sertifikat diproses secara internal bahkan jika siaran gagal
                    info!("[AEGIS GRAVITY] Kuorum finalitas tercapai untuk Epoch #{}. Memproses sertifikat secara lokal...", epoch_num);
                    let self_clone_for_local_processing = self.clone();
                    let cert_clone_for_local = finality_cert.clone();
                    tokio::spawn(async move {
                        self_clone_for_local_processing.handle_finality_certificate(cert_clone_for_local).await;
                    });

                    // 2. Setelah pemrosesan lokal, siarkan ke jaringan.
                    info!("[AEGIS GRAVITY] Menyiarkan sertifikat finalitas Epoch #{} ke jaringan.", epoch_num);
                    let cmd = P2pCommand::BroadcastConsensusMessage(
                        ConsensusMessage::AegisFinalityCertificate(finality_cert)
                    );
                    if self.p2p_cmd_tx.send(cmd).await.is_err() {
                        error!("[AEGIS GRAVITY] Gagal menyiarkan FinalityCertificate.");
                    }

                    gravity.finality_votes.remove(&epoch_num);
                }
            }
        }
    }

    async fn handle_finality_certificate(&self, cert: FinalityCertificate) {
        // 1. Dapatkan kunci untuk mencegah pengiriman duplikat secara bersamaan
        let _guard = self.finalization_lock.lock().await;
        
        // 2. Lakukan validasi awal yang cepat dan in-memory
        let last_finalized_hash = self.block_tree.read().await.get_finalized_head().block.header.calculate_hash();
        if last_finalized_hash == cert.checkpoint_hash {
            debug!("[AEGIS GRAVITY] Menerima sertifikat finalitas duplikat untuk epoch #{}. Diabaikan.", cert.epoch);
            return;
        }

        if !crypto::verify_finality_certificate(&self.dkg_state, &cert) {
            warn!("[AEGIS GRAVITY] Menerima sertifikat finalitas yang tidak valid! Diabaikan.");
            return;
        }

        // 3. "Hand-off" - Serahkan tugas ke Finalizer Worker
        info!("[AEGIS GRAVITY] Menyerahkan sertifikat valid untuk Epoch #{} ke Finalizer Worker.", cert.epoch);
        if self.finalization_tx.send(cert).await.is_err() {
            error!("[AEGIS GRAVITY] KRITIS: Gagal mengirim tugas finalisasi ke worker. Channel mungkin tertutup.");
        }
    }

    async fn cast_vote_for_block(&self, header: &BlockHeader, round: u64) {
        let block_hash = header.calculate_hash();
        let proposer_address = header.authority;

        let proposer_peer_id = match self.address_book.lock().await.get_peer_id(&proposer_address) {
            Some(id) => id,
            None => {
                warn!("[AEGIS VOTE] Tidak dapat menemukan PeerId untuk proposer 0x{}, tidak dapat mengirim suara.", hex::encode(proposer_address.as_ref()));
                return;
            }
        };

        info!("[AEGIS VOTE] Proposal 0x{} divalidasi. Mengirim suara langsung ke proposer {}", hex::encode(&block_hash[..4]), proposer_peer_id);

        let mut vote = VelocityVote {
            round_id: round,
            block_hash: block_hash.to_vec(),
            voter_address: self.my_address,
            signature: [0; crypto::SIGNATURE_SIZE],
        };
        vote = vote.sign(&self.validator_keys.signing_keys);

        let cmd = P2pCommand::SendDirectRequest {
            destination: proposer_peer_id,
            request: SyncRequest::SubmitVote(Box::new(vote)),
        };

        if self.p2p_cmd_tx.send(cmd).await.is_err() {
            error!("[AEGIS VOTE] Gagal mengirim vote ke channel P2P.");
        }
    }

    async fn determine_sub_committee(&self, round: u64, seed_hash: &[u8]) -> Vec<Address> {
        let validators = {
            let chain = self.blockchain.read().await;
            chain.state.validators.iter().cloned().collect::<Vec<_>>()
        };

        if validators.is_empty() { return Vec::new(); }

        let mut sorted_validators = validators;
        sorted_validators.sort();

        let seed_material = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(seed_hash);
            hasher.update(&round.to_be_bytes());
            hasher.finalize()
        };

        let seed: [u8; 32] = seed_material.into();
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        sorted_validators.shuffle(&mut rng);

        let committee = sorted_validators.into_iter().take(AEGIS_SUB_COMMITTEE_SIZE).collect::<Vec<_>>();

        if !committee.is_empty() {
            debug!("[AEGIS LEADER ELECTION] Ronde #{}: Sub-komite terpilih (proposer pertama): 0x{}", round, hex::encode(committee[0].as_ref()));
        }

        committee
    }

    async fn handle_gravity_epoch(&self, epoch: u64, _triggering_block: Block) {
        info!("[AEGIS GRAVITY] Memulai proses finalitas untuk Epoch #{}", epoch);
        
        let checkpoint_block_index = ((epoch + 1) * self.aegis_gravity_epoch_length) - 1;

        let (checkpoint_block_opt, coordinator_address) = {
            let chain = self.blockchain.read().await;
            
            // 1. Prioritaskan pencarian di BlockTree.
            let block_from_tree = {
                let block_tree = chain.block_tree.read().await;
                block_tree.get_node_by_index(checkpoint_block_index).map(|node| node.block.clone())
            };

            let block_opt = if let Some(block) = block_from_tree {
                Some(block)
            } else {
                // 2. Jika tidak ada di BlockTree, cari di speculative_chain dan rantai final.
                let speculative_chain_guard = chain.speculative_chain.read().await;
                speculative_chain_guard.get_speculative_block_by_index(checkpoint_block_index)
                    .or_else(|| chain.get_block_by_index(checkpoint_block_index).ok().flatten())
            };

            if let Some(block) = block_opt {
                (Some(block.clone()), block.header.authority)
            } else {
                error!("[AEGIS GRAVITY] KRITIS: Tidak dapat menemukan blok checkpoint #{} untuk finalisasi Epoch #{}.", checkpoint_block_index, epoch);
                return;
            }
        };

        if let Some(checkpoint_block) = checkpoint_block_opt {
            let checkpoint_hash = checkpoint_block.header.calculate_hash();

            let signature_share = self.validator_keys.bls_secret_key.sign(&checkpoint_hash, b"aegis_finality_vote", &[]).to_bytes();
            let vote = FinalityVote {
                checkpoint_hash,
                epoch,
                voter_address: self.my_address,
                signature_share: signature_share.to_vec(),
            };
            
            let vote_message = ConsensusMessage::AegisFinalityVote(vote.clone());

            if self.my_address == coordinator_address {
                info!("[AEGIS GRAVITY] Saya adalah koordinator Epoch #{}. Memproses suara internal.", epoch);
                self.handle_finality_vote(vote).await;
            } else {
                if let Some(coordinator_peer_id) = self.address_book.lock().await.get_peer_id(&coordinator_address) {
                    info!(
                        "[AEGIS GRAVITY] Mengirim FinalityVote untuk Epoch #{} langsung ke koordinator {}",
                        epoch, coordinator_peer_id
                    );
        
                    let cmd = P2pCommand::SendDirectRequest {
                        destination: coordinator_peer_id,
                        request: SyncRequest::ConsensusRequest(Box::new(vote_message)),
                    };
        
                    if self.p2p_cmd_tx.send(cmd).await.is_err() {
                        error!("[AEGIS GRAVITY] Gagal mengirim FinalityVote ke channel P2P.");
                    }
                } else {
                    error!(
                        "[AEGIS GRAVITY] Gagal mengirim FinalityVote: PeerId untuk koordinator 0x{} tidak ditemukan.",
                        hex::encode(coordinator_address.as_ref())
                    );
                }
            }
        }
    }

    async fn handle_consensus_offense(&self, offense: ConsensusOffense) {
        match offense {
            ConsensusOffense::StateRootMismatch { header, computed_state_root } => {
                let offender_address = header.authority;
                warn!("[AEGIS PENALTY] Pelanggaran serius terdeteksi: StateRootMismatch dari proposer 0x{}. Memulai proses slashing.", hex::encode(offender_address.as_ref()));

                if let Some(peer_id) = self.address_book.lock().await.get_peer_id(&offender_address) {
                    let _ = self.p2p_cmd_tx.send(P2pCommand::ApplyPenalty {
                        peer_id,
                        penalty: -100,
                    }).await;
                }

                let slashing_tx_data = TransactionData::ReportInvalidState {
                    offending_header: header,
                    computed_state_root,
                };

                let (my_account, chain_snapshot, state_snapshot) = {
                    let chain = self.blockchain.read().await;
                    let account = chain.state.get_account(&self.my_address).unwrap().unwrap_or_default();
                    (account, chain.clone(), chain.state.clone())
                };

                let mut tx = Transaction {
                    sender_public_key: FullPublicKey(self.validator_keys.signing_keys.public_key_bytes()),
                    data: slashing_tx_data,
                    nonce: my_account.nonce,
                    max_fee_per_gas: 20,
                    max_priority_fee_per_gas: 2,
                    signature: [0; crypto::SIGNATURE_SIZE],
                    chain_id: self.chain_id.clone(),
                };
                tx.signature = self.validator_keys.signing_keys.sign(&tx.message_hash());

                info!("[AEGIS PENALTY] Menyiarkan transaksi slashing (InvalidState) untuk 0x{}", hex::encode(offender_address.as_ref()));
                if self.mempool.add_transaction(tx.clone(), "local_slashing", &state_snapshot, &chain_snapshot).await.is_ok() {
                    if let Err(e) = self.tx_gossip.send(ChainMessage::NewTransaction(tx)).await {
                        error!("[AEGIS PENALTY] Gagal mengirim transaksi slashing ke kanal P2P: {}", e);
                    }
                }
            }
            ConsensusOffense::FailedSimulation { header, error } => {
                let offender_address = header.authority;
                warn!("[AEGIS PENALTY] Simulasi eksekusi gagal untuk proposal dari 0x{}. Error: {}. Memberikan penalti P2P.", hex::encode(offender_address.as_ref()), error);

                if let Some(peer_id) = self.address_book.lock().await.get_peer_id(&offender_address) {
                    let _ = self.p2p_cmd_tx.send(P2pCommand::ApplyPenalty {
                        peer_id,
                        penalty: -20,
                    }).await;
                }
            }
            ConsensusOffense::InvalidSignature { header } |
            ConsensusOffense::TransactionsRootMismatch { header } |
            ConsensusOffense::UnknownProposer { header } => {
                let offender_address = header.authority;
                warn!("[AEGIS PENALTY] Proposal tidak valid diterima dari proposer 0x{}. Memberikan penalti P2P ringan.", hex::encode(offender_address.as_ref()));

                if let Some(peer_id) = self.address_book.lock().await.get_peer_id(&offender_address) {
                    let _ = self.p2p_cmd_tx.send(P2pCommand::ApplyPenalty {
                        peer_id,
                        penalty: -10,
                    }).await;
                }
            }
            ConsensusOffense::MissingParent { .. } => {}
        }
    }

    #[async_recursion]
    async fn reprocess_dependant_proposals(&self, newly_arrived_block_hash: &[u8]) {
        self.state.proposal_queues.write().await
            .stale_qc_request
            .remove(newly_arrived_block_hash);

        let proposals_to_reprocess = self.state.proposal_queues.write().await
            .pending_proposals_waiting_for_parent
            .remove(newly_arrived_block_hash);

        if let Some(proposals) = proposals_to_reprocess {
            info!("[AEGIS] Blok induk 0x{} telah tiba. Memproses ulang {} proposal yang tertunda.", hex::encode(&newly_arrived_block_hash[..4]), proposals.len());
            for (pending_msg, pending_peer, pending_txs) in proposals {
                let self_clone = self.clone();
                tokio::spawn(async move {
                    self_clone.handle_consensus_message(pending_msg, pending_peer, pending_txs).await;
                });
            }
        }

        let proposals_to_reprocess_state = self.state.proposal_queues.write().await
            .pending_proposals_awaiting_parent_state
            .remove(newly_arrived_block_hash);

        if let Some(proposals) = proposals_to_reprocess_state {
            info!("[AEGIS] State untuk induk 0x{} telah siap. Memproses ulang {} proposal yang tertunda.", hex::encode(&newly_arrived_block_hash[..4]), proposals.len());
            for (pending_msg, pending_peer, pending_txs) in proposals {
                let self_clone = self.clone();
                tokio::spawn(async move {
                    self_clone.handle_consensus_message(pending_msg, pending_peer, pending_txs).await;
                });
            }
        }
    }
}

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    #[clap(long)]
    bootstrap: bool,
    #[clap(long, default_value = "./database")]
    db_path: String,
    #[clap(long, default_value = "verifying_key.bin")]
    vk_path: String,
    #[clap(long, help = "Alamat multiaddr dari bootstrap node. Bisa digunakan berkali-kali.")]
    bootstrap_node: Vec<String>,
    #[clap(long, default_value = "8080")]
    rpc_port: u16,
    #[clap(long, default_value = "50000")]
    p2p_port: u16,
    #[clap(long)]
    is_authority: bool,
    #[clap(long, requires = "is_authority")]
    keystore_path: Option<String>,
    #[clap(long = "vrf-private-key", requires = "is_authority")]
    vrf_priv_key: Option<String>,
    #[clap(long, requires = "is_authority")]
    bls_private_key: Option<String>,
    #[clap(long, default_value = "./snapshots")]
    snapshot_path: String,
    #[clap(long, help = "Berikan kata sandi keystore secara langsung (untuk skrip pengujian).")]
    password: Option<String>,
    #[clap(long, default_value = "9615")]
    metrics_port: u16,
    #[clap(long, default_value = "agg_verifying_key.bin")]
    agg_vk_path: String,
    #[clap(long, help = "Hanya cetak PeerId untuk db-path yang diberikan dan keluar.")]
    get_peer_id: bool,
    #[clap(long, help = "Jalankan dalam mode pengembangan (izinkan alamat loopback P2P).")]
    dev: bool,
}

#[derive(Debug, Clone)]
struct PeerHealthStatus {
    peer_id: PeerId,
    height: u64,
}

#[derive(Debug)]
enum SyncState {
    Idle,
    InitialAssessment {
        peers_queried: usize,
        responses: HashMap<PeerId, PeerHealthStatus>,
    },
    RequestingSnapshotMetadata { 
        best_peer: PeerHealthStatus 
    },
    DownloadingSnapshot {
        metadata: SnapshotMetadata,
        temp_file: Arc<Mutex<File>>,
        next_chunk: u32,
        source_peer: PeerId,
    },
    RestartingNode,
    SyncingHeaders {
        best_peer: PeerId,
        since_index: u64,
        fetched_headers: Vec<BlockHeader>,
    },
    SyncingBodies {
        headers_to_fetch: VecDeque<BlockHeader>,
        peers: Vec<PeerId>,
        pending_bodies: HashMap<Vec<u8>, BlockHeader>, 
        received_bodies: HashMap<u64, Block>, 
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    LogTracer::init()?;
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();

    if args.dev {
        p2p::DEV_MODE.store(true, Ordering::SeqCst);
        warn!("Menjalankan dalam mode PENGEMBANGAN. Alamat loopback P2P akan diizinkan.");
    }

    if args.get_peer_id {
        let p2p_key_path = Path::new(&args.db_path).join("p2p_keypair");
        let keypair = if p2p_key_path.exists() {
            let mut key_bytes = fs::read(&p2p_key_path)?;
            let secret_key = ed25519::SecretKey::try_from_bytes(&mut key_bytes)
                .map_err(|e| format!("File P2P keypair corrupt: {}", e))?;
            P2pKeypair::from(ed25519::Keypair::from(secret_key))
        } else {
            let ed25519_keypair = ed25519::Keypair::generate();
            fs::create_dir_all(&args.db_path)?;
            fs::write(&p2p_key_path, ed25519_keypair.secret().as_ref())
                .map_err(|e| format!("Gagal menyimpan keypair baru: {}", e))?;
            P2pKeypair::from(ed25519_keypair)
        };
        let peer_id = PeerId::from(keypair.public());
        println!("{}", peer_id);
        return Ok(());
    }
    
    if args.bootstrap {
        info!("Mem-bootstrap state awal dan menghasilkan genesis.json yang lengkap...");
        const NUM_VALIDATORS: usize = 7;
        const INITIAL_BALANCE: u128 = 1_000_000_000;
        const INITIAL_STAKE: u128 = 50_000_000;
        let mut validator_keys_generated: Vec<ValidatorKeys> = Vec::new();
        let mut genesis_accounts = HashMap::new();
        let mut p2p_keypairs: Vec<P2pKeypair> = Vec::new();

        for _ in 0..NUM_VALIDATORS {
            validator_keys_generated.push(ValidatorKeys::new());
            p2p_keypairs.push(P2pKeypair::generate_ed25519());
        }

        for (i, keys) in validator_keys_generated.iter().enumerate() {
            let address_hex = hex::encode(keys.signing_keys.public_key_bytes());
            let bls_public_key = keys.bls_secret_key.sk_to_pk();

            let p2p_key = &p2p_keypairs[i];
            let peer_id = PeerId::from(p2p_key.public());

            let port = 50000 + i;
            let multiaddr = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", port, peer_id);

            let account = GenesisAccount {
                public_key: address_hex.clone(),
                balance: (INITIAL_BALANCE - INITIAL_STAKE).to_string(),
                staked_amount: INITIAL_STAKE.to_string(),
                vrf_public_key: Some(hex::encode(keys.vrf_keys.public.to_bytes())),
                bls_public_key: Some(hex::encode(bls_public_key.to_bytes())),
                network_identity: Some(multiaddr),
            };
            genesis_accounts.insert(address_hex, account);
        }

        let genesis = Genesis {
            genesis_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            chain_id: "evice-testnet-v1".to_string(),

            parameters: evice_blockchain::genesis::GenesisParameters {
                aegis_sub_committee_size: 6,
                aegis_gravity_epoch_length: 10,
                proposer_timeout_ms: 1200,
                max_transactions_per_block: 500,
                minimum_stake: "10000".to_string(),
                proposal_voting_period_blocks: 100,
                base_reward_factor: 64,
                initial_total_supply: 1_000_000_000,
                blocks_per_epoch_for_reward: 86400,
            },
            accounts: genesis_accounts,
        };

        let genesis_json = serde_json::to_string_pretty(&genesis)?;
        let mut file = File::create("genesis.json")?;
        file.write_all(genesis_json.as_bytes())?;

        println!("\n========================================================================");
        println!("             KUNCI VALIDATOR GENESIS (UNTUK SCRIPT)             ");
        println!("========================================================================");
        for (i, keys) in validator_keys_generated.iter().enumerate() {
            let bls_public_key = keys.bls_secret_key.sk_to_pk();
            println!("\n--- Validator {} ---", i + 1);
            println!("Alamat (Sign PubKey): 0x{}", hex::encode(keys.signing_keys.public_key_bytes()));
            println!("Signing Private Key:  0x{}", hex::encode(keys.signing_keys.private_key_bytes()));
            println!("VRF Public Key:       0x{}", hex::encode(keys.vrf_keys.public.to_bytes()));
            println!("VRF Secret Key:       0x{}", hex::encode(keys.vrf_keys.secret.to_bytes()));
            println!("BLS Public Key:       0x{}", hex::encode(bls_public_key.to_bytes()));
            println!("BLS Secret Key:       0x{}", hex::encode(keys.bls_secret_key.to_bytes()));
        }
        println!("\n========================================================================");
        info!("Bootstrap selesai. Program berhenti.");
        std::process::exit(0);
    }

    let (restart_tx, mut restart_rx) = mpsc::channel::<()>(1);

    loop {
        const CONSENSUS_START_DELAY_SECS: u64 = 45;

        let genesis = Genesis::from_file("genesis.json")
            .expect("File genesis.json tidak ditemukan atau tidak valid.");

        let chain_id = genesis.chain_id.clone();
        let aegis_gravity_epoch_length = genesis.parameters.aegis_gravity_epoch_length;
        let genesis_time = genesis.genesis_time;

        let target_start_time = std::time::UNIX_EPOCH + Duration::from_secs(genesis_time + CONSENSUS_START_DELAY_SECS);
        info!("[MAIN] Waktu startup node global dijadwalkan pada {:?}", target_start_time);

        let current_time = std::time::SystemTime::now();
        if let Ok(wait_duration) = target_start_time.duration_since(current_time) {
            info!("[MAIN] Akan tidur selama {:?} hingga waktu startup global.", wait_duration);
            tokio::time::sleep(wait_duration).await;
        } else {
            warn!("[MAIN] Waktu startup global sudah berlalu. Memulai node segera.");
        }

        info!("[MAIN] Waktu startup global tercapai. Memulai semua layanan node...");

        let metrics_port = args.metrics_port;
        tokio::task::spawn_blocking(move || {
            info!("Menjalankan server metrik di http://0.0.0.0:{}/metrics", metrics_port);
            metrics::run_metrics_server(metrics_port);
        });

        let snapshot_dir = PathBuf::from(&args.snapshot_path);
        if !snapshot_dir.exists() {
            std::fs::create_dir_all(&snapshot_dir)?;
        }

        let authority_validator_keys: Option<Arc<ValidatorKeys>> = if args.is_authority {
            let keystore_path = args.keystore_path.clone().expect("Node authority harus dijalankan dengan --keystore-path");
            let vrf_priv_key_hex = args.vrf_priv_key.clone().expect("Node authority harus dijalankan dengan --vrf-private-key");
            let bls_priv_key_hex = args.bls_private_key.clone().expect("Node authority harus dijalankan dengan --bls-private-key");

            info!("Membuka keystore dari: {}", keystore_path);
            let keystore = Keystore::from_path(&keystore_path)?;
            let password = match args.password {
                Some(ref p) => {
                    info!("Menggunakan kata sandi yang disediakan dari argumen CLI.");
                    p
                }
                None => {
                    println!("🔒 Masukkan kata sandi untuk keystore '{}':", keystore_path);
                    &read_password()?
                }
            };
            let sk_bytes_vec = keystore.decrypt(&password)?;
            let pk_bytes = hex::decode(&keystore.public_key)?;
            let signing_keys = KeyPair::from_key_bytes(&pk_bytes, &sk_bytes_vec)?;
            let signing_address = public_key_to_address(&signing_keys.public_key_bytes());
            info!("Menjalankan sebagai NODE OTORITAS dengan alamat: 0x{}", hex::encode(signing_address.as_ref()));
            let vrf_secret_bytes = hex::decode(vrf_priv_key_hex)?;
            let vrf_secret = SchnorrkelSecretKey::from_bytes(&vrf_secret_bytes)
                .map_err(|_| "VRF private key tidak valid. Pastikan panjangnya 64-byte.")?;
            let vrf_keys = vrf_secret.to_keypair();

            let mut ikm = [0u8; 32];
            rand::rng().fill_bytes(&mut ikm);
            let bls_secret_bytes = hex::decode(bls_priv_key_hex)?;
            let bls_secret_key = BlsSecretKey::from_bytes(&bls_secret_bytes)
                .map_err(|_| "BLS private key tidak valid.")?;

            Some(Arc::new(ValidatorKeys { signing_keys, vrf_keys, bls_secret_key }))

        } else { None };

        let db_path_clone_for_blockchain = args.db_path.clone();
        let (block_processing_tx, block_processing_rx) = mpsc::channel::<BlockProcessingResult>(128);

        let blockchain = Arc::new(RwLock::new(Blockchain::new(
            &db_path_clone_for_blockchain,
            &args.vk_path, 
            &args.agg_vk_path,
            block_processing_tx,
        )?));
        let mempool = Arc::new(Mempool::new());

        let address_book = Arc::new(Mutex::new(p2p::AddressBook::default()));
        {
            let mut ab = address_book.lock().await;
            let chain_guard = blockchain.read().await;
            ab.update_from_chain_state(&*chain_guard);
            info!("[MAIN] AddressBook diinisialisasi dengan {} entri dari genesis.", ab.get_all_peer_ids().len());
        }

        let (tx_gossip, rx_gossip) = mpsc::channel::<ChainMessage>(100);
        let (tx_sync_cmd, rx_sync_cmd) = mpsc::channel::<SyncRequest>(10);
        let (tx_sync_resp, _) = broadcast::channel::<(SyncResponse, PeerId)>(100);
        let (p2p_cmd_tx, p2p_cmd_rx) = mpsc::channel::<P2pCommand>(100);
        let (consensus_msg_tx, consensus_msg_rx) = mpsc::channel::<ConsensusMsgTuple>(100);
        let (new_block_tx, _) = broadcast::channel::<()>(16);
        let (sync_trigger_tx, mut sync_trigger_rx) = mpsc::channel::<()>(1);
        let (finalization_tx, finalization_rx) = mpsc::channel::<FinalityCertificate>(32); 

        let p2p_ready_flag = Arc::new(AtomicBool::new(false));
        let consensus_ready_flag = Arc::new(AtomicBool::new(false));
        let is_syncing_flag = Arc::new(AtomicBool::new(false)); 
        let mut consensus_state: Option<Arc<RwLock<ConsensusState>>> = None; 
        let (txs_response_to_consensus_tx, txs_response_from_p2p_rx) = mpsc::channel(100);
        
        if let Some(ref keys) = authority_validator_keys {
            let my_address = public_key_to_address(&keys.signing_keys.public_key_bytes());
            let (initial_qc, initial_block_hash, dkg_state) = {
                let chain = blockchain.read().await;

                let genesis_block = chain.chain.get(0).expect("Blok genesis tidak ada");
                let genesis_hash = genesis_block.header.calculate_hash();
                let genesis_qc = QuorumCertificate::genesis_qc();

                let mut participants = std::collections::HashMap::new();
                for validator_addr in &chain.state.validators {
                    if let Ok(Some(acc)) = chain.state.get_account(validator_addr) {
                        if let Some(pk_bytes) = acc.bls_public_key {
                            if let Ok(pk) = blst::min_pk::PublicKey::from_bytes(&pk_bytes) {
                                participants.insert(*validator_addr, pk);
                            }
                        }
                    }
                }
                
                let dkg = DkgState {
                    participants,
                    threshold: (chain.state.validators.len() * 2 / 3) + 1,
                };

                (genesis_qc, genesis_hash, dkg)
            };

            let state_struct = ConsensusState::new(initial_qc, initial_block_hash);
            consensus_state = Some(Arc::new(RwLock::new(state_struct.clone()))); 

            let engine = ConsensusEngine {
                my_address,
                validator_keys: Arc::clone(keys),
                blockchain: Arc::clone(&blockchain),
                block_tree: Arc::clone(&blockchain.read().await.block_tree),
                mempool: Arc::clone(&mempool),
                p2p_cmd_tx: p2p_cmd_tx.clone(),
                consensus_ready: consensus_ready_flag.clone(),
                state: state_struct,
                dkg_state,
                address_book: Arc::clone(&address_book),
                pending_tx_requests: Arc::new(RwLock::new(HashMap::new())),
                is_syncing_flag: Arc::clone(&is_syncing_flag),
                pacesetter_notifier: Arc::new(Notify::new()),
                sync_trigger_tx: sync_trigger_tx.clone(),
                tx_gossip: tx_gossip.clone(),
                chain_id: chain_id.clone(),
                aegis_gravity_epoch_length,
                finalization_tx,
                finalization_lock: Arc::new(Mutex::new(())),
            };
            tokio::spawn(engine.run(consensus_msg_rx, txs_response_from_p2p_rx, block_processing_rx));
        }

        let finalizer_worker = FinalizerWorker {
            blockchain: Arc::clone(&blockchain),
            mempool: Arc::clone(&mempool),
            block_tree: Arc::clone(&blockchain.read().await.block_tree),
            new_block_notifier: new_block_tx.clone(),
            snapshot_dir: snapshot_dir.clone(),
            finalization_rx,
        };
        tokio::spawn(finalizer_worker.run());

        let is_bootstrap_node = args.bootstrap_node.is_empty();
        let snapshot_path_for_rpc = args.snapshot_path.clone();
        let snapshot_path_for_p2p = args.snapshot_path.clone();

        let p2p_keypair = {
            let p2p_key_path = Path::new(&args.db_path).join("p2p_keypair");

            if p2p_key_path.exists() {
                match fs::read(&p2p_key_path) {
                    Ok(mut key_bytes) => {
                        match ed25519::SecretKey::try_from_bytes(&mut key_bytes) {
                            Ok(secret_key) => {
                                let ed25519_keypair = ed25519::Keypair::from(secret_key);
                                let keypair = P2pKeypair::from(ed25519_keypair);
                                info!("P2P keypair berhasil dimuat dari: {:?}", p2p_key_path);
                                keypair
                            }
                            Err(e) => {
                                warn!("File P2P keypair corrupt, membuat yang baru. Error: {}", e);

                                let backup_path = p2p_key_path.with_extension("corrupt.bak");
                                let _ = fs::rename(&p2p_key_path, &backup_path);

                                let ed25519_keypair = ed25519::Keypair::generate();
                                fs::write(&p2p_key_path, ed25519_keypair.secret().as_ref())
                                    .map_err(|e| format!("Gagal menyimpan keypair baru: {}", e))?;
                                info!("P2P keypair baru berhasil dibuat");
                                P2pKeypair::from(ed25519_keypair)
                            }
                        }
                    }
                    Err(e) => {
                        error!("Gagal membaca file P2P keypair: {}", e);
                        return Err(e.into());
                    }
                }
            } else {
                let ed25519_keypair = ed25519::Keypair::generate();
                fs::write(&p2p_key_path, ed25519_keypair.secret().as_ref())
                    .map_err(|e| format!("Gagal menyimpan keypair: {}", e))?;
                info!("P2P keypair baru berhasil dibuat dan disimpan ke: {:?}", p2p_key_path);
                P2pKeypair::from(ed25519_keypair)
            }
        };

        let local_peer_id = PeerId::from(p2p_keypair.public());
        info!("Peer ID lokal (dari main, persisten): {}", local_peer_id);

        let bootstrap_nodes_clone = args.bootstrap_node.clone();

        let rpc_future = rpc::run(
            Arc::clone(&blockchain),
            Arc::clone(&mempool),
            tx_gossip.clone(),
            args.rpc_port,
            PathBuf::from(snapshot_path_for_rpc),
        );

        if !args.bootstrap_node.is_empty() {
            let delay_ms = rand::rng().random_range(500..2000);
            info!("Node non-bootstrap, menunggu selama {}ms sebelum memulai P2P untuk memberi waktu pada bootstrap node.", delay_ms);
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        let p2p_future = p2p::run(
            p2p_keypair,
            Arc::clone(&blockchain),
            Arc::clone(&mempool),
            rx_gossip,
            rx_sync_cmd,
            tx_sync_resp.clone(),
            tx_sync_cmd.clone(),
            bootstrap_nodes_clone,
            args.p2p_port,
            consensus_msg_tx,
            txs_response_to_consensus_tx,
            snapshot_path_for_p2p,
            is_bootstrap_node,
            consensus_state,
            p2p_cmd_rx,
            p2p_cmd_tx.clone(),
            p2p_ready_flag.clone(), 
            new_block_tx.subscribe(),
            Arc::clone(&address_book),
            sync_trigger_tx.clone(),
        );

        let sync_is_syncing_flag = Arc::clone(&is_syncing_flag);
        let sync_consensus_ready_flag = Arc::clone(&consensus_ready_flag);
        let sync_p2p_cmd_tx = p2p_cmd_tx.clone();
        let sync_blockchain_clone = Arc::clone(&blockchain);
        let mut sync_manager_rx_resp = tx_sync_resp.subscribe();
        let sync_snapshot_dir = snapshot_dir.clone();
        let sync_restart_tx = restart_tx.clone();
        let db_path_for_sync_manager = args.db_path.clone();

        tokio::spawn(async move {
            loop {
                if p2p_ready_flag.load(Ordering::SeqCst) {
                    info!("[SYNC_MANAGER] Sinyal P2PReady diterima. Memulai SyncManager.");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            let mut sync_state = SyncState::Idle;
            let mut peer_health: HashMap<PeerId, PeerHealthStatus> = HashMap::new();
            let mut next_sync_state: Option<SyncState> = Some(SyncState::InitialAssessment { peers_queried: 0, responses: HashMap::new() });
            
            loop {
                if let Some(new_state) = next_sync_state.take() {
                    match new_state {
                        SyncState::InitialAssessment { .. } => {
                            if !sync_is_syncing_flag.load(Ordering::SeqCst) {
                                info!("[SYNC_MANAGER] Memasuki mode penilaian/sinkronisasi.");
                                sync_is_syncing_flag.store(true, Ordering::SeqCst);
                                sync_consensus_ready_flag.store(false, Ordering::SeqCst);
                            }
                            
                            let (tx, rx) = oneshot::channel();
                            if sync_p2p_cmd_tx.send(P2pCommand::GetConnectedPeers(tx)).await.is_err() {
                                warn!("[SYNC_MANAGER] Gagal mengirim permintaan daftar peer.");
                                sync_state = SyncState::Idle;
                            } else if let Ok(peers) = rx.await {
                                let num_peers = peers.len();
                                info!("[SYNC_MANAGER] Mengirim GetChainInfo ke {} peer.", num_peers);
                                for peer in peers {
                                    let _ = sync_p2p_cmd_tx.send(P2pCommand::SendDirectRequest { destination: peer, request: SyncRequest::GetChainInfo }).await;
                                }
                                sync_state = SyncState::InitialAssessment { peers_queried: num_peers, responses: HashMap::new() };
                            } else {
                                sync_state = SyncState::Idle;
                            }
                        },
                        _ => {
                            sync_state = new_state;
                        }
                    }
                }

                select! {
                    Some(_) = sync_trigger_rx.recv() => {
                        if !sync_is_syncing_flag.load(Ordering::SeqCst) {
                            warn!("[SYNC_MANAGER] Menerima pemicu sinkronisasi paksa. Memulai ulang penilaian.");
                            next_sync_state = Some(SyncState::InitialAssessment { peers_queried: 0, responses: HashMap::new() });
                        }
                    },

                    Ok((response, source_peer)) = sync_manager_rx_resp.recv() => {
                        match &mut sync_state {
                            SyncState::InitialAssessment { peers_queried, responses } => {
                                if let SyncResponse::ChainInfo { height, .. } = response {
                                    responses.insert(source_peer, PeerHealthStatus { peer_id: source_peer, height });
                                    
                                    let decision_threshold = (*peers_queried / 2).max(1);
                                    if responses.len() >= decision_threshold {
                                        let local_height = sync_blockchain_clone.read().await.chain.last().map_or(0, |b| b.header.index);
                                        
                                        peer_health.clear();
                                        for (peer_id, status) in responses.iter() {
                                            peer_health.insert(*peer_id, status.clone());
                                        }

                                        if let Some(best_peer) = responses.values().max_by_key(|s| s.height).cloned() {
                                            if best_peer.height == 0 && local_height == 0 {
                                                info!("[SYNC_MANAGER] Kondisi Genesis terdeteksi. Jaringan siap untuk konsensus.");
                                                next_sync_state = Some(SyncState::Idle);
                                            } else if best_peer.height > local_height {
                                                warn!("[SYNC_MANAGER] Terdeteksi tertinggal. Lokal: {}, Jaringan: {}. Memulai sinkronisasi.", local_height, best_peer.height);
                                                let gap = best_peer.height.saturating_sub(local_height);
                                                if gap > SNAPSHOT_SYNC_THRESHOLD {
                                                    let _ = sync_p2p_cmd_tx.send(P2pCommand::SendDirectRequest { destination: best_peer.peer_id, request: SyncRequest::GetSnapshotMetadata }).await;
                                                    next_sync_state = Some(SyncState::RequestingSnapshotMetadata { best_peer });
                                                } else {
                                                    let _ = sync_p2p_cmd_tx.send(P2pCommand::SendDirectRequest {
                                                        destination: best_peer.peer_id,
                                                        request: SyncRequest::GetBlockHeaders { since_index: local_height + 1, count: 200 },
                                                    }).await;
                                                    next_sync_state = Some(SyncState::SyncingHeaders { best_peer: best_peer.peer_id, since_index: local_height + 1, fetched_headers: Vec::new() });
                                                }
                                            } else {
                                                info!("[SYNC_MANAGER] Sinkron. Kembali ke mode Idle.");
                                                next_sync_state = Some(SyncState::Idle);
                                            }
                                        } else {
                                            info!("[SYNC_MANAGER] Tidak ada data peer. Kembali ke Idle.");
                                            next_sync_state = Some(SyncState::Idle);
                                        }
                                    }
                                }
                            },
                            SyncState::RequestingSnapshotMetadata { best_peer } => {
                                if let SyncResponse::SnapshotMetadata(Some(metadata)) = response {
                                    let local_height = sync_blockchain_clone.read().await.chain.last().map_or(0, |b| b.header.index);
                                    if metadata.height > local_height {
                                        info!("[SYNC_MANAGER] Menerima metadata snapshot untuk blok #{}. Memulai unduhan.", metadata.height);
                                        let temp_path = sync_snapshot_dir.join(format!("downloading_{}.part", metadata.file_name));
                                        match OpenOptions::new().write(true).create(true).truncate(true).open(&temp_path) {
                                            Ok(temp_file) => {
                                                let request = SyncRequest::GetSnapshotChunk { file_name: metadata.file_name.clone(), chunk_index: 0 };
                                                let _ = sync_p2p_cmd_tx.send(P2pCommand::SendDirectRequest { destination: best_peer.peer_id, request }).await;
                                                next_sync_state = Some(SyncState::DownloadingSnapshot { metadata, temp_file: Arc::new(Mutex::new(temp_file)), next_chunk: 0, source_peer: best_peer.peer_id });
                                            },
                                            Err(e) => {
                                                error!("[SYNC_MANAGER] Gagal membuat file snapshot sementara: {}. Membatalkan.", e);
                                                next_sync_state = Some(SyncState::Idle);
                                            },
                                        }
                                    } else {
                                        warn!("[SYNC_MANAGER] Menerima metadata snapshot, tetapi tidak lagi relevan. Kembali ke Idle.");
                                        next_sync_state = Some(SyncState::Idle);
                                    }
                                }
                            },
                            SyncState::DownloadingSnapshot { metadata, temp_file, next_chunk, source_peer } => {
                                if let SyncResponse::SnapshotChunk { data } = response {
                                    if data.is_empty() {
                                        info!("[SYNC_MANAGER] Semua chunk snapshot telah diunduh. Menjadwalkan penerapan...");

                                        let temp_path = sync_snapshot_dir.join(format!("downloading_{}.part", metadata.file_name));
                                        let final_path = sync_snapshot_dir.join(&metadata.file_name);
                                        
                                        if let Err(e) = std::fs::rename(&temp_path, &final_path) {
                                            error!("[SYNC_MANAGER] Gagal me-rename file snapshot: {}. Membatalkan.", e);
                                            next_sync_state = Some(SyncState::Idle);
                                        } else {
                                            info!("[SYNC_MANAGER] Snapshot '{}' siap diterapkan.", metadata.file_name);
                                            
                                            let db_path_for_task = db_path_for_sync_manager.clone();
                                            let snapshot_dir_clone = sync_snapshot_dir.clone();
                                            let metadata_clone = metadata.clone();

                                            let apply_result = tokio::task::spawn_blocking(move || {
                                                snapshot::load_snapshot(
                                                    db_path_for_task, 
                                                    snapshot_dir_clone, 
                                                    &metadata_clone
                                                )
                                            }).await;

                                            match apply_result {
                                                Ok(Ok(_)) => {
                                                    info!("[SYNC_MANAGER] Penerapan snapshot berhasil. Mengirim sinyal restart ke node utama.");
                                                    if sync_restart_tx.send(()).await.is_err() {
                                                        error!("[SYNC_MANAGER] KRITIS: Gagal mengirim sinyal restart. Node mungkin perlu di-restart manual.");
                                                    }
                                                    next_sync_state = Some(SyncState::RestartingNode);
                                                },
                                                Ok(Err(e)) => {
                                                    error!("[SYNC_MANAGER] KRITIS: Gagal menerapkan snapshot: {}. Kembali ke Idle.", e);
                                                    next_sync_state = Some(SyncState::Idle);
                                                },
                                                Err(e) => {
                                                    error!("[SYNC_MANAGER] KRITIS: Task penerapan snapshot mengalami panic: {}. Kembali ke Idle.", e);
                                                    next_sync_state = Some(SyncState::Idle);
                                                }
                                            }
                                        }
                                    } else {
                                        let mut file_lock = temp_file.lock().await;
                                        if file_lock.write_all(&data).is_ok() {
                                            let chunk_to_request = *next_chunk + 1;
                                            info!("[SYNC_MANAGER] Mengunduh chunk {}/{}", chunk_to_request, metadata.total_chunks);
                                            let request = SyncRequest::GetSnapshotChunk { file_name: metadata.file_name.clone(), chunk_index: chunk_to_request };
                                            let _ = sync_p2p_cmd_tx.send(P2pCommand::SendDirectRequest { destination: *source_peer, request }).await;
                                            *next_chunk = chunk_to_request;
                                        } else {
                                            error!("[SYNC_MANAGER] Gagal menulis chunk ke file sementara. Membatalkan sinkronisasi.");
                                            next_sync_state = Some(SyncState::Idle);
                                        }
                                    }
                                }
                            },
                            SyncState::SyncingHeaders { best_peer, since_index, fetched_headers } => {
                                if let SyncResponse::BlockHeaders { headers, .. } = response {
                                    if headers.is_empty() {
                                        info!("[SYNC_MANAGER] Semua header diunduh. Fokus menyelesaikan unduhan badan blok.");
                                        let peers_to_use = peer_health.keys().cloned().collect();
                                        next_sync_state = Some(SyncState::SyncingBodies {
                                            headers_to_fetch: std::mem::take(fetched_headers).into(), 
                                            peers: peers_to_use,
                                            pending_bodies: HashMap::new(),
                                            received_bodies: HashMap::new(),
                                        });
                                    } else {
                                        let chain = sync_blockchain_clone.read().await;
                                        let last_known_header = if fetched_headers.is_empty() {
                                            chain.chain.last().unwrap().header.clone()
                                        } else {
                                            fetched_headers.last().unwrap().clone()
                                        };

                                        if chain.verify_header_chain(&headers, &last_known_header) {
                                            let last_idx = headers.last().unwrap().index;
                                            *since_index = last_idx + 1;

                                            // 1. Langsung pindahkan header yang baru diterima ke antrian unduh body
                                            let mut headers_to_download_now: VecDeque<_> = headers.clone().into();

                                            if let Some(SyncState::SyncingBodies { headers_to_fetch, .. }) = &mut next_sync_state {
                                                headers_to_fetch.append(&mut headers_to_download_now);
                                            } else {
                                                let peers_to_use = peer_health.keys().cloned().collect();
                                                next_sync_state = Some(SyncState::SyncingBodies {
                                                    headers_to_fetch: headers_to_download_now,
                                                    peers: peers_to_use,
                                                    pending_bodies: HashMap::new(),
                                                    received_bodies: HashMap::new(),
                                                });
                                            }
                                            
                                            // 2. Tetap minta batch header berikutnya secara paralel
                                            fetched_headers.extend(headers); 
                                            info!("[SYNC_MANAGER] Menerima {} header valid. Memulai unduh body & meminta batch berikutnya dari blok #{}.", fetched_headers.len(), *since_index);
                                            let _ = sync_p2p_cmd_tx.send(P2pCommand::SendDirectRequest {
                                                destination: *best_peer,
                                                request: SyncRequest::GetBlockHeaders { since_index: *since_index, count: 200 },
                                            }).await;

                                            sync_state = SyncState::Idle; 
                                        } else {
                                            warn!("[SYNC_MANAGER] Menerima rantai header tidak valid. Kembali ke Idle.");
                                            next_sync_state = Some(SyncState::Idle);
                                        }
                                    }
                                }
                            },
                            SyncState::SyncingBodies { received_bodies, pending_bodies, .. } => {
                                if let SyncResponse::FullProposal(Some(block)) = response {
                                    let block_hash = block.header.calculate_hash();
                                    if let Some(header) = pending_bodies.remove(&block_hash) {
                                        let full_block = Block { header, transactions: block.transactions, round: block.round, view_number: block.round, justify: block.parent_qc, vrf_output: vec![], vrf_proof: vec![] };
                                        received_bodies.insert(full_block.header.index, full_block);
                                    }
                                }
                            },
                            _ => {} 
                        }
                    },
                    
                    _ = tokio::time::sleep(Duration::from_secs(15)), if matches!(sync_state, SyncState::InitialAssessment {..}) => {
                        warn!("[SYNC_MANAGER] Timeout saat penilaian. Kembali ke Idle.");
                        next_sync_state = Some(SyncState::Idle);
                    },
                }

                if let SyncState::SyncingBodies { headers_to_fetch, peers, pending_bodies, received_bodies } = &mut sync_state {
                    let mut last_processed_index = sync_blockchain_clone.read().await.chain.last().map_or(0, |b| b.header.index);
                    let mut blocks_to_commit = Vec::new();
                    while let Some(block) = received_bodies.remove(&(last_processed_index + 1)) {
                        blocks_to_commit.push(block);
                        last_processed_index += 1;
                    }

                    if !blocks_to_commit.is_empty() {
                        let num_blocks_to_commit = blocks_to_commit.len();

                        if let Err(e) = sync_blockchain_clone.write().await.write_finalized_blocks_to_db(blocks_to_commit).await {
                            error!("[SYNC_MANAGER] Gagal menerapkan badan blok: {}. Kembali ke Idle.", e);
                            next_sync_state = Some(SyncState::Idle);
                        } else {
                            info!(
                                "[SYNC_MANAGER] Catch-up: Berhasil menerapkan {} blok. Tinggi lokal sekarang: #{}",
                                num_blocks_to_commit,
                                last_processed_index
                            );
                        }
                    }

                    while pending_bodies.len() < MAX_PARALLEL_BODY_DOWNLOADS && !headers_to_fetch.is_empty() {
                        if let Some(header) = headers_to_fetch.pop_front() {
                            let peer_index = header.index as usize % peers.len();
                            if let Some(peer_id) = peers.get(peer_index).cloned() {
                                let block_hash = header.calculate_hash();
                                debug!("[SYNC_MANAGER] Catch-up: Meminta badan blok #{} (hash: 0x{}) dari peer {}", header.index, hex::encode(&block_hash[..4]), peer_id); 
                                pending_bodies.insert(block_hash.clone(), header);
                                let _ = sync_p2p_cmd_tx.send(P2pCommand::SendDirectRequest { destination: peer_id, request: SyncRequest::GetFullProposal(block_hash) }).await;
                            }
                        }
                    }

                    if headers_to_fetch.is_empty() && pending_bodies.is_empty() {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        if received_bodies.is_empty() {
                            info!("[SYNC_MANAGER] Sinkronisasi badan blok selesai.");
                            next_sync_state = Some(SyncState::Idle);
                        }
                    }
                }

                if let Some(SyncState::Idle) = &next_sync_state {
                    if sync_is_syncing_flag.load(Ordering::SeqCst) {
                        info!("[SYNC_MANAGER] Proses penilaian/sinkronisasi selesai. Mengaktifkan konsensus.");
                        sync_is_syncing_flag.store(false, Ordering::SeqCst);
                        sync_consensus_ready_flag.store(true, Ordering::SeqCst);
                    }
                }
            }
        });

        let pruning_blockchain_clone = Arc::clone(&blockchain);
        tokio::spawn(async move {
            let mut pruning_interval = tokio::time::interval(Duration::from_secs(100 * 10));
            const PRUNING_HORIZON: u64 = 100_000;

            loop {
                pruning_interval.tick().await;
                info!("PRUNING_TASK: Memulai tugas pemangkasan state periodik.");
                let chain = pruning_blockchain_clone.read().await;
                if let Err(e) = chain.state.prune(PRUNING_HORIZON) {
                    error!("PRUNING_TASK: Gagal melakukan pemangkasan state: {}", e);
                }
            }
        });

        tokio::try_join!(
            async { p2p_future.await.map_err(|e| e.into()) },
            async { rpc_future.await }
        )?;

        select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Menerima sinyal Ctrl-C, node berhenti.");
                break; 
            },
            _ = restart_rx.recv() => {
                info!("[MAIN] Menerima sinyal restart setelah penerapan snapshot. Me-restart semua layanan...");
                continue;
            },
        }
    }

    Ok(())
}