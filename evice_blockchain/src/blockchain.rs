// evice_blockchain/src/blockchain.rs

use ark_bls12_377::{Bls12_377, Fr};
use ark_bw6_761::{Fr as Bw6_761Fr, BW6_761};
use ark_crypto_primitives::snark::constraints::EmulatedFieldInputVar;
use ark_crypto_primitives::snark::FromFieldElementsGadget;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use ark_std::sync::Arc;
use async_recursion::async_recursion;
use bincode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
use futures::future;
use hash_db::{AsHashDB, HashDB, HashDBRef, Hasher};
use keccak_hasher::KeccakHasher;
use libp2p::Multiaddr;
use log::{error, info, warn};
use lru::LruCache;
use rayon::prelude::*;
use merlin::Transcript;
use schnorrkel::{
    vrf::{VRFPreOut, VRFProof},
    PublicKey as VrfPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::task;
use trie_db::{
    TrieDBMut, TrieDBMutBuilder, TrieDBBuilder,
    TrieError, TrieMut, Trie, DBValue, 
};
use wasmer::{
    CompileError, ExportError, InstantiationError, LinkError, MemoryAccessError, MemoryError,
    RuntimeError, WasmError,
};

use crate::state::{
    Account, ParityDbTrieBackend, StateError, StateMachine, TrieSession, ACTIVE_SEQUENCERS_KEY,
    COL_BLOCKS, COL_CONTRACT_CODE, COL_CONTRACT_STORAGE, COL_GOVERNANCE, COL_L2_BATCHES,
    COL_METADATA, COL_STATE_JOURNAL, COL_TRIE, COL_TX_LOOKUP, DATA_AVAILABILITY_COMMITTEE, 
    H256, L2_BRIDGE_ADDRESS, L2_STATE_ROOT_KEY, MINIMUM_STAKE, NEXT_PROPOSAL_ID_KEY, 
    PROPOSAL_VOTING_PERIOD, STATE_ROOT_KEY, VALIDATORS_KEY,
};
use crate::{
    block_tree::{BlockProcessingResult, BlockTree},
    consensus::{ConsensusMessage, QuorumCertificate, VelocityVote},
    crypto::{public_key_to_address, DkgState, KeyPair, ADDRESS_SIZE, SIGNATURE_SIZE},
    governance::ProposalState,
    serde_helpers, wasm_runtime, crypto, Address, 
    EviceTrieLayout, Transaction, TransactionData,
};

type StateOverlay = HashMap<H256, DBValue>;
pub type PublicKey = [u8; ADDRESS_SIZE];
pub type Signature = [u8; SIGNATURE_SIZE];
pub const INITIAL_BASE_FEE: u64 = 10;
const INACTIVITY_THRESHOLD_BLOCKS: u64 = 1000;
const INACTIVITY_SLASH_PERCENT: u64 = 1;

impl Default for Block {
    fn default() -> Self {
        Self {
            header: BlockHeader {
                index: 0,
                timestamp: 0,
                prev_hash: vec![0; 32],
                state_root: vec![0; 32],
                transactions_root: vec![0; 32],
                l2_transactions_hash: None,
                authority: Address([0; 20]),
                gas_used: 0,
                base_fee_per_gas: INITIAL_BASE_FEE,
                signature: [0; SIGNATURE_SIZE],
            },
            transactions: vec![],
            round: 0,
            view_number: 0,
            justify: QuorumCertificate::genesis_qc(),
            vrf_output: vec![],
            vrf_proof: vec![],
        }
    }
}

#[derive(Debug, Default)]
struct CanonicalResult {
    validators_to_jail: Vec<Address>,
    final_validators: HashSet<Address>,
    final_sequencers: HashSet<Address>,
    new_l2_state_root: Vec<u8>,
}

#[derive(Clone)]
struct ExecutionContext<'a> {
    validators: &'a HashSet<Address>,
    sequencers: &'a HashSet<Address>,
    l2_root: &'a Vec<u8>,
    validator_last_seen: &'a HashMap<Address, u64>,
}

fn get_account_helper(
    temporary_accounts: &BTreeMap<Address, Account>,
    address: &Address,
    trie: &impl Trie<EviceTrieLayout>,
) -> Result<Account, BlockchainError> {
    if let Some(account) = temporary_accounts.get(address) {
        return Ok(account.clone());
    }
    trie.get(&KeccakHasher::hash(address.as_ref()))?
        .and_then(|d| {
            bincode::decode_from_slice(&d, bincode::config::standard())
                .ok()
                .map(|(acc, _)| acc)
        })
        .ok_or_else(|| {
            BlockchainError::TransactionInvalid(format!(
                "Akun tidak ditemukan: {}",
                hex::encode(address.as_ref())
            ))
        })
}

pub struct SpeculativeNode {
    pub block_hash: Vec<u8>,
    pub parent_hash: Vec<u8>,
    pub header: BlockHeader,
    pub state_overlay: StateOverlay,
}

pub struct SpeculativeChain {
    nodes: LruCache<Vec<u8>, (Block, Arc<tokio::sync::Mutex<TrieSession>>)>,
    finalized_head: Vec<u8>,
    pub l2_verifying_key: VerifyingKey<Bls12_377>,
    pub l2_aggregation_verifying_key: VerifyingKey<BW6_761>,
}

impl SpeculativeChain {
    pub fn new(
        finalized_head: BlockHeader,
        l2_verifying_key: VerifyingKey<Bls12_377>,
        l2_aggregation_verifying_key: VerifyingKey<BW6_761>,
    ) -> Self {
        Self {
            nodes: LruCache::new(std::num::NonZeroUsize::new(256).unwrap()),
            finalized_head: finalized_head.calculate_hash(),
            l2_verifying_key,
            l2_aggregation_verifying_key,
        }
    }

    pub async fn add_block(
        &mut self, 
        block: &Block,
        blockchain: &Blockchain,
    ) -> Result<(), BlockchainError> {
        let block_hash = block.header.calculate_hash();
        if self.nodes.contains(&block_hash) {
            return Ok(());
        }

        info!(
            "[SPECULATIVE] Mengeksekusi blok #{} (hash: 0x{})",
            block.header.index,
            hex::encode(&block_hash[..4])
        );

        let parent_session = self
        .create_session_for_hash(&block.header.prev_hash, &blockchain.state) 
        .await?;

        let validators = &blockchain.state.validators;
        let sequencers = &blockchain.state.active_sequencers;
        let l2_root = &blockchain.state.l2_state_root;

        let (final_session, _applied_txs, _changed_accounts) = blockchain
            .apply_transactions_to_session( 
                parent_session,
                &block.header,
                &block.transactions,
                validators,
                sequencers,
                l2_root,
            )
            .await?;

        self.nodes.put(
            block_hash,
            (block.clone(), Arc::new(Mutex::new(final_session))),
        );
        Ok(())
    }

    pub fn speculative_head_height(&self) -> u64 {
        self.nodes
            .iter()
            .map(|(_, (block, _))| block.header.index)
            .max()
            .unwrap_or(0)
    }

    #[async_recursion]
    pub async fn create_session_for_hash(
        &mut self,
        block_hash: &[u8],
        finalized_state: &StateMachine, 
    ) -> Result<TrieSession, BlockchainError> {
        if block_hash == self.finalized_head {
            return Ok(finalized_state.create_trie_session(finalized_state.state_root, COL_TRIE));
        }

        if let Some((_, session_arc)) = self.nodes.get(block_hash) {
            let session = session_arc.lock().await;
            return Ok((*session).clone());
        }

        Err(BlockchainError::LogicError(
            "Blok induk spekulatif tidak ditemukan di cache".into(),
        ))
    }

    pub fn get_block_header_by_hash(&self, hash: &[u8]) -> Option<BlockHeader> {
        self.nodes
            .peek(hash)
            .map(|(block, _session)| block.header.clone())
    }

    pub fn get_speculative_block_by_hash(&self, hash: &[u8]) -> Option<Block> {
        self.nodes
        .peek(hash)
        .map(|(block, _)| block.clone())
    }

    pub fn get_speculative_block_by_index(&self, index: u64) -> Option<Block> {
        self.nodes
            .iter()
            .find(|(_, (block, _))| block.header.index == index)
            .map(|(_, (block, _))| block.clone())
    }

    pub fn prune_speculative_block(&mut self, block_hash_to_remove: &[u8]) {
        if self.nodes.peek(block_hash_to_remove).is_none() {
            return;
        }

        let mut to_remove = vec![block_hash_to_remove.to_vec()];
        let mut i = 0;
        while i < to_remove.len() {
            let parent_hash = &to_remove[i];
            let children: Vec<Vec<u8>> = self
                .nodes
                .iter()
                .filter(|(_hash, (block, _session))| block.header.prev_hash == *parent_hash)
                .map(|(hash, _)| hash.clone())
                .collect();

            for child_hash in children {
                if !to_remove.contains(&child_hash) {
                    to_remove.push(child_hash);
                }
            }
            i += 1;
        }

        for hash in to_remove.iter().rev() {
            self.nodes.pop(hash);
            info!(
                "[SPECULATIVE] Membersihkan blok spekulatif yang gagal: 0x{}",
                hex::encode(&hash[..4])
            );
        }
    }

    pub fn finalize_block(&mut self, finalized_block: &Block) {
        let finalized_hash = finalized_block.header.calculate_hash();
        info!(
            "[SPECULATIVE] Finalisasi blok #{}. Head baru: 0x{}",
            finalized_block.header.index,
            hex::encode(&finalized_hash[..4])
        );

        self.finalized_head = finalized_hash;
    }
}

#[derive(Clone)]
pub struct ChainSnapshot {
    pub last_header: Option<BlockHeader>,
    pub current_state_root: H256,
    pub validators: HashSet<Address>,
    pub active_sequencers: HashSet<Address>,
    pub l2_state_root: Vec<u8>,
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Encode,
    Decode,
)]
pub struct BlockHeader {
    pub index: u64,
    pub timestamp: u128,
    pub prev_hash: Vec<u8>,
    pub state_root: Vec<u8>,
    pub transactions_root: Vec<u8>,
    #[serde(with = "serde_helpers::option_vec_u8")]
    pub l2_transactions_hash: Option<Vec<u8>>,
    pub authority: Address,
    pub gas_used: u64,
    pub base_fee_per_gas: u64,
    #[serde(with = "serde_bytes")]
    pub signature: Signature,
}

impl Default for BlockHeader {
    fn default() -> Self {
        Self {
            index: 0,
            timestamp: 0,
            prev_hash: vec![0; 32],
            state_root: vec![0; 32],
            transactions_root: vec![0; 32],
            l2_transactions_hash: None,
            authority: Address([0; 20]),
            gas_used: 0,
            base_fee_per_gas: INITIAL_BASE_FEE,
            signature: [0; SIGNATURE_SIZE],
        }
    }
}

impl BlockHeader {
    pub fn canonical_bytes_for_signing(&self) -> Vec<u8> {
        #[derive(BorshSerialize)]
        struct HeaderForSigning<'a> {
            index: u64,
            timestamp: u128,
            prev_hash: &'a Vec<u8>,
            state_root: &'a Vec<u8>,
            transactions_root: &'a Vec<u8>,
            l2_transactions_hash: &'a Option<Vec<u8>>,
            authority: Address,
            gas_used: u64,
            base_fee_per_gas: u64,
        }

        let data_to_sign = HeaderForSigning {
            index: self.index,
            timestamp: self.timestamp,
            prev_hash: &self.prev_hash,
            state_root: &self.state_root,
            transactions_root: &self.transactions_root,
            l2_transactions_hash: &self.l2_transactions_hash,
            authority: self.authority,
            gas_used: self.gas_used,
            base_fee_per_gas: self.base_fee_per_gas,
        };

        borsh::to_vec(&data_to_sign).expect("Serialisasi header untuk signing tidak boleh gagal.")
    }

    pub fn calculate_hash(&self) -> Vec<u8> {
        let w = borsh::to_vec(self).expect("Serialisasi Borsh untuk header tidak boleh gagal.");
        Sha256::digest(&w).to_vec()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Encode, Decode)]
pub struct DoubleSignEvidence {
    pub header1: BlockHeader,
    pub header2: BlockHeader,
}

impl BorshSerialize for DoubleSignEvidence {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.header1, writer)?;
        BorshSerialize::serialize(&self.header2, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for DoubleSignEvidence {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(Self {
            header1: BorshDeserialize::deserialize_reader(reader)?,
            header2: BorshDeserialize::deserialize_reader(reader)?,
        })
    }
}

#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, Encode, Decode,
)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub round: u64,
    pub view_number: u64,
    pub justify: QuorumCertificate,
    #[serde(with = "serde_bytes")]
    pub vrf_output: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub vrf_proof: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub enum ChainMessage {
    NewTransaction(Transaction),
    NewTransactionHash(Vec<u8>),
    NewConsensusMessage(ConsensusMessage),
    GetTransaction(Vec<u8>),
    PeerList(Vec<String>),
}

#[derive(Debug, Error)]
pub enum BlockchainError {
    #[error("Missing parent block: 0x{parent_hash:?}")]
    MissingParent { parent_hash: Vec<u8> },
    #[error("Database error: {0}")]
    Db(#[from] parity_db::Error),
    #[error("State error: {0}")]
    State(#[from] crate::state::StateError),
    #[error("Serialization error: {0}")]
    Bincode(#[from] bincode::error::EncodeError),
    #[error("Deserialization error: {0}")]
    BincodeDecode(#[from] Box<bincode::error::DecodeError>),
    #[error("Trie error: {0}")]
    Trie(String),
    #[error("Genesis block not found. Chain is uninitialized.")]
    UninitializedChain,
    #[error("Invalid block index. Expected {expected}, got {got}.")]
    InvalidIndex { expected: u64, got: u64 },
    #[error("Previous block hash does not match.")]
    PreviousHashMismatch,
    #[error("Block signature is invalid.")]
    InvalidSignature,
    #[error("Block authority is not a registered validator.")]
    NotAValidator,
    #[error("VRF proof verification failed.")]
    VrfVerificationFailed,
    #[error("VRF output does not meet the required threshold.")]
    VrfThresholdNotMet,
    #[error("Transaction validation failed: {0}")]
    TransactionInvalid(String),
    #[error("Stale nonce for transaction. Expected >= {expected}, got {got}.")]
    StaleNonce { expected: u64, got: u64 },
    #[error("Insufficient balance for transaction. Has {has}, needs {needs}.")]
    InsufficientBalance { has: u64, needs: u64 },
    #[error("State root mismatch! Expected {expected}, Got: {got}")]
    StateRootMismatch { expected: String, got: String },
    #[error("Transactions root mismatch!")]
    TransactionsRootMismatch,
    #[error("Invalid double signing evidence: {0}")]
    InvalidDoubleSignEvidence(String),
    #[error("Vote signature is invalid.")]
    InvalidVoteSignature,
    #[error("ZK proof synthesis error: {0}")]
    SynthesisError(#[from] ark_relations::r1cs::SynthesisError),
    #[error("WASM runtime error: {0}")]
    WasmError(String),
    #[error("State machine logic error: {0}")]
    LogicError(String),
    #[error("Serialization error from Arkworks: {0}")]
    ArkSerialization(#[from] ark_serialize::SerializationError),
}

impl From<Box<bincode::error::EncodeError>> for BlockchainError {
    fn from(e: Box<bincode::error::EncodeError>) -> Self {
        BlockchainError::Bincode(*e)
    }
}

impl From<WasmError> for BlockchainError {
    fn from(e: WasmError) -> Self {
        BlockchainError::WasmError(e.to_string())
    }
}

impl From<LinkError> for BlockchainError {
    fn from(e: LinkError) -> Self {
        BlockchainError::WasmError(format!("Linker error: {}", e))
    }
}

impl From<MemoryError> for BlockchainError {
    fn from(e: MemoryError) -> Self {
        BlockchainError::WasmError(format!("Memory error: {}", e))
    }
}

impl From<CompileError> for BlockchainError {
    fn from(e: CompileError) -> Self {
        BlockchainError::WasmError(e.to_string())
    }
}

impl From<InstantiationError> for BlockchainError {
    fn from(e: InstantiationError) -> Self {
        BlockchainError::WasmError(e.to_string())
    }
}

impl From<ExportError> for BlockchainError {
    fn from(e: ExportError) -> Self {
        BlockchainError::WasmError(e.to_string())
    }
}

impl From<RuntimeError> for BlockchainError {
    fn from(e: RuntimeError) -> Self {
        BlockchainError::WasmError(e.to_string())
    }
}

impl From<MemoryAccessError> for BlockchainError {
    fn from(e: MemoryAccessError) -> Self {
        BlockchainError::WasmError(e.to_string())
    }
}

impl<L: std::fmt::Debug, E: std::fmt::Debug> From<Box<TrieError<L, E>>> for BlockchainError {
    fn from(err: Box<TrieError<L, E>>) -> Self {
        BlockchainError::Trie(format!("{:?}", err))
    }
}

impl Block {
    pub fn calculate_transactions_root(transactions: &[Transaction]) -> Vec<u8> {
        if transactions.is_empty() {
            return vec![0; 32];
        }
        let tx_hashes: Vec<u8> = transactions
            .iter()
            .flat_map(|tx| tx.message_hash())
            .collect();
        Sha256::digest(&tx_hashes).to_vec()
    }
}

#[derive(Clone, Default, Debug)]
pub struct ChainInfoSnapshot {
    pub height: u64,
    pub best_block_hash: Vec<u8>,
}

#[derive(Clone)]
pub struct Blockchain {
    pub chain: Vec<Block>,
    pub state: StateMachine,
    pub l2_verifying_key: VerifyingKey<Bls12_377>,
    pub l2_aggregation_verifying_key: VerifyingKey<BW6_761>,
    pub dkg_state: DkgState,
    processed_evidence: HashSet<Vec<u8>>,
    block_hash_cache: HashMap<Vec<u8>, Block>,
    pub block_tree: Arc<RwLock<BlockTree>>,
    pub speculative_chain: Arc<RwLock<SpeculativeChain>>,
    pub info_snapshot: Arc<RwLock<ChainInfoSnapshot>>,
}

impl Blockchain {
    pub fn new(
        db_path: &str,
        vk_path: &str,
        agg_vk_path: &str,
        block_processing_tx: mpsc::Sender<BlockProcessingResult>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let state = StateMachine::new(db_path)?;
        let mut chain = Vec::new();
        let mut block_hash_cache = HashMap::new();

        if let Ok(Some(genesis_block_bytes)) = state.db.get(COL_BLOCKS, &0u64.to_be_bytes()) {
            if let Ok((genesis_block, _)) = bincode::decode_from_slice::<Block, _>(
                &genesis_block_bytes,
                bincode::config::standard(),
            ) {
                block_hash_cache
                    .insert(genesis_block.header.calculate_hash(), genesis_block.clone());
            }
        }

        info!("Mencoba memuat L2 Verifying Key dari '{}'...", vk_path);
        let mut vk_file = File::open(vk_path).map_err(|e| {
            format!(
                "KRITIS: Gagal membuka file verifying key '{}'. Error: {}",
                vk_path, e
            )
        })?;

        let l2_verifying_key = VerifyingKey::<Bls12_377>::deserialize_uncompressed(&mut vk_file)
            .map_err(|e| format!("KRITIS: Gagal deserialisasi verifying key. Error: {}", e))?;

        info!("✅ L2 Verifying Key berhasil dimuat.");

        info!(
            "Mencoba memuat L2 Aggregation Verifying Key dari '{}'...",
            agg_vk_path
        );
        let mut agg_vk_file = File::open(agg_vk_path).map_err(|e| {
            format!(
                "KRITIS: Gagal membuka file aggregation verifying key '{}'. Error: {}",
                agg_vk_path, e
            )
        })?;
        let l2_aggregation_verifying_key =
            VerifyingKey::<BW6_761>::deserialize_uncompressed(&mut agg_vk_file).map_err(|e| {
                format!(
                    "KRITIS: Gagal deserialisasi aggregation verifying key. Error: {}",
                    e
                )
            })?;
        info!("✅ L2 Aggregation Verifying Key berhasil dimuat.");

        let dkg_state = {
            let mut participants = std::collections::HashMap::new();
            for validator_addr in &state.validators {
                if let Ok(Some(acc)) = state.get_account(validator_addr) {
                    if let Some(pk_bytes) = acc.bls_public_key {
                        if let Ok(pk) = blst::min_pk::PublicKey::from_bytes(&pk_bytes) {
                            participants.insert(*validator_addr, pk);
                        }
                    }
                }
            }

            DkgState {
                participants,
                threshold: (state.validators.len() * 2 / 3) + 1,
            }
        };

        let last_block_from_db = if let Ok(Some(bytes)) = state.db.get(COL_BLOCKS, &state.db.get(COL_METADATA, b"latest_block_num")?.unwrap_or_else(|| 0u64.to_be_bytes().to_vec())) {
            bincode::decode_from_slice::<Block, _>(&bytes, bincode::config::standard()).map(|(b, _)| Some(b)).unwrap_or(None)
        } else {
            None
        };
        
        let initial_snapshot = ChainInfoSnapshot {
            height: last_block_from_db.as_ref().map_or(0, |b| b.header.index),
            best_block_hash: last_block_from_db.as_ref().map_or(vec![0; 32], |b| b.header.calculate_hash()),
        };

        let last_header_for_speculative = last_block_from_db.as_ref().map(|b| b.header.clone()).unwrap_or_default();
        let speculative_chain = Arc::new(RwLock::new(SpeculativeChain::new(
            last_header_for_speculative,
            l2_verifying_key.clone(),
            l2_aggregation_verifying_key.clone(),
        )));

        let genesis_block = if let Ok(Some(bytes)) = state.db.get(COL_BLOCKS, &0u64.to_be_bytes()) {
            bincode::decode_from_slice::<Block, _>(&bytes, bincode::config::standard()).map(|(b, _)| b).unwrap()
        } else {
            return Err("Blok Genesis tidak ditemukan di database!".into());
        };
        
        if chain.is_empty() {
            chain.push(genesis_block.clone());
        }

        let block_tree = Arc::new(RwLock::new(BlockTree::new(genesis_block, block_processing_tx)));

        Ok(Self {
            chain,
            state,
            l2_verifying_key,
            l2_aggregation_verifying_key,
            dkg_state,
            processed_evidence: HashSet::new(),
            block_hash_cache,
            block_tree,
            speculative_chain,
            info_snapshot: Arc::new(RwLock::new(initial_snapshot)),
        })
    }

    pub async fn write_finalized_blocks_to_db(&mut self, blocks: Vec<Block>) -> Result<Vec<Transaction>, BlockchainError> {
        if blocks.is_empty() {
            return Ok(Vec::new()); 
        }
        
        info!("[DB] Menulis {} blok final ke database...", blocks.len());
        let mut db_ops = Vec::new();
        let mut all_committed_transactions = Vec::new();
        let mut latest_block_in_batch: Option<Block> = None;
        
        for block in blocks {
            // Kumpulkan transaksi dari setiap blok
            all_committed_transactions.extend(block.transactions.clone());

            db_ops.push((
                COL_BLOCKS,
                block.header.index.to_be_bytes().to_vec(),
                Some(bincode::encode_to_vec(&block, bincode::config::standard())?),
            ));
            if self.chain.last().map_or(true, |b| block.header.index == b.header.index + 1) {
                self.chain.push(block.clone());
            }
            latest_block_in_batch = Some(block);
        }
        
        // 1. Commit semua perubahan ke database
        self.state.db.commit(db_ops)?;

        // 2. Perbarui snapshot informasi rantai
        if let Some(last_block) = latest_block_in_batch {
            let mut snapshot = self.info_snapshot.write().await;
            snapshot.height = last_block.header.index;
            snapshot.best_block_hash = last_block.header.calculate_hash();
            info!("[SNAPSHOT] Info rantai diperbarui ke tinggi #{}.", snapshot.height);
        }
        
        // 3. Bersihkan cache akun yang sekarang sudah basi
        self.state.account_cache.lock().unwrap().clear();
        info!("[CACHE] Account cache dibersihkan setelah finalisasi epoch.");
        
        Ok(all_committed_transactions)
    }

    pub fn snapshot(&self) -> ChainSnapshot {
        ChainSnapshot {
            last_header: self.chain.last().map(|b| b.header.clone()),
            current_state_root: self.state.state_root,
            validators: self.state.validators.clone(),
            active_sequencers: self.state.active_sequencers.clone(),
            l2_state_root: self.state.l2_state_root.clone(),
        }
    }

    pub async fn verify_rollup_proof_async(&self, tx: &Transaction) -> Result<(), BlockchainError> {
        if let TransactionData::SubmitRollupBatch {
            old_state_root,
            new_state_root,
            zk_proof,
            is_test_tx,
            ..
        } = &tx.data
        {
            if *is_test_tx {
                return Ok(());
            }

            let vk = self.l2_verifying_key.clone();
            let proof_bytes = zk_proof.clone();
            let old_root_bytes = old_state_root.clone();
            let new_root_bytes = new_state_root.clone();

            let verification_result = task::spawn_blocking(move || {
                let proof = Proof::deserialize_uncompressed(&proof_bytes[..]).map_err(|e| {
                    BlockchainError::TransactionInvalid(format!(
                        "Gagal deserialize bukti ZK: {}",
                        e
                    ))
                })?;

                let old_root_fr = Fr::from_be_bytes_mod_order(&old_root_bytes);
                let new_root_fr = Fr::from_be_bytes_mod_order(&new_root_bytes);
                let public_inputs = &[old_root_fr, new_root_fr];

                match Groth16::<Bls12_377>::verify(&vk, public_inputs, &proof) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(BlockchainError::TransactionInvalid(
                        "Bukti ZK tidak valid!".into(),
                    )),
                    Err(e) => Err(BlockchainError::from(e)),
                }
            })
            .await;

            return match verification_result {
                Ok(res) => res,
                Err(join_error) => {
                    error!(
                        "[ZK Verify] FATAL: Task verifikasi ZK mengalami panic: {}",
                        join_error
                    );
                    Err(BlockchainError::LogicError(
                        "Proses internal verifikasi ZK gagal.".into(),
                    ))
                }
            };
        }
        Ok(())
    }

    pub async fn simulate_transactions_incrementally(
        &mut self,
        snapshot: &ChainSnapshot,
        proposer: Address,
        candidate_txs: &[Transaction],
    ) -> Result<(Vec<Transaction>, Vec<u8>, Vec<Vec<u8>>), BlockchainError> {
        let verification_futures = candidate_txs
            .iter()
            .filter(|tx| matches!(tx.data, TransactionData::SubmitRollupBatch { .. }))
            .map(|tx| self.verify_rollup_proof_async(tx));

        let results = future::join_all(verification_futures).await;

        let mut invalid_proof_hashes = HashSet::new();
        for (i, result) in results.into_iter().enumerate() {
            if result.is_err() {
                let failed_tx = candidate_txs
                    .iter()
                    .filter(|tx| matches!(tx.data, TransactionData::SubmitRollupBatch { .. }))
                    .nth(i)
                    .unwrap();
                invalid_proof_hashes.insert(failed_tx.message_hash());
            }
        }

        let base_fee_per_gas = snapshot
            .last_header
            .as_ref()
            .map_or(INITIAL_BASE_FEE, |h| self.calculate_next_base_fee(h));

        let session_for_precheck = self
            .state
            .create_trie_session(snapshot.current_state_root, COL_TRIE);
        let mut potentially_valid_txs = Vec::new();
        let mut invalid_tx_hashes = Vec::new();

        for tx in candidate_txs {
            if invalid_proof_hashes.contains(&tx.message_hash()) {
                invalid_tx_hashes.push(tx.message_hash());
                continue;
            }

            if let Ok(Some(sender_account)) = session_for_precheck.get_account(&tx.sender()) {
                if tx.nonce != sender_account.nonce {
                    invalid_tx_hashes.push(tx.message_hash());
                    continue;
                }

                let tip = tx
                    .max_priority_fee_per_gas
                    .min(tx.max_fee_per_gas.saturating_sub(base_fee_per_gas));
                let fee_paid = (base_fee_per_gas + tip) * tx.data.base_gas_cost();
                let main_tx_amount = match &tx.data {
                    TransactionData::Transfer { amount, .. }
                    | TransactionData::Stake { amount, .. }
                    | TransactionData::DepositToL2 { amount, .. } => *amount,
                    _ => 0,
                };
                let total_deduction = main_tx_amount + fee_paid;

                if sender_account.balance < total_deduction {
                    invalid_tx_hashes.push(tx.message_hash());
                    continue;
                }

                potentially_valid_txs.push(tx.clone());
            } else {
                invalid_tx_hashes.push(tx.message_hash());
            }
        }

        let (final_root, valid_txs_for_block) = {
            let temp_trie_db = ParityDbTrieBackend::new(self.state.db.clone(), COL_TRIE);

            let dummy_header = BlockHeader {
                index: snapshot.last_header.as_ref().map_or(1, |h| h.index + 1),
                authority: proposer,
                base_fee_per_gas,
                timestamp: 0,
                prev_hash: vec![],
                state_root: vec![],
                transactions_root: vec![],
                l2_transactions_hash: None,
                gas_used: 0,
                signature: [0; SIGNATURE_SIZE],
            };

            let mut dummy_gov_ops = Vec::new();
            let mut dummy_db_ops = Vec::new();

            let mut applied_txs = Vec::new();
            let mut current_root = snapshot.current_state_root;

            for tx in &potentially_valid_txs {
                let mut temp_trie_db_for_tx = temp_trie_db.clone();

                let exec_context = ExecutionContext {
                    validators: &snapshot.validators,
                    sequencers: &snapshot.active_sequencers,
                    l2_root: &snapshot.l2_state_root,
                    validator_last_seen: &self.state.validator_last_seen,
                };

                match self.execute_block_state_transition(
                    &mut temp_trie_db_for_tx,
                    current_root,
                    &dummy_header,
                    &[tx.clone()],
                    &exec_context,
                    &mut dummy_gov_ops,
                    &mut dummy_db_ops,
                ) {
                    Ok((new_root, _result, _valid_txs, _local_overlay)) => {
                        current_root = new_root.try_into().unwrap();
                        applied_txs.push(tx.clone());
                    }
                    Err(_) => {
                        invalid_tx_hashes.push(tx.message_hash());
                    }
                }
            }

            let mut final_trie_db = ParityDbTrieBackend::new(self.state.db.clone(), COL_TRIE);
            let exec_context = ExecutionContext {
                validators: &snapshot.validators,
                sequencers: &snapshot.active_sequencers,
                l2_root: &snapshot.l2_state_root,
                validator_last_seen: &self.state.validator_last_seen,
            };
            let (final_root_vec, _, _, _) = self.execute_block_state_transition(
                &mut final_trie_db,
                snapshot.current_state_root,
                &dummy_header,
                &applied_txs,
                &exec_context,
                &mut dummy_gov_ops,
                &mut dummy_db_ops,
            )?;

            (final_root_vec, applied_txs)
        };

        Ok((valid_txs_for_block, final_root, invalid_tx_hashes))
    }

    fn process_inactivity_slashing(
        &self,
        current_block_height: u64,
        trie: &mut TrieDBMut<EviceTrieLayout>, 
        temporary_accounts: &mut BTreeMap<Address, Account>,
        current_validators: &Vec<Address>,
        validator_last_seen: &HashMap<Address, u64>,
    ) -> Result<Vec<Address>, BlockchainError> {
        let mut validators_to_jail = Vec::new();
      
        for validator_addr in current_validators {
            let last_seen = validator_last_seen.get(validator_addr).unwrap_or(&0);
            if current_block_height > *last_seen && current_block_height.saturating_sub(*last_seen) > INACTIVITY_THRESHOLD_BLOCKS {
                validators_to_jail.push(*validator_addr);
            }
        }

        if !validators_to_jail.is_empty() {
            info!(
                "INACTIVITY: Terdeteksi {} validator tidak aktif yang akan di-slash.",
                validators_to_jail.len()
            );
            validators_to_jail.sort();
            
            for offender_addr in &validators_to_jail {
                let mut offender_account = if let Some(account) = temporary_accounts.get(offender_addr).cloned() {
                    account
                } else {
                    trie.get(&KeccakHasher::hash(offender_addr.as_ref()))?
                        .and_then(|d| bincode::decode_from_slice(&d, bincode::config::standard()).ok().map(|(acc, _): (Account, _)| acc))
                        .ok_or_else(|| BlockchainError::TransactionInvalid(format!("Akun pelaku tidak ditemukan: {}", offender_addr)))?
                };

                let slash_amount = (offender_account.staked_amount * INACTIVITY_SLASH_PERCENT) / 100;
                if slash_amount > 0 {
                    offender_account.staked_amount = offender_account.staked_amount.saturating_sub(slash_amount);

                    // let mut treasury_account = if let Some(account) = temporary_accounts.get(&TREASURY_ADDRESS).cloned() {
                    //     account
                    // } else {
                    //     trie.get(&KeccakHasher::hash(TREASURY_ADDRESS.as_ref()))?
                    //         .and_then(|d| bincode::decode_from_slice(&d, bincode::config::standard()).ok().map(|(acc, _): (Account, _)| acc))
                    //         .unwrap_or_default() 
                    // };
                    
                    // treasury_account.balance = treasury_account.balance.saturating_add(slash_amount);

                    temporary_accounts.insert(*offender_addr, offender_account);
                    // temporary_accounts.insert(TREASURY_ADDRESS, treasury_account);

                    info!(
                        "SLASH & BURN (Inactivity): Membakar {} stake dari validator {}",
                        slash_amount, offender_addr
                    );
                }
            }
        }

        Ok(validators_to_jail)
    }

    pub fn get_block_by_hash(&self, hash: &[u8]) -> Option<Block> {
        if let Some(block) = self.block_hash_cache.get(hash) {
            return Some(block.clone());
        }

        if let Ok(Some(block_index_bytes)) = self.state.db.get(COL_TX_LOOKUP, hash) {
            if let Ok(block_height) =
                TryInto::<[u8; 8]>::try_into(block_index_bytes).map(u64::from_be_bytes)
            {
                if let Ok(Some(block_bytes)) =
                    self.state.db.get(COL_BLOCKS, &block_height.to_be_bytes())
                {
                    if let Ok((block, _)) = bincode::decode_from_slice::<Block, _>(
                        &block_bytes,
                        bincode::config::standard(),
                    ) {
                        return Some(block);
                    }
                }
            }
        }

        None
    }

    pub fn get_block_by_index(&self, index: u64) -> Result<Option<Block>, StateError> {
        if let Some(block_bytes) = self.state.db.get(COL_BLOCKS, &index.to_be_bytes())? {
            let block: Block =
                bincode::decode_from_slice(&block_bytes, bincode::config::standard())
                    .map(|(b, _)| b)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    pub fn verify_header_chain(
        &self,
        headers: &[BlockHeader],
        last_known_header: &BlockHeader,
    ) -> bool {
        if headers.is_empty() {
            return true;
        }

        let mut current_parent_hash = last_known_header.calculate_hash();
        let mut current_parent_index = last_known_header.index;

        for header in headers {
            if header.index != current_parent_index + 1 {
                warn!("[SYNC_VALIDATION] Rantai header tidak valid: indeks tidak berurutan.");
                return false;
            }
            if header.prev_hash != current_parent_hash {
                warn!("[SYNC_VALIDATION] Rantai header tidak valid: hash tidak cocok.");
                return false;
            }
            // Di sini kita bisa menambahkan verifikasi tanda tangan header jika diperlukan
            // untuk keamanan ekstra selama sinkronisasi.

            current_parent_hash = header.calculate_hash();
            current_parent_index = header.index;
        }
        true
    }

    fn validate_double_sign_evidence(
        &self,
        evidence: &DoubleSignEvidence,
    ) -> Result<Vec<u8>, BlockchainError> {
        let h1 = &evidence.header1;
        let h2 = &evidence.header2;

        if h1.authority != h2.authority {
            return Err(BlockchainError::InvalidDoubleSignEvidence(
                "Otoritas header tidak cocok.".into(),
            ));
        }
        if h1.index != h2.index {
            return Err(BlockchainError::InvalidDoubleSignEvidence(
                "Index blok tidak sama.".into(),
            ));
        }
        if h1.calculate_hash() == h2.calculate_hash() {
            return Err(BlockchainError::InvalidDoubleSignEvidence(
                "Header identik, bukan double signing.".into(),
            ));
        }
        if !self.state.validators.contains(&h1.authority) {
            return Err(BlockchainError::InvalidDoubleSignEvidence(
                "Pelaku bukan validator yang terdaftar.".into(),
            ));
        }
        let offender_account = self.state.get_account(&h1.authority)?.ok_or_else(|| {
            BlockchainError::InvalidDoubleSignEvidence("Akun pelaku tidak ditemukan.".into())
        })?;

        if !crypto::verify(
            &offender_account.signing_public_key,
            &h1.canonical_bytes_for_signing(),
            &h1.signature,
        ) {
            return Err(BlockchainError::InvalidDoubleSignEvidence(
                "Tanda tangan pada header 1 tidak valid.".into(),
            ));
        }
        if !crypto::verify(
            &offender_account.signing_public_key,
            &h2.canonical_bytes_for_signing(),
            &h2.signature,
        ) {
            return Err(BlockchainError::InvalidDoubleSignEvidence(
                "Tanda tangan pada header 2 tidak valid.".into(),
            ));
        }

        let mut evidence_hasher = Sha256::new();
        evidence_hasher.update(h1.calculate_hash());
        evidence_hasher.update(h2.calculate_hash());
        let evidence_hash = evidence_hasher.finalize().to_vec();

        if self.processed_evidence.contains(&evidence_hash) {
            return Err(BlockchainError::InvalidDoubleSignEvidence(
                "Bukti ini sudah pernah diproses.".into(),
            ));
        }

        Ok(evidence_hash)
    }

    pub async fn process_block_proposal(&mut self, block: &Block) -> Result<(), BlockchainError> {
        let last_header = self.chain.last().map(|b| &b.header);
        let expected_index = last_header.map_or(0, |h| h.index + 1);

        if block.header.index == 0 {
            return Ok(());
        }

        if block.header.index != expected_index {
            return Err(BlockchainError::InvalidIndex {
                expected: expected_index,
                got: block.header.index,
            });
        }

        let expected_prev_hash = last_header.map_or(vec![0; 32], |h| h.calculate_hash());
        if block.header.prev_hash != expected_prev_hash {
            return Err(BlockchainError::PreviousHashMismatch);
        }

        if !self.state.validators.contains(&block.header.authority) {
            return Err(BlockchainError::NotAValidator);
        }

        let proposer_account = self
            .state
            .get_account(&block.header.authority)?
            .ok_or(BlockchainError::NotAValidator)?;

        if !self.verify_velocity_qc(&block.justify) {
            return Err(BlockchainError::InvalidSignature);
        }

        let expected_prev_hash = last_header.map_or(vec![0; 32], |h| h.calculate_hash());
        if block.header.prev_hash != expected_prev_hash {
            return Err(BlockchainError::PreviousHashMismatch);
        }

        if !crypto::verify(
            &proposer_account.signing_public_key,
            &block.header.canonical_bytes_for_signing(),
            &block.header.signature,
        ) {
            return Err(BlockchainError::InvalidSignature);
        }

        let calculated_state_root =
            self.calculate_next_state_root(&block.transactions, block.header.authority)?;

        if calculated_state_root != block.header.state_root {
            return Err(BlockchainError::StateRootMismatch {
                expected: hex::encode(&block.header.state_root),
                got: hex::encode(&calculated_state_root),
            });
        }

        Ok(())
    }

    pub fn calculate_next_state_root(
        &mut self,
        transactions: &[Transaction],
        proposer: Address,
    ) -> Result<Vec<u8>, BlockchainError> {
        let mut temp_trie_db = ParityDbTrieBackend::new(self.state.db.clone(), COL_TRIE);
        let temp_state_root = self.state.state_root;

        let last_header = self.chain.last().map(|b| &b.header);
        let base_fee_per_gas =
            last_header.map_or(INITIAL_BASE_FEE, |h| self.calculate_next_base_fee(h));

        let dummy_header = BlockHeader {
            index: last_header.map_or(1, |h| h.index + 1),
            authority: proposer,
            base_fee_per_gas,
            timestamp: 0,
            prev_hash: vec![],
            state_root: vec![],
            transactions_root: vec![],
            l2_transactions_hash: None,
            gas_used: 0,
            signature: [0; SIGNATURE_SIZE],
        };

        let mut dummy_gov_ops = Vec::new();
        let mut dummy_db_ops = Vec::new();

        let exec_context = ExecutionContext {
            validators: &self.state.validators,
            sequencers: &self.state.active_sequencers,
            l2_root: &self.state.l2_state_root,
            validator_last_seen: &self.state.validator_last_seen,
        };
        let (final_root_vec, _, _, _) = self.execute_block_state_transition(
            &mut temp_trie_db,
            temp_state_root,
            &dummy_header,
            transactions,
            &exec_context,
            &mut dummy_gov_ops,
            &mut dummy_db_ops,
        )?;

        Ok(final_root_vec)
    }

    pub fn calculate_next_base_fee(&self, parent: &BlockHeader) -> u64 {
        const TARGET_GAS_USED: u64 = 15_000_000;
        const MAX_CHANGE_DENOMINATOR: u64 = 8;

        let parent_gas_used = parent.gas_used;
        let parent_base_fee = parent.base_fee_per_gas;

        if parent_gas_used == TARGET_GAS_USED {
            return parent_base_fee;
        }

        if parent_gas_used > TARGET_GAS_USED {
            let gas_diff = parent_gas_used - TARGET_GAS_USED;
            let delta = (parent_base_fee * gas_diff / TARGET_GAS_USED) / MAX_CHANGE_DENOMINATOR;
            parent_base_fee + delta.max(1)
        } else {
            let gas_diff = TARGET_GAS_USED - parent_gas_used;
            let delta = (parent_base_fee * gas_diff / TARGET_GAS_USED) / MAX_CHANGE_DENOMINATOR;
            parent_base_fee.saturating_sub(delta)
        }
    }

    fn calculate_dynamic_block_reward(
        &self,
        trie: &TrieDBMut<EviceTrieLayout>,
        temporary_accounts: &BTreeMap<Address, Account>,
        final_validators: &HashSet<Address>,
        base_reward_factor: u64,
        blocks_per_epoch: u64,
    ) -> Result<u64, BlockchainError> {
        if final_validators.is_empty() {
            return Ok(0);
        }
    
        let total_staked_amount: u64 = final_validators
            .iter()
            .map(|addr| {
                if let Some(account) = temporary_accounts.get(addr) {
                    Ok(account.staked_amount)
                } else {
                    trie.get(&KeccakHasher::hash(addr.as_ref()))
                        .map_err(BlockchainError::from)
                        .and_then(|opt_data| {
                            opt_data
                                .and_then(|d| bincode::decode_from_slice(&d, bincode::config::standard()).ok().map(|(acc, _): (Account, _)| acc))
                                .map(|acc| acc.staked_amount)
                                .ok_or_else(|| BlockchainError::TransactionInvalid(format!("Akun validator tidak ditemukan: {}", addr)))
                        })
                }
            })
            .collect::<Result<Vec<u64>, _>>()?
            .iter()
            .sum();
        
        if total_staked_amount == 0 {
            return Ok(0);
        }

        let total_staked_as_u128 = total_staked_amount as u128;
        let sqrt_total_staked = total_staked_as_u128.isqrt();

        let base_reward = (base_reward_factor as u128 * sqrt_total_staked) as u64;
        
        if blocks_per_epoch == 0 { return Ok(base_reward); }
        Ok(base_reward / blocks_per_epoch)
    }

    pub fn create_block(
        &self,
        authority_keypair: &KeyPair,
        transactions: Vec<Transaction>,
        state_root: Vec<u8>,
        vrf_output: Vec<u8>,
        vrf_proof: Vec<u8>,
        timestamp: u128,
        round: u64,
        view_number: u64,
        parent_qc: QuorumCertificate,
        parent_header: Option<&BlockHeader>,
    ) -> Block {
        let new_index = parent_header.map_or(1, |h| h.index + 1);
        let prev_hash = parent_header.map_or(
            self.chain
                .get(0)
                .map(|b| b.header.calculate_hash())
                .unwrap_or_default(),
            |h| h.calculate_hash(),
        );
        let base_fee_per_gas =
            parent_header.map_or(INITIAL_BASE_FEE, |h| self.calculate_next_base_fee(h));

        let l2_transactions_hash = {
            let mut l2_data = Vec::new();
            for tx in &transactions {
                if let TransactionData::SubmitRollupBatch {
                    compressed_batch, ..
                } = &tx.data
                {
                    l2_data.extend_from_slice(compressed_batch);
                }
            }

            if l2_data.is_empty() {
                None
            } else {
                let mut hasher = Sha256::new();
                hasher.update(&l2_data);
                Some(hasher.finalize().to_vec())
            }
        };

        let transactions_root = Block::calculate_transactions_root(&transactions);
        let gas_used = transactions.iter().map(|tx| tx.data.base_gas_cost()).sum();

        let mut header = BlockHeader {
            index: new_index,
            timestamp,
            prev_hash,
            state_root,
            transactions_root,
            l2_transactions_hash,
            authority: public_key_to_address(&authority_keypair.public_key_bytes()),
            gas_used,
            base_fee_per_gas,
            signature: [0; SIGNATURE_SIZE],
        };

        let data_to_sign = header.canonical_bytes_for_signing();
        header.signature = authority_keypair.sign(&data_to_sign);

        Block {
            header,
            transactions,
            round,
            view_number,
            justify: parent_qc,
            vrf_output,
            vrf_proof,
        }
    }

    fn process_governance_proposals(
        &self,
        current_block_height: u64,
        _trie: &mut TrieDBMut<EviceTrieLayout>,
        governance_ops: &mut Vec<(u8, Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<(), BlockchainError> {
        let mut proposals = self.state.get_all_proposals()?;
        proposals.sort_by_key(|p| p.id);

        for mut proposal_state in proposals {
            if !proposal_state.executed && current_block_height > proposal_state.end_block {
                info!(
                    "GOVERNANCE: Memproses proposal #{} yang telah selesai.",
                    proposal_state.id
                );
                proposal_state.executed = true;

                if proposal_state.yes_votes > proposal_state.no_votes {
                    info!(
                        "GOVERNANCE: Proposal #{} disetujui. Mengeksekusi tindakan...",
                        proposal_state.id
                    );

                    match &proposal_state.proposal.action {
                        _ => {}
                    }
                } else {
                    info!("GOVERNANCE: Proposal #{} ditolak.", proposal_state.id);
                }

                governance_ops.push((
                    COL_GOVERNANCE,
                    proposal_state.id.to_be_bytes().to_vec(),
                    Some(bincode::encode_to_vec(
                        &proposal_state,
                        bincode::config::standard(),
                    )?),
                ));
            }
        }
        Ok(())
    }

    fn slash_validator(
        &self,
        trie: &impl Trie<EviceTrieLayout>,
        temporary_accounts: &mut BTreeMap<Address, Account>,
        offender_addr: &Address,
        slash_percent: u64,
    ) -> Result<u64, BlockchainError> {
        let mut offender_account = get_account_helper(temporary_accounts, offender_addr, trie)?; 

        let slash_amount = (offender_account.staked_amount * slash_percent) / 100;

        if slash_amount > 0 {
            offender_account.staked_amount =
                offender_account.staked_amount.saturating_sub(slash_amount);

            // let mut treasury_account = get_account_helper(temporary_accounts, &TREASURY_ADDRESS, trie).unwrap_or_default();
            // treasury_account.balance = treasury_account.balance.saturating_add(slash_amount);

            temporary_accounts.insert(*offender_addr, offender_account);
            // temporary_accounts.insert(TREASURY_ADDRESS, treasury_account);
            
            info!(
                "SLASH & BURN: Membakar {} stake dari validator {}",
                slash_amount, offender_addr
            );
        }

        Ok(slash_amount)
    }

    pub async fn finalize_and_commit_block(
        &mut self,
        block: Block,
    ) -> Result<Vec<Transaction>, BlockchainError> {
        if block.header.index == 0 {
            info!("GENESIS SYNC: Menerima dan menyimpan Blok #0 dari jaringan.");

            let block_op = (
                COL_BLOCKS,
                0u64.to_be_bytes().to_vec(),
                Some(bincode::encode_to_vec(&block, bincode::config::standard()).unwrap()),
            );

            let state_root_op = (
                COL_METADATA,
                STATE_ROOT_KEY.to_vec(),
                Some(block.header.state_root.clone()),
            );

            self.state.db.commit(vec![block_op, state_root_op])?;

            self.state.state_root = block.header.state_root.as_slice().try_into().unwrap();

            if let Ok(Some(encoded_validators)) = self.state.db.get(COL_METADATA, VALIDATORS_KEY) {
                if let Ok((validators, _)) =
                    bincode::decode_from_slice(&encoded_validators, bincode::config::standard())
                {
                    info!("GENESIS SYNC: Memuat ulang set validator dari state yang disinkronkan.");
                    self.state.validators = validators;
                }
            }

            self.chain.push(block);
            return Ok(Vec::new());
        }

        let mut trie_db = ParityDbTrieBackend::new(self.state.db.clone(), COL_TRIE);

        let mut governance_ops = Vec::new();
        let mut db_ops = Vec::new();
        
        let exec_context = ExecutionContext {
            validators: &self.state.validators,
            sequencers: &self.state.active_sequencers,
            l2_root: &self.state.l2_state_root,
            validator_last_seen: &self.state.validator_last_seen,
        };
        let (final_root_hash, canonical_result, _, _) = self.execute_block_state_transition(
            &mut trie_db,
            self.state.state_root,
            &block.header,
            &block.transactions,
            &exec_context,
            &mut governance_ops,
            &mut db_ops,
        )?;

        for tx in &block.transactions {
            if let TransactionData::ReportDoubleSigning { evidence } = &tx.data {
                let h1 = &evidence.header1;
                let h2 = &evidence.header2;
                let mut evidence_hasher = Sha256::new();
                evidence_hasher.update(h1.calculate_hash());
                evidence_hasher.update(h2.calculate_hash());
                let evidence_hash = evidence_hasher.finalize().to_vec();
                self.processed_evidence.insert(evidence_hash);
            }
        }

        let new_root: H256 = final_root_hash.try_into().map_err(|_| {
            BlockchainError::LogicError("Invalid root length from canonical execution".into())
        })?;

        if new_root.as_ref() != block.header.state_root {
            return Err(BlockchainError::StateRootMismatch {
                expected: hex::encode(&block.header.state_root),
                got: hex::encode(new_root.as_ref()),
            });
        }

        trie_db.commit_pending()?;

        self.state.state_root = new_root;
        self.state.l2_state_root = canonical_result.new_l2_state_root;
        self.state.validators = canonical_result.final_validators;

        if self.state.l2_state_root_history.front() != Some(&self.state.l2_state_root) {
            self.state
                .l2_state_root_history
                .push_front(self.state.l2_state_root.clone());
            if self.state.l2_state_root_history.len() > 256 {
                self.state.l2_state_root_history.pop_back();
            }
        }

        for jailed_validator in canonical_result.validators_to_jail {
            self.state.validators.remove(&jailed_validator);
            self.state.jailed_validators.insert(jailed_validator);
        }
        self.state.active_sequencers = canonical_result.final_sequencers;
        self.state
            .validator_last_seen
            .insert(block.header.authority, block.header.index);

        let mut final_ops = governance_ops;
        final_ops.extend(db_ops);

        final_ops.push((
            COL_METADATA,
            ACTIVE_SEQUENCERS_KEY.to_vec(),
            Some(bincode::encode_to_vec(
                &self.state.active_sequencers,
                bincode::config::standard(),
            )?),
        ));

        final_ops.push((
            COL_METADATA,
            STATE_ROOT_KEY.to_vec(),
            Some(new_root.as_ref().to_vec()),
        ));
        final_ops.push((
            COL_BLOCKS,
            block.header.index.to_be_bytes().to_vec(),
            Some(bincode::encode_to_vec(&block, bincode::config::standard()).unwrap()),
        ));
        final_ops.push((
            COL_METADATA,
            L2_STATE_ROOT_KEY.to_vec(),
            Some(self.state.l2_state_root.clone()),
        ));
        final_ops.push((
            COL_METADATA,
            b"l2_state_root_history".to_vec(),
            Some(bincode::encode_to_vec(
                &self.state.l2_state_root_history,
                bincode::config::standard(),
            )?),
        ));
        final_ops.push((
            COL_METADATA,
            VALIDATORS_KEY.to_vec(),
            Some(bincode::encode_to_vec(
                &self.state.validators,
                bincode::config::standard(),
            )?),
        ));
        final_ops.push((
            COL_STATE_JOURNAL,
            block.header.index.to_be_bytes().to_vec(),
            Some(new_root.as_ref().to_vec()),
        ));
        final_ops.push((
            COL_METADATA,
            b"latest_block_num".to_vec(),
            Some(block.header.index.to_be_bytes().to_vec()),
        ));

        self.state.db.commit(final_ops)?;
        self.state.account_cache.lock().unwrap().clear();
        info!(
            "[CACHE] Account cache dibersihkan setelah finalisasi blok #{}.",
            block.header.index
        );

        let transactions = block.transactions.clone();
        let block_hash = block.header.calculate_hash();
        self.block_hash_cache
            .insert(block_hash.clone(), block.clone());
        self.chain.push(block);

        Ok(transactions)
    }

    pub async fn apply_transactions_to_session(
        &self,
        mut session: TrieSession,
        block_header: &BlockHeader,
        transactions: &[Transaction],
        validators: &HashSet<Address>,
        sequencers: &HashSet<Address>,
        l2_root: &Vec<u8>,
    ) -> Result<(TrieSession, Vec<Transaction>, BTreeMap<Address, Account>), BlockchainError> {
        let initial_root = *session.root();
        let validator_last_seen = &self.state.validator_last_seen;

        let exec_context = ExecutionContext {
            validators,
            sequencers,
            l2_root,
            validator_last_seen,
        };

        let mut dummy_gov_ops = Vec::new();
        let mut dummy_db_ops = Vec::new();

        let (final_root_vec, _canonical_result, final_valid_txs, changed_accounts_map) = 
            self.execute_block_state_transition(
                session.backend_mut(),
                initial_root,
                block_header,
                transactions,
                &exec_context,
                &mut dummy_gov_ops,
                &mut dummy_db_ops,
            )?;

        session.set_root(final_root_vec.try_into().map_err(|_| {
            BlockchainError::LogicError("Invalid root length from state transition".into())
        })?);
        
        Ok((session, final_valid_txs, changed_accounts_map))
    }

    fn execute_block_state_transition<H>(
        &self,
        trie_db: &mut H,
        initial_root: H256,
        block_header: &BlockHeader,
        transactions: &[Transaction],
        exec_context: &ExecutionContext,
        governance_ops: &mut Vec<(u8, Vec<u8>, Option<Vec<u8>>)>,
        db_ops: &mut Vec<(u8, Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<(Vec<u8>, CanonicalResult, Vec<Transaction>, BTreeMap<Address, Account>), BlockchainError>
    where
        H: HashDB<KeccakHasher, DBValue> + AsHashDB<KeccakHasher, DBValue> + HashDBRef<KeccakHasher, DBValue> + Send + Sync,
    {
        let mut current_root = initial_root;
        let mut current_l2_root = exec_context.l2_root.clone();
        let mut final_state_overlay: BTreeMap<Address, Account> = BTreeMap::new();

        let mut result = CanonicalResult {
            validators_to_jail: Vec::new(),
            final_validators: exec_context.validators.clone(),
            final_sequencers: exec_context.sequencers.clone(),
            new_l2_state_root: exec_context.l2_root.clone(),
        };

        current_root = {
            let mut trie_for_slashing = TrieDBMutBuilder::<EviceTrieLayout>::from_existing(
                trie_db.as_hash_db_mut(),
                &mut current_root,
            )
            .build();
            let mut temporary_accounts = BTreeMap::new();
            let mut sorted_validators: Vec<Address> = result.final_validators.iter().cloned().collect();
            sorted_validators.sort();

            result.validators_to_jail = self.process_inactivity_slashing(
                block_header.index,
                &mut trie_for_slashing,
                &mut temporary_accounts,
                &sorted_validators,
                exec_context.validator_last_seen,
            )?;

            for (address, account) in temporary_accounts {
                final_state_overlay.insert(address, account);
                let encoded_account = bincode::encode_to_vec(&final_state_overlay[&address], bincode::config::standard())?;
                trie_for_slashing.insert(&KeccakHasher::hash(address.as_ref()), &encoded_account)?;
            }
            *trie_for_slashing.root()
        };

        let mut parallelizable_txs: Vec<(usize, Transaction)> = Vec::new();
        let mut sequential_txs: Vec<(usize, Transaction)> = Vec::new();

        for (index, tx) in transactions.iter().cloned().enumerate() {
            match tx.data {
                TransactionData::CallContract { .. } | TransactionData::SubmitAggregateRollupBatch { .. } => {
                    sequential_txs.push((index, tx));
                }
                _ => {
                    parallelizable_txs.push((index, tx));
                }
            }
        }

        let mut final_valid_txs_map: BTreeMap<usize, Transaction> = BTreeMap::new();

        if !parallelizable_txs.is_empty() {
            let mut txs_to_process: Vec<(usize, Transaction)> = parallelizable_txs;
            let mut permanently_failed_tx_hashes: HashSet<Vec<u8>> = HashSet::new();

            're_execution_loop: loop {
                if txs_to_process.is_empty() {
                    break;
                }

                let l2_root_for_iteration = current_l2_root.clone();

                let execution_results: Vec<(
                    usize,
                    Result<(Transaction, BTreeMap<Address, Account>, Vec<u8>, Vec<(u8, Vec<u8>, Option<Vec<u8>>)>, Vec<(u8, Vec<u8>, Option<Vec<u8>>)>, bool, bool, bool), BlockchainError>,
                )> = txs_to_process
                    .par_iter()
                    .map(|(original_index, tx)| {
                        let mut became_validator = false;
                        let mut became_sequencer = false;
                        let mut was_deregistered = false;

                        let mut execution_logic = || -> Result<_, BlockchainError> {
                            let sender_address = tx.sender();
                            let mut local_temp_accounts = BTreeMap::new();
                            let mut local_intra_block_l2_root = l2_root_for_iteration.clone();
                            let mut local_db_ops = Vec::new();
                            let mut local_gov_ops = Vec::new();

                            let trie_ro = TrieDBBuilder::<crate::EviceTrieLayout>::new(trie_db, &current_root).build();
                            let mut sender_account = get_account_helper(&final_state_overlay, &sender_address, &trie_ro)?;
                            
                            if tx.nonce != sender_account.nonce { return Err(BlockchainError::StaleNonce { expected: sender_account.nonce, got: tx.nonce }); }
                            let tip = tx.max_priority_fee_per_gas.min(tx.max_fee_per_gas.saturating_sub(block_header.base_fee_per_gas));
                            let fee_paid = (block_header.base_fee_per_gas + tip) * tx.data.base_gas_cost();
                            
                            let main_tx_amount = match &tx.data {
                                TransactionData::Transfer { amount, .. } | TransactionData::Stake { amount, .. } | TransactionData::DepositToL2 { amount, .. } => *amount,
                                _ => 0,
                            };
                            let total_deduction = main_tx_amount + fee_paid;
                            if sender_account.balance < total_deduction { return Err(BlockchainError::InsufficientBalance { has: sender_account.balance, needs: total_deduction }); }
                            
                            sender_account.balance -= total_deduction;
                            sender_account.nonce += 1;
                
                            match &tx.data {
                                TransactionData::Transfer { recipient, amount } => {
                                    let mut recipient_account = get_account_helper(&final_state_overlay, recipient, &trie_ro).unwrap_or_default();
                                    recipient_account.balance = recipient_account.balance.saturating_add(*amount);
                                    local_temp_accounts.insert(*recipient, recipient_account);
                                }
                                TransactionData::Stake { amount } => {
                                    sender_account.staked_amount = sender_account.staked_amount.saturating_add(*amount);
                                    if sender_account.staked_amount >= MINIMUM_STAKE {
                                        became_validator = true;
                                    }
                                }
                                TransactionData::ReportDoubleSigning { evidence } => {
                                    let _evidence_hash = self.validate_double_sign_evidence(evidence)?;
                                    let offender_addr = evidence.header1.authority;
                                    let trie_ro = TrieDBBuilder::<crate::EviceTrieLayout>::new(trie_db, &current_root).build();

                                    let _slash_amount = self.slash_validator(&trie_ro, &mut local_temp_accounts, &offender_addr, 10)?;
                                    // sender_account.balance = sender_account.balance.saturating_add(slash_amount / 2);
                                }
                                TransactionData::ReportInvalidState { offending_header, computed_state_root } => {
                                    let offender_addr = offending_header.authority;
                                    let offender_account = get_account_helper(&local_temp_accounts, &offender_addr, &trie_ro)?;
                                    if !crypto::verify(&offender_account.signing_public_key, &offending_header.canonical_bytes_for_signing(), &offending_header.signature) {
                                        return Err(BlockchainError::TransactionInvalid("Bukti InvalidState tidak valid: tanda tangan pada header yang dituduhkan salah.".into()));
                                    }
                                    if &offending_header.state_root == computed_state_root {
                                        return Err(BlockchainError::TransactionInvalid("Bukti InvalidState tidak valid: state root yang dilaporkan sama dengan yang di-klaim.".into()));
                                    }
                                    let trie_ro = TrieDBBuilder::<crate::EviceTrieLayout>::new(trie_db, &current_root).build();

                                    let _slash_amount = self.slash_validator(&trie_ro, &mut local_temp_accounts, &offender_addr, 50)?;
                                    // sender_account.balance = sender_account.balance.saturating_add(slash_amount / 2);
                                }
                                TransactionData::CastVote { proposal_id, vote } => {
                                    let mut p_state: ProposalState = self.state.db.get(COL_GOVERNANCE, &proposal_id.to_be_bytes())?.and_then(|bytes| bincode::decode_from_slice(&bytes, bincode::config::standard()).ok().map(|(p, _)| p)).ok_or(BlockchainError::TransactionInvalid("Proposal tidak ditemukan".into()))?;
                                    let vote_weight = sender_account.staked_amount;
                                    if *vote { p_state.yes_votes += vote_weight; } else { p_state.no_votes += vote_weight; }
                                    p_state.voters.insert(tx.sender());
                                    local_gov_ops.push((COL_GOVERNANCE, p_state.id.to_be_bytes().to_vec(), Some(bincode::encode_to_vec(&p_state, bincode::config::standard())?)));
                                }
                                TransactionData::SubmitProposal { proposal } => {
                                    let next_id_bytes = self.state.db.get(COL_METADATA, NEXT_PROPOSAL_ID_KEY)?.unwrap_or_else(|| 0u64.to_be_bytes().to_vec());
                                    let mut next_proposal_id = u64::from_be_bytes(next_id_bytes.try_into().unwrap());
                                    let proposal_state = ProposalState { id: next_proposal_id, proposal: proposal.clone(), proposer: tx.sender(), start_block: block_header.index, end_block: block_header.index + PROPOSAL_VOTING_PERIOD, yes_votes: 0, no_votes: 0, executed: false, voters: HashSet::new() };
                                    local_gov_ops.push((COL_GOVERNANCE, proposal_state.id.to_be_bytes().to_vec(), Some(bincode::encode_to_vec(&proposal_state, bincode::config::standard())?)));
                                    next_proposal_id += 1;
                                    local_gov_ops.push((COL_METADATA, NEXT_PROPOSAL_ID_KEY.to_vec(), Some(next_proposal_id.to_be_bytes().to_vec())));
                                }
                                TransactionData::DepositToL2 { amount } => {
                                    let mut bridge_account = get_account_helper(&local_temp_accounts, &L2_BRIDGE_ADDRESS, &trie_ro).unwrap_or_default();
                                    bridge_account.balance += *amount;
                                    local_temp_accounts.insert(L2_BRIDGE_ADDRESS, bridge_account);
                                }
                                TransactionData::RegisterAsSequencer => {
                                    if !exec_context.validators.contains(&tx.sender()) { return Err(BlockchainError::TransactionInvalid("Hanya validator aktif yang bisa mendaftar sebagai sequencer.".into())); }
                                    became_sequencer = true;
                                }
                                TransactionData::DeregisterAsSequencer => {
                                    if result.final_sequencers.contains(&tx.sender()) {
                                        was_deregistered = true;
                                    } else {
                                        return Err(BlockchainError::TransactionInvalid("Pengirim bukan sequencer aktif.".into()));
                                    }
                                }
                                TransactionData::SubmitRollupBatch {
                                    old_state_root,
                                    new_state_root,
                                    compressed_batch,
                                    vrf_output,
                                    vrf_proof,
                                    dac_signatures,
                                    ..
                                } => {
                                    if !result.final_sequencers.contains(&tx.sender()) {
                                        return Err(BlockchainError::TransactionInvalid(
                                            "Pengirim batch bukan sequencer yang terdaftar.".into(),
                                        ));
                                    }

                                    let vrf_pubkey = VrfPublicKey::from_bytes(&sender_account.vrf_public_key)
                                        .map_err(|_| BlockchainError::VrfVerificationFailed)?;
                                    let mut transcript =
                                        Transcript::new(b"EVICE_L2_SEQUENCER_ELECTION_STAKE_WEIGHTED");

                                    transcript.append_message(b"selection_material", &block_header.prev_hash);
                                    transcript.append_message(b"candidate_addr", tx.sender().as_ref());

                                    let vrf_preout = VRFPreOut::from_bytes(vrf_output)
                                        .map_err(|_| BlockchainError::VrfVerificationFailed)?;
                                    let proof = VRFProof::from_bytes(vrf_proof)
                                        .map_err(|_| BlockchainError::VrfVerificationFailed)?;

                                    if vrf_pubkey
                                        .vrf_verify(transcript, &vrf_preout, &proof)
                                        .is_err()
                                    {
                                        return Err(BlockchainError::VrfVerificationFailed);
                                    }

                                    let required_dac_signatures = (DATA_AVAILABILITY_COMMITTEE.len() / 2) + 1;
                                    let batch_data_hash = Sha256::digest(compressed_batch);
                                    let mut valid_dac_approvers = HashSet::new();
                                    let dac_addresses: HashSet<Address> = DATA_AVAILABILITY_COMMITTEE
                                        .iter()
                                        .map(|s| {
                                            Address(
                                                hex::decode(s.trim_start_matches("0x"))
                                                    .unwrap()
                                                    .try_into()
                                                    .unwrap(),
                                            )
                                        })
                                        .collect();

                                    for signature in dac_signatures {
                                        for dac_address in &dac_addresses {
                                            if valid_dac_approvers.contains(dac_address) {
                                                continue;
                                            }
                                            if let Ok(dac_account) = get_account_helper(&local_temp_accounts, dac_address, &trie_ro) {
                                                if crypto::verify(
                                                    &dac_account.signing_public_key,
                                                    &batch_data_hash,
                                                    signature,
                                                ) {
                                                    valid_dac_approvers.insert(*dac_address);
                                                    break;
                                                }
                                            }
                                        }
                                    }

                                    if valid_dac_approvers.len() < required_dac_signatures {
                                        return Err(BlockchainError::TransactionInvalid(format!(
                                            "Persetujuan DAC unik tidak cukup ({} dari {} dibutuhkan).",
                                            valid_dac_approvers.len(),
                                            required_dac_signatures
                                        )));
                                    }

                                    if old_state_root != &local_intra_block_l2_root {
                                        return Err(BlockchainError::TransactionInvalid(
                                            "Batch L2 dibangun di atas state root intra-blok yang usang.".into(),
                                        ));
                                    }

                                    local_intra_block_l2_root = new_state_root.clone();

                                    local_db_ops.push((
                                        COL_L2_BATCHES,
                                        block_header.index.to_be_bytes().to_vec(),
                                        Some(compressed_batch.clone()),
                                    ));
                                    local_db_ops.push((
                                        COL_METADATA,
                                        crate::state::L2_LAST_BATCH_L1_BLOCK_KEY.to_vec(),
                                        Some(block_header.index.to_be_bytes().to_vec()),
                                    ));
                                }
                                TransactionData::UpdateVrfKey { new_vrf_public_key } => {
                                    if !result.final_validators.contains(&tx.sender()) {
                                        return Err(BlockchainError::TransactionInvalid(
                                            "Hanya validator aktif yang dapat memperbarui kunci VRF.".into(),
                                        ));
                                    }
                                    sender_account.vrf_public_key = *new_vrf_public_key;
                                }
                                // TransactionData::WithdrawFromTreasury {
                                //     recipient,
                                //     amount,
                                //     approvals,
                                // } => {
                                //     let mut message_to_sign = Vec::new();
                                //     message_to_sign.extend_from_slice(recipient.as_ref());
                                //     message_to_sign.extend_from_slice(&amount.to_be_bytes());
                                //     let message_hash = sha2::Sha256::digest(&message_to_sign);

                                //     let required_approvals = (DEVELOPER_COMMITTEE.len() / 2) + 1;
                                //     let mut valid_approvers = HashSet::new();
                                //     let committee_addresses: HashSet<Address> = DEVELOPER_COMMITTEE
                                //         .iter()
                                //         .map(|hex_str| {
                                //             Address(
                                //                 hex::decode(hex_str.trim_start_matches("0x"))
                                //                     .unwrap()
                                //                     .try_into()
                                //                     .unwrap(),
                                //             )
                                //         })
                                //         .collect();

                                //     for signature in approvals {
                                //         for dev_address in &committee_addresses {
                                //             if valid_approvers.contains(dev_address) {
                                //                 continue;
                                //             }
                                //             if let Ok(dev_account) =
                                //                 get_account_helper(&local_temp_accounts, dev_address, &trie_ro)
                                //             {
                                //                 if crypto::verify(
                                //                     &dev_account.signing_public_key,
                                //                     &message_hash,
                                //                     signature,
                                //                 ) {
                                //                     valid_approvers.insert(*dev_address);
                                //                     break;
                                //                 }
                                //             }
                                //         }
                                //     }

                                //     if valid_approvers.len() < required_approvals {
                                //         return Err(BlockchainError::TransactionInvalid(
                                //             format!("Persetujuan unik dari komite pengembang tidak mencukupi (dibutuhkan {}, hanya ada {}).", required_approvals, valid_approvers.len())
                                //         ));
                                //     }

                                //     let mut treasury_account =
                                //         get_account_helper(&local_temp_accounts, &TREASURY_ADDRESS, &trie_ro)?;
                                //     if treasury_account.balance < *amount {
                                //         return Err(BlockchainError::InsufficientBalance {
                                //             has: treasury_account.balance,
                                //             needs: *amount,
                                //         });
                                //     }
                                //     treasury_account.balance = treasury_account.balance.saturating_sub(*amount);

                                //     let mut recipient_account = get_account_helper(&local_temp_accounts, recipient, &trie_ro).unwrap_or_default();
                                //     recipient_account.balance = recipient_account.balance.saturating_add(*amount);

                                //     local_temp_accounts.insert(TREASURY_ADDRESS, treasury_account);
                                //     local_temp_accounts.insert(*recipient, recipient_account);
                                // }
                                TransactionData::DeployContract { code } => {
                                    if code.is_empty() {
                                        return Err(BlockchainError::TransactionInvalid(
                                            "Kode kontrak tidak boleh kosong.".into(),
                                        ));
                                    }
                                    let contract_address_bytes = KeccakHasher::hash(
                                        &[tx.sender().as_ref(), &sender_account.nonce.to_be_bytes()].concat(),
                                    );
                                    let contract_address = Address(
                                        contract_address_bytes.as_slice()[..ADDRESS_SIZE]
                                            .try_into()
                                            .unwrap(),
                                    );

                                    let empty_storage_session = self
                                        .state
                                        .create_trie_session(Default::default(), COL_CONTRACT_STORAGE);
                                    let initial_storage_root = empty_storage_session.commit()?;
                                    let code_hash = KeccakHasher::hash(code).to_vec();

                                    let contract_account = Account {
                                        code_hash: Some(code_hash.clone()),
                                        storage_root: Some(initial_storage_root.to_vec()),
                                        ..Default::default()
                                    };

                                    local_db_ops.push((COL_CONTRACT_CODE, code_hash, Some(code.clone())));
                                    local_temp_accounts.insert(contract_address, contract_account);
                                    info!(
                                        "KONTRAK: Berhasil deploy di alamat {}",
                                        hex::encode(contract_address.as_ref())
                                    );
                                }
                                TransactionData::CallContract { .. } => {
                                    unreachable!("Sudah ditangani secara terpisah")
                                }
                                TransactionData::UpdateNetworkIdentity { multiaddr } => {
                                    if Multiaddr::try_from(multiaddr.clone()).is_err() {
                                        warn!("Transaksi UpdateNetworkIdentity dari {} berisi multiaddr tidak valid. Diabaikan.", hex::encode(tx.sender().as_ref()));
                                    } else {
                                        sender_account.network_identity = Some(multiaddr.clone());
                                    }
                                }
                                TransactionData::ImAlive => {}
                                &TransactionData::SubmitAggregateRollupBatch { .. } => {}
                            }

                            local_temp_accounts.insert(sender_address, sender_account);
                            Ok((tx.clone(), local_temp_accounts, local_intra_block_l2_root, local_db_ops, local_gov_ops, became_validator, became_sequencer, was_deregistered))
                        };

                        (*original_index, execution_logic())
                    })
                    .collect();

                let mut conflicted_txs_for_next_iteration: Vec<(usize, Transaction)> = Vec::new();
                let mut successful_overlays_this_iteration: BTreeMap<Address, Account> = BTreeMap::new();
                let mut made_progress = false;

                let mut sorted_results = execution_results;
                sorted_results.sort_by_key(|(_, result)| result.as_ref().map_or(0, |(tx, _, _, _, _, _, _, _)| tx.max_priority_fee_per_gas));
                sorted_results.reverse();

                for (original_index, res) in sorted_results {
                    match res {
                        Ok((tx, local_overlay, new_l2_root, local_db_ops, local_gov_ops, became_validator, became_sequencer, was_deregistered)) => {
                            let has_conflict = local_overlay.keys().any(|addr| successful_overlays_this_iteration.contains_key(addr));
                            if !has_conflict {
                                made_progress = true;
                                final_valid_txs_map.insert(original_index, tx.clone());
                                db_ops.extend(local_db_ops);
                                governance_ops.extend(local_gov_ops);
                                successful_overlays_this_iteration.extend(local_overlay);
                                current_l2_root = new_l2_root;

                                if became_validator {
                                    result.final_validators.insert(tx.sender());
                                }
                                if became_sequencer {
                                    result.final_sequencers.insert(tx.sender());
                                }
                                if was_deregistered {
                                    result.final_sequencers.remove(&tx.sender());
                                }
                            } else {
                                conflicted_txs_for_next_iteration.push((original_index, transactions[original_index].clone()));
                            }
                        }
                        Err(e) => {
                            made_progress = true;
                            permanently_failed_tx_hashes.insert(transactions[original_index].message_hash());
                            log::trace!("[Block-STM] Tx 0x{} gagal permanen: {}", hex::encode(transactions[original_index].message_hash()), e);
                        }
                    }
                }

                if !made_progress && !txs_to_process.is_empty() {
                    warn!("[Block-STM] Tidak ada kemajuan, membatalkan {} tx.", txs_to_process.len());
                    break 're_execution_loop;
                }

                if !successful_overlays_this_iteration.is_empty() {
                    let new_root = {
                        let mut temp_trie = TrieDBMutBuilder::<EviceTrieLayout>::from_existing(trie_db.as_hash_db_mut(), &mut current_root).build();
                        for (address, account) in &successful_overlays_this_iteration {
                            final_state_overlay.insert(*address, account.clone());
                            let encoded_account = bincode::encode_to_vec(account, bincode::config::standard())?;
                            temp_trie.insert(&KeccakHasher::hash(address.as_ref()), &encoded_account)?;
                        }
                        *temp_trie.root()
                    }; 
                    current_root = new_root;
                }
                txs_to_process = conflicted_txs_for_next_iteration;
            }
        }

        for (original_index, tx) in sequential_txs {
            let execution_result: Result<(), BlockchainError> = (|| {
                match &tx.data {
                    TransactionData::CallContract { contract_address, call_data } => {
                        let (mut contract_account, code) = {
                            let trie_ro = TrieDBBuilder::<crate::EviceTrieLayout>::new(trie_db, &current_root).build();
                            let acc_data = trie_ro.get(&KeccakHasher::hash(contract_address.as_ref()))?
                                .ok_or_else(|| BlockchainError::TransactionInvalid("Akun kontrak tidak ditemukan.".into()))?;
                            let acc: Account = bincode::decode_from_slice(&acc_data, bincode::config::standard())
                                .map(|(a, _)| a)
                                .map_err(|e| BlockchainError::BincodeDecode(Box::new(e)))?;
                            let code_hash = acc.code_hash.clone()
                                .ok_or_else(|| BlockchainError::TransactionInvalid("Akun bukan kontrak.".into()))?;
                            let code_bytes = self.state.db.get(COL_CONTRACT_CODE, &code_hash)?
                                .ok_or_else(|| BlockchainError::TransactionInvalid("Kode kontrak tidak ditemukan.".into()))?;
                            (acc, code_bytes)
                        };

                        let result_wasm = wasm_runtime::execute_contract(
                            &self.state,
                            &code,
                            contract_account.storage_root.clone(), 
                            tx.sender(),
                            call_data,
                            50_000_000,
                            block_header.timestamp as u64
                        )?;

                        if result_wasm.reverted {
                            return Err(BlockchainError::WasmError(format!("Eksekusi kontrak gagal: {}", result_wasm.revert_message)));
                        }

                        contract_account.storage_root = Some(result_wasm.new_storage_root); 
                        final_state_overlay.insert(*contract_address, contract_account);
                    }
                    TransactionData::SubmitAggregateRollupBatch { initial_state_root, final_state_root, aggregated_proof, .. } => {
                        if initial_state_root != &current_l2_root { 
                            return Err(BlockchainError::TransactionInvalid("Batch agregat L2 dibangun di atas state root yang usang.".into())); 
                        }
                        
                        let agg_vk = self.l2_aggregation_verifying_key.clone();
                        let proof = Proof::<BW6_761>::deserialize_uncompressed(&aggregated_proof[..])?;
                        let public_inputs_bls: Vec<Fr> = vec![Fr::from_be_bytes_mod_order(initial_state_root), Fr::from_be_bytes_mod_order(final_state_root)];
                        
                        let aggregated_public_inputs: Vec<Bw6_761Fr> = EmulatedFieldInputVar::<Fr, Bw6_761Fr>::repack_input(&public_inputs_bls);
                        if !Groth16::<BW6_761>::verify(&agg_vk, &aggregated_public_inputs, &proof)? { 
                            return Err(BlockchainError::TransactionInvalid("Bukti ZK agregat tidak valid!".into())); 
                        }
                        current_l2_root = final_state_root.clone();
                    }
                    _ => unreachable!(),
                }
                Ok(())
            })();

            if execution_result.is_ok() {
                final_valid_txs_map.insert(original_index, tx);
            } else {
                log::trace!("[Sequential Exec] Tx 0x{} dilewati karena error: {:?}", hex::encode(tx.message_hash()), execution_result.unwrap_err());
            }
        }

        result.new_l2_state_root = current_l2_root;
        let final_valid_txs_list: Vec<Transaction> = final_valid_txs_map.values().cloned().collect();

        let (total_priority_fees, total_base_fees_collected) = {
            let mut total_tip = 0;
            let mut total_base = 0;
            for tx in &final_valid_txs_list {
                let tip = tx.max_priority_fee_per_gas.min(tx.max_fee_per_gas.saturating_sub(block_header.base_fee_per_gas));
                total_tip += tip * tx.data.base_gas_cost();
                total_base += block_header.base_fee_per_gas * tx.data.base_gas_cost();
            }
            (total_tip, total_base)
        };

        current_root = {
            let mut trie = TrieDBMutBuilder::<crate::EviceTrieLayout>::from_existing(
                trie_db.as_hash_db_mut(),
                &mut current_root,
            )
            .build();
            
            self.process_governance_proposals(block_header.index, &mut trie, governance_ops)?;

            // 1. Dapatkan total stake dari state saat ini
            let total_staked_amount: u64 = result.final_validators.iter()
                .map(|addr| {
                    if let Some(account) = final_state_overlay.get(addr) {
                        return Ok(account.staked_amount);
                    }
                    trie.get(&KeccakHasher::hash(addr.as_ref()))
                        .map_err(BlockchainError::from)
                        .and_then(|opt_data| {
                            opt_data
                                .and_then(|d| bincode::decode_from_slice(&d, bincode::config::standard()).ok().map(|(acc, _)| acc))
                                .map(|acc: Account| acc.staked_amount)
                                .ok_or_else(|| BlockchainError::TransactionInvalid(format!("Akun validator tidak ditemukan: {}", addr)))
                        })
                })
                .collect::<Result<Vec<u64>, _>>()?
                .iter()
                .sum();
            
            // 2. Hitung hadiah blok dinamis
            let genesis = crate::genesis::Genesis::from_file("genesis.json")
                .map_err(|e| BlockchainError::LogicError(format!("Gagal memuat genesis: {}", e)))?;
            
            let block_reward = self.calculate_dynamic_block_reward(
                &trie,
                &final_state_overlay,
                &result.final_validators,
                genesis.parameters.base_reward_factor,
                genesis.parameters.blocks_per_epoch_for_reward,
            )?;

            // 3. Akumulasikan semua imbalan untuk proposer
            let proposer_total_reward = block_reward.saturating_add(total_priority_fees);

            // 4. Dapatkan akun proposer dan tambahkan imbalannya
            let mut proposer_account = match final_state_overlay.get(&block_header.authority).cloned() {
                Some(account) => account, 
                None => {
                    let hashed_key = keccak_hasher::KeccakHasher::hash(block_header.authority.as_ref());
                    match trie.get(hashed_key.as_ref())? {
                        Some(encoded_account) => {
                            bincode::decode_from_slice(&encoded_account, bincode::config::standard())
                                .map(|(acc, _)| acc)
                                .map_err(|e| BlockchainError::BincodeDecode(Box::new(e)))?
                        }
                        None => {
                            return Err(BlockchainError::TransactionInvalid(format!(
                                "Akun proposer tidak ditemukan: {}",
                                hex::encode(block_header.authority.as_ref())
                            )));
                        }
                    }
                }
            };

            proposer_account.balance = proposer_account.balance.saturating_add(proposer_total_reward);
            final_state_overlay.insert(block_header.authority, proposer_account);

            info!(
                "Dynamic reward processed: Proposer gets {} ({} block reward + {} tip). Total Staked: {}. Total base fee burned: {}",
                proposer_total_reward, block_reward, total_priority_fees, total_staked_amount, total_base_fees_collected
            );

            for (address, account) in &final_state_overlay {
                let encoded_account = bincode::encode_to_vec(account, bincode::config::standard())?;
                trie.insert(&KeccakHasher::hash(address.as_ref()), &encoded_account)?;
            }
            *trie.root()
        };

        let final_txs_sorted: Vec<Transaction> = final_valid_txs_map.into_values().collect();
        
        Ok((current_root.to_vec(), result, final_txs_sorted, final_state_overlay))
    }

    pub fn verify_velocity_qc(&self, qc: &QuorumCertificate) -> bool {
        if qc.view_number == 0 && qc.signatures.is_empty() {
            return true;
        }

        if qc.signatures.len() < self.dkg_state.threshold {
            warn!(
                "[QC VERIFY] Gagal: Jumlah tanda tangan ({}) di bawah ambang batas ({}).",
                qc.signatures.len(),
                self.dkg_state.threshold
            );
            return false;
        }

        let mut unique_voters = HashSet::new();
        for (voter_address, signature) in &qc.signatures {
            if !unique_voters.insert(voter_address) {
                warn!(
                    "[QC VERIFY] Gagal: Ditemukan suara duplikat dari voter 0x{}.",
                    hex::encode(voter_address.as_ref())
                );
                return false;
            }

            let voter_account = match self.state.get_account(voter_address) {
                Ok(Some(acc)) => acc,
                _ => {
                    warn!(
                        "[QC VERIFY] Gagal: Akun untuk voter 0x{} tidak ditemukan.",
                        hex::encode(voter_address.as_ref())
                    );
                    return false;
                }
            };

            let temp_vote = VelocityVote {
                round_id: qc.view_number,
                block_hash: qc.block_hash.clone(),
                voter_address: *voter_address,
                signature: [0; crate::crypto::SIGNATURE_SIZE],
            };
            let data_to_verify =
                temp_vote.canonical_bytes(voter_account.signing_public_key.as_ref());

            if !crypto::verify(
                &voter_account.signing_public_key,
                &data_to_verify,
                signature,
            ) {
                warn!(
                    "[QC VERIFY] Gagal: Tanda tangan tidak valid dari voter 0x{}.",
                    hex::encode(voter_address.as_ref())
                );
                return false;
            }
        }

        true
    }

    pub fn update_dkg_state_from_machine(&mut self) -> Result<(), StateError> {
        let mut participants = std::collections::HashMap::new();
        for validator_addr in &self.state.validators {
            if let Some(acc) = self.state.get_account(validator_addr)? {
                if let Some(pk_bytes) = acc.bls_public_key {
                    if let Ok(pk) = blst::min_pk::PublicKey::from_bytes(&pk_bytes) {
                        participants.insert(*validator_addr, pk);
                    } else {
                        warn!("[DKG Update] Gagal mem-parsing kunci BLS untuk validator {}", validator_addr);
                    }
                } else {
                    warn!("[DKG Update] Validator aktif {} tidak memiliki kunci BLS di state.", validator_addr);
                }
            }
        }

        self.dkg_state = DkgState {
            participants,
            threshold: (self.state.validators.len() * 2 / 3) + 1,
        };
        
        info!("[DKG Update] DKG state berhasil diperbarui. Validator aktif: {}, Threshold: {}", self.dkg_state.participants.len(), self.dkg_state.threshold);
        Ok(())
    }
}
