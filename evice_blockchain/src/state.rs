// evice_blockchain/src/state.rs

use bincode::{Decode, Encode};
use libp2p::Multiaddr;
use log::{debug, info};
use lru::LruCache;
use parity_db::{ColumnOptions as ParityColumnOptions, Db, Options as DbOptions};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;

use hash_db::{AsHashDB, HashDB, HashDBRef, Hasher, Prefix};
use keccak_hasher::KeccakHasher;
use memory_db::{HashKey, MemoryDB};
use trie_db::{
    node::{Node, NodeHandle, Value},
    DBValue, Trie, TrieDBBuilder, TrieDBMutBuilder, TrieDBNodeIterator, TrieError, TrieMut,
};

use crate::serde_helpers;
use crate::EviceTrieLayout;
use crate::{
    consensus::QuorumCertificate,
    crypto::{public_key_to_address, ADDRESS_SIZE, PUBLIC_KEY_SIZE},
    genesis::Genesis,
    governance::{ProposalId, ProposalState},
    Address, FullPublicKey,
};

pub type DbTx<'a> = (ColumnId, &'a [u8], Option<Vec<u8>>);
pub type H256 = [u8; 32];

fn hash_key(address: &Address) -> H256 {
    KeccakHasher::hash(address.as_ref())
}

#[derive(Clone)]
pub struct ParityDbTrieBackend {
    db: Arc<Db>,
    pending_writes: BTreeMap<TrieRoot, DBValue>,
    col: ColumnId,
    node_cache: Arc<Mutex<LruCache<TrieRoot, DBValue>>>,
}

impl ParityDbTrieBackend {
    pub fn new(db: Arc<Db>, col: ColumnId) -> Self {
        Self {
            db,
            pending_writes: BTreeMap::new(),
            col,
            node_cache: Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(1_000_000).unwrap()))),
        }
    }

    pub fn commit_pending(&mut self) -> Result<(), parity_db::Error> {
        if self.pending_writes.is_empty() {
            return Ok(());
        }

        let mut batch = Vec::new();
        let mut cache = self.node_cache.lock().unwrap();
        for (key, value) in std::mem::take(&mut self.pending_writes) {
            cache.put(key, value.clone());
            batch.push((self.col, key.as_ref().to_vec(), Some(value)));
        }

        self.db.commit(batch)
    }

    pub fn rollback_pending(&mut self) {
        self.pending_writes.clear();
    }
}

impl HashDBRef<KeccakHasher, DBValue> for ParityDbTrieBackend {
    fn get(&self, key: &TrieRoot, _prefix: Prefix) -> Option<DBValue> {
        // 1. Cek di pending writes 
        if let Some(value) = self.pending_writes.get(key) {
            return Some(value.clone());
        }

        // 2. Cek di cache memori 
        if let Some(value) = self.node_cache.lock().unwrap().get(key) {
            return Some(value.clone());
        }

        // 3. Jika tidak ada di mana pun, akses ke disk 
        match self.db.get(self.col, key.as_ref()) {
            Ok(Some(value)) => {
                self.node_cache.lock().unwrap().put(*key, value.clone());
                Some(value)
            }
            Ok(None) => None,
            Err(e) => {
                debug!(
                    "Database read error for key {}: {}",
                    hex::encode(key.as_ref()),
                    e
                );
                None
            }
        }
    }

    fn contains(&self, key: &TrieRoot, prefix: Prefix) -> bool {
        HashDB::get(self, key, prefix).is_some()
    }
}

impl HashDB<KeccakHasher, DBValue> for ParityDbTrieBackend {
    fn get(&self, key: &TrieRoot, prefix: Prefix) -> Option<DBValue> {
        HashDBRef::get(self, key, prefix)
    }

    fn contains(&self, key: &TrieRoot, prefix: Prefix) -> bool {
        HashDBRef::contains(self, key, prefix)
    }

    fn emplace(&mut self, key: TrieRoot, _prefix: Prefix, value: DBValue) {
        self.pending_writes.insert(key, value);
    }

    fn insert(&mut self, _prefix: Prefix, value: &[u8]) -> TrieRoot {
        let key = KeccakHasher::hash(value);
        self.emplace(key, _prefix, value.to_vec());
        key
    }

    fn remove(&mut self, key: &TrieRoot, _prefix: Prefix) {
        self.pending_writes.remove(key);
    }
}

impl AsHashDB<KeccakHasher, DBValue> for ParityDbTrieBackend {
    fn as_hash_db(&self) -> &dyn HashDB<KeccakHasher, DBValue> {
        self
    }
    fn as_hash_db_mut(&mut self) -> &mut dyn HashDB<KeccakHasher, DBValue> {
        self
    }
}

pub type VrfPublicKeyBytes = [u8; 32];
pub const MINIMUM_STAKE: u64 = 10_000;
// pub const TREASURY_ADDRESS: Address = Address([0u8; ADDRESS_SIZE]);
pub const PROPOSAL_VOTING_PERIOD: u64 = 10;
pub const L2_BRIDGE_ADDRESS: Address = Address([1u8; ADDRESS_SIZE]);
pub const DEVELOPER_COMMITTEE: &[&str] = &[
    "0x2a282495b86386619f57297e5509a25b2ea4a56a",
    "0x9f535805298f87c897f4c42d3221430262183c51",
    "0xbf7a05a8d7a1811e23339f40b2a884358a9d13e3",
];
pub const DATA_AVAILABILITY_COMMITTEE: &[&str] = &[
    "0x2a282495b86386619f57297e5509a25b2ea4a56a",
    "0x9f535805298f87c897f4c42d3221430262183c51",
    "0xbf7a05a8d7a1811e23339f40b2a884358a9d13e3",
];

pub type ColumnId = u8;
pub const COL_TRIE: ColumnId = 0;
pub const COL_METADATA: ColumnId = 1;
pub const COL_GOVERNANCE: ColumnId = 2;
pub const COL_BLOCKS: ColumnId = 3;
pub const COL_STATE_JOURNAL: ColumnId = 4;
pub const COL_L2_BATCHES: ColumnId = 5;
pub const COL_CONTRACT_CODE: ColumnId = 6;
pub const COL_CONTRACT_STORAGE: ColumnId = 7;
pub const COL_DKG_RESULTS: ColumnId = 8;
pub const COL_NETWORK_IDENTITIES: ColumnId = 9;
pub const COL_TX_LOOKUP: ColumnId = 10;

pub const STATE_ROOT_KEY: &[u8] = b"current_state_root";
pub const VALIDATORS_KEY: &[u8] = b"validators_set";
pub const VALIDATOR_LAST_SEEN_KEY: &[u8] = b"validator_last_seen";
pub const JAILED_VALIDATORS_KEY: &[u8] = b"jailed_validators";
pub const NEXT_PROPOSAL_ID_KEY: &[u8] = b"next_proposal_id";
pub const L2_STATE_ROOT_KEY: &[u8] = b"l2_state_root";
pub const ACTIVE_SEQUENCERS_KEY: &[u8] = b"active_sequencers_set";
pub const PENDING_UPGRADE_KEY: &[u8] = b"pending_runtime_upgrade";
pub const L2_LAST_BATCH_L1_BLOCK_KEY: &[u8] = b"l2_last_batch_l1_block";

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, Encode, Decode)]
pub struct Account {
    pub balance: u64,
    pub staked_amount: u64,
    pub nonce: u64,
    pub signing_public_key: FullPublicKey,
    #[serde(with = "serde_bytes")]
    pub vrf_public_key: VrfPublicKeyBytes,
    #[serde(with = "serde_helpers::option_vec_u8")]
    pub bls_public_key: Option<Vec<u8>>,
    #[serde(with = "serde_helpers::option_vec_u8")]
    pub network_identity: Option<Vec<u8>>,
    pub network_identity_version: u64,
    #[serde(with = "serde_helpers::option_vec_u8")]
    pub code_hash: Option<Vec<u8>>,
    #[serde(with = "serde_helpers::option_vec_u8")]
    pub storage_root: Option<Vec<u8>>,
    pub last_seen_block: u64,
}

impl Account {
    pub fn new(balance: u64) -> Self {
        Self {
            balance,
            staked_amount: 0,
            nonce: 0,
            signing_public_key: Default::default(),
            vrf_public_key: [0u8; 32],
            bls_public_key: None,
            network_identity: None,
            network_identity_version: 0,
            code_hash: None,
            storage_root: None,
            last_seen_block: 0,
        }
    }
}

#[derive(Error, Debug)]
pub enum StateError {
    #[error("Database error: {0}")]
    DbError(#[from] parity_db::Error),
    #[error("Serialization/deserialization error: {0}")]
    SerializationError(String),
    #[error("Encode error: {0}")]
    EncodeError(#[from] Box<bincode::error::EncodeError>),
    #[error("Trie error: {0}")]
    TrieError(String),
    #[error("State machine logic error: {0}")]
    LogicError(String),
    #[error("Error converting bytes: {0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<bincode::error::DecodeError> for StateError {
    fn from(e: bincode::error::DecodeError) -> Self {
        StateError::SerializationError(e.to_string())
    }
}

impl From<Box<bincode::error::DecodeError>> for StateError {
    fn from(e: Box<bincode::error::DecodeError>) -> Self {
        StateError::SerializationError(e.to_string())
    }
}

impl From<bincode::error::EncodeError> for StateError {
    fn from(e: bincode::error::EncodeError) -> Self {
        StateError::EncodeError(Box::new(e))
    }
}

impl<L: std::fmt::Debug, E: std::fmt::Debug> From<Box<TrieError<L, E>>> for StateError {
    fn from(err: Box<TrieError<L, E>>) -> Self {
        StateError::TrieError(format!("{:?}", err))
    }
}

pub type TrieRoot = <KeccakHasher as Hasher>::Out;

pub struct StateMachine {
    pub db: Arc<Db>,
    pub state_root: TrieRoot,
    pub validators: HashSet<Address>,
    pub validator_last_seen: HashMap<Address, u64>,
    pub jailed_validators: HashSet<Address>,
    pub active_sequencers: HashSet<Address>,
    pub l2_state_root: Vec<u8>,
    pub l2_state_root_history: VecDeque<Vec<u8>>,
    pub account_cache: Arc<Mutex<LruCache<Address, Account>>>,
}

impl Clone for StateMachine {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            state_root: self.state_root,
            validators: self.validators.clone(),
            validator_last_seen: self.validator_last_seen.clone(),
            jailed_validators: self.jailed_validators.clone(),
            active_sequencers: self.active_sequencers.clone(),
            l2_state_root: self.l2_state_root.clone(),
            l2_state_root_history: self.l2_state_root_history.clone(),
            account_cache: Arc::clone(&self.account_cache),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Encode, Decode)]
pub struct UpgradeInfo {
    pub binary_hash: Vec<u8>,
    pub download_url: String,
    pub activation_block_height: u64,
}

impl StateMachine {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, StateError> {
        info!(
            "[STATE_DIAGNOSTIC] Memasuki StateMachine::new untuk path: {:?}",
            path.as_ref()
        ); 

        let mut opts = DbOptions::with_columns(path.as_ref(), 11);

        opts.stats = true;
        opts.sync_wal = false;

        opts.columns = vec![
            ParityColumnOptions {
                btree_index: true,
                ..Default::default()
            }, // COL_TRIE = 0
            ParityColumnOptions {
                ..Default::default()
            }, // COL_METADATA = 1
            ParityColumnOptions {
                btree_index: true,
                ..Default::default()
            }, // COL_GOVERNANCE = 2
            ParityColumnOptions {
                ..Default::default()
            }, // COL_BLOCKS = 3
            ParityColumnOptions {
                btree_index: true,
                ..Default::default()
            }, // COL_STATE_JOURNAL = 4
            ParityColumnOptions {
                ..Default::default()
            }, // COL_L2_BATCHES = 5
            ParityColumnOptions {
                ..Default::default()
            }, // COL_CONTRACT_CODE = 6
            ParityColumnOptions {
                btree_index: true,
                ..Default::default()
            }, // COL_CONTRACT_STORAGE = 7
            ParityColumnOptions {
                ..Default::default()
            }, // COL_DKG_RESULTS = 8
            ParityColumnOptions {
                ..Default::default()
            }, // COL_NETWORK_IDENTITIES = 9
            ParityColumnOptions {
                btree_index: true,
                ..Default::default()
            }, // COL_TX_LOOKUP = 10
        ];

        opts.path = path.as_ref().to_path_buf();

        let db = Arc::new(Db::open_or_create(&opts)?);
        let is_new_db = db.get(COL_METADATA, STATE_ROOT_KEY)?.is_none();

        let mut machine = Self {
            db: Arc::clone(&db),
            state_root: Default::default(),
            validators: HashSet::new(),
            validator_last_seen: HashMap::new(),
            jailed_validators: HashSet::new(),
            active_sequencers: HashSet::new(),
            l2_state_root: vec![0; 32],
            l2_state_root_history: VecDeque::with_capacity(256),
            account_cache: Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(100_000).unwrap()))),
        };

        if is_new_db {
            info!("Database kosong terdeteksi. Mencoba memuat dari genesis.json...");
            let genesis = Genesis::from_file("genesis.json").map_err(|e| {
                StateError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    e.to_string(),
                ))
            })?;
            machine
                .initialize_from_genesis(&genesis)
                .map_err(|e| StateError::LogicError(e.to_string()))?;
        } else {
            info!("Memuat state dari database yang ada...");

            let root_bytes = db
                .get(COL_METADATA, STATE_ROOT_KEY)?
                .ok_or_else(|| StateError::LogicError("State root krusial tidak ditemukan di database yang ada.".to_string()))?; // Kembalikan error spesifik

            if root_bytes.len() == machine.state_root.len() {
                machine.state_root.as_mut().copy_from_slice(&root_bytes);
            } else {
                return Err(StateError::LogicError(format!(
                    "State root di database memiliki panjang yang salah: {} (diharapkan {})",
                    root_bytes.len(),
                    machine.state_root.len()
                )));
            }

            let config = bincode::config::standard();
            machine.validators = db
                .get(COL_METADATA, VALIDATORS_KEY)?
                .map(|enc| {
                    bincode::decode_from_slice(&enc, config)
                        .map(|(v, _)| v)
                        .unwrap_or_default()
                })
                .unwrap_or_default();

            machine.validator_last_seen = db
                .get(COL_METADATA, VALIDATOR_LAST_SEEN_KEY)?
                .map(|enc| {
                    bincode::decode_from_slice(&enc, config)
                        .map(|(v, _)| v)
                        .unwrap_or_default()
                })
                .unwrap_or_default();

            machine.jailed_validators = db
                .get(COL_METADATA, JAILED_VALIDATORS_KEY)?
                .map(|enc| {
                    bincode::decode_from_slice(&enc, config)
                        .map(|(v, _)| v)
                        .unwrap_or_default()
                })
                .unwrap_or_default();

            machine.active_sequencers = db
                .get(COL_METADATA, ACTIVE_SEQUENCERS_KEY)?
                .map(|enc| {
                    bincode::decode_from_slice(&enc, config)
                        .map(|(v, _)| v)
                        .unwrap_or_default()
                })
                .unwrap_or_default();

            machine.l2_state_root = db
                .get(COL_METADATA, L2_STATE_ROOT_KEY)?
                .unwrap_or(vec![0; 32]);
            machine.l2_state_root_history = db
                .get(COL_METADATA, b"l2_state_root_history")?
                .map(|enc| {
                    bincode::decode_from_slice(&enc, config)
                        .map(|(v, _)| v)
                        .unwrap_or_default()
                })
                .unwrap_or_else(|| {
                    let mut history = VecDeque::with_capacity(256);
                    if !machine.l2_state_root.iter().all(|&b| b == 0) {
                        history.push_front(machine.l2_state_root.clone());
                    }
                    history
                });
        }

        Ok(machine)
    }

    fn mark_reachable_nodes(
        db: &Arc<Db>,
        root: &TrieRoot,
        reachable_nodes: &mut HashSet<Vec<u8>>,
    ) -> Result<(), StateError> {
        if !reachable_nodes.insert(root.as_ref().to_vec()) {
            return Ok(());
        }

        let trie_db = ParityDbTrieBackend::new(Arc::clone(db), COL_TRIE);
        let trie = TrieDBBuilder::<EviceTrieLayout>::new(&trie_db, root).build();
        let mut iter = TrieDBNodeIterator::new(&trie)?;

        while let Some(item) = iter.next() {
            let (_, _, node) = item?;
            match node.node() {
                Node::Extension(_, child_handle) => {
                    if let NodeHandle::Hash(hash) = child_handle {
                        let hash_arr: TrieRoot = (*hash)
                            .try_into()
                            .map_err(|_| StateError::TrieError("Invalid hash length".into()))?;
                        StateMachine::mark_reachable_nodes(db, &hash_arr, reachable_nodes)?;
                    }
                }
                Node::Leaf(_, Value::Node(child_handle_bytes)) => {
                    let hash_arr: TrieRoot = child_handle_bytes
                        .try_into()
                        .map_err(|_| StateError::TrieError("Invalid hash length".into()))?;
                    StateMachine::mark_reachable_nodes(db, &hash_arr, reachable_nodes)?;
                }
                Node::Branch(children, value) | Node::NibbledBranch(_, children, value) => {
                    if let Some(Value::Node(val_hash)) = value {
                        let val_hash_arr: TrieRoot = val_hash
                            .try_into()
                            .map_err(|_| StateError::TrieError("Invalid hash length".into()))?;
                        StateMachine::mark_reachable_nodes(db, &val_hash_arr, reachable_nodes)?;
                    }
                    for child_handle in children.iter().flatten() {
                        if let NodeHandle::Hash(hash) = child_handle {
                            let hash_arr: TrieRoot = (*hash)
                                .try_into()
                                .map_err(|_| StateError::TrieError("Invalid hash length".into()))?;
                            StateMachine::mark_reachable_nodes(db, &hash_arr, reachable_nodes)?;
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn prune(&self, keep_recent_blocks: u64) -> Result<(), StateError> {
        info!("STATE PRUNING: Memulai proses pemangkasan state...");

        let latest_block_num = match self.db.get(COL_METADATA, b"latest_block_num")? {
            Some(bytes) => u64::from_be_bytes(bytes.try_into().unwrap_or([0; 8])),
            None => return Ok(()),
        };

        if latest_block_num <= keep_recent_blocks {
            info!("STATE PRUNING: Jumlah blok belum cukup untuk pemangkasan.");
            return Ok(());
        }

        let mut reachable_nodes = HashSet::new();
        let first_kept_block = latest_block_num - keep_recent_blocks;

        info!(
            "STATE PRUNING: Menjaga state dari blok #{} hingga #{}.",
            first_kept_block, latest_block_num
        );

        for i in first_kept_block..=latest_block_num {
            if let Some(root_bytes) = self.db.get(COL_STATE_JOURNAL, &i.to_be_bytes())? {
                let mut root_hash = TrieRoot::default();
                root_hash.as_mut().copy_from_slice(&root_bytes);
                StateMachine::mark_reachable_nodes(&self.db, &root_hash, &mut reachable_nodes)?;
            }
        }
        info!(
            "STATE PRUNING: Total {} node trie ditandai sebagai dapat dijangkau.",
            reachable_nodes.len()
        );

        let mut delete_batch = Vec::new();
        let mut iter = self.db.iter(COL_TRIE)?;
        let mut total_nodes = 0;

        while let Ok(Some((key, _))) = iter.next() {
            total_nodes += 1;
            if !reachable_nodes.contains(&key) {
                delete_batch.push((COL_TRIE, key, None));
            }
        }

        if !delete_batch.is_empty() {
            info!(
                "STATE PRUNING: Menghapus {} dari {} node trie yang usang...",
                delete_batch.len(),
                total_nodes
            );
            self.db.commit(delete_batch)?;
        } else {
            info!("STATE PRUNING: Tidak ada node usang yang ditemukan.");
        }

        let mut journal_delete_batch = Vec::new();
        let mut journal_iter = self.db.iter(COL_STATE_JOURNAL)?;
        while let Ok(Some((key, _))) = journal_iter.next() {
            let block_num = u64::from_be_bytes(key.as_slice().try_into().unwrap_or([0; 8]));
            if block_num < first_kept_block {
                journal_delete_batch.push((COL_STATE_JOURNAL, key, None));
            }
        }

        if !journal_delete_batch.is_empty() {
            info!(
                "STATE PRUNING: Menghapus {} entri jurnal state root yang lama.",
                journal_delete_batch.len()
            );
            self.db.commit(journal_delete_batch)?;
        }

        info!("STATE PRUNING: Proses pemangkasan selesai.");
        Ok(())
    }

    pub fn get_account(&self, address: &Address) -> Result<Option<Account>, StateError> {
        if let Some(account) = self.account_cache.lock().unwrap().get(address) {
            return Ok(Some(account.clone()));
        }

        let trie_db = ParityDbTrieBackend::new(Arc::clone(&self.db), COL_TRIE);
        let trie = TrieDBBuilder::<EviceTrieLayout>::new(&trie_db, &self.state_root).build();
        let hashed_key = hash_key(address);
        match trie.get(hashed_key.as_ref())? {
            Some(encoded_account) => {
                let config = bincode::config::standard();
                let account: Account =
                    bincode::decode_from_slice(&encoded_account, config).map(|(a, _)| a)?;
                self.account_cache
                    .lock()
                    .unwrap()
                    .put(*address, account.clone());
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    pub fn get_proposal(&self, id: ProposalId) -> Result<Option<ProposalState>, StateError> {
        match self.db.get(COL_GOVERNANCE, &id.to_be_bytes())? {
            Some(encoded) => Ok(Some(
                bincode::decode_from_slice(&encoded, bincode::config::standard())
                    .map(|(p, _)| p)?,
            )),
            None => Ok(None),
        }
    }

    pub fn set_proposal_in_tx(
        &self,
        ops: &mut Vec<(ColumnId, Vec<u8>, Option<Vec<u8>>)>,
        state: &ProposalState,
    ) -> Result<(), StateError> {
        let encoded = bincode::encode_to_vec(state, bincode::config::standard())?; 
        ops.push((
            COL_GOVERNANCE,
            state.id.to_be_bytes().to_vec(),
            Some(encoded),
        ));
        Ok(())
    }

    pub fn get_all_proposals(&self) -> Result<Vec<ProposalState>, StateError> {
        let mut proposals = Vec::new();
        let mut iter = self.db.iter(COL_GOVERNANCE)?;

        while let Ok(Some((key, value))) = iter.next() {
            if key.as_slice() == NEXT_PROPOSAL_ID_KEY {
                continue;
            }
            let proposal_state: ProposalState =
                bincode::decode_from_slice(&value[..], bincode::config::standard())
                    .map(|(p, _)| p)?;
            proposals.push(proposal_state);
        }

        Ok(proposals)
    }

    pub fn create_trie_session(&self, root: TrieRoot, col: ColumnId) -> TrieSession {
        TrieSession::new(Arc::clone(&self.db), root, col)
    }

    pub fn process_finished_proposals(
        &self,
        current_block_height: u64,
        ops: &mut Vec<(ColumnId, Vec<u8>, Option<Vec<u8>>)>,
        session: &mut TrieSession,
    ) -> Result<(), StateError> {
        let proposals_to_check = self.get_all_proposals()?;

        for mut proposal_state in proposals_to_check {
            if !proposal_state.executed && current_block_height > proposal_state.end_block {
                info!(
                    "Memproses proposal #{} yang telah selesai.",
                    proposal_state.id
                );
                self.tally_and_execute_proposal(&mut proposal_state, ops, session)?;
            }
        }
        Ok(())
    }

    fn tally_and_execute_proposal(
        &self,
        proposal_state: &mut ProposalState,
        ops: &mut Vec<(ColumnId, Vec<u8>, Option<Vec<u8>>)>,
        _session: &mut TrieSession,
    ) -> Result<(), StateError> {
        proposal_state.executed = true;

        if proposal_state.yes_votes > proposal_state.no_votes {
            info!(
                "Proposal #{} disetujui. Mengeksekusi tindakan...",
                proposal_state.id
            );

            match &proposal_state.proposal.action {
                // ProposalAction::FundTransfer { recipient, amount } => {
                //     let mut treasury_account: Account = session.get_account(&TREASURY_ADDRESS)?
                //         .unwrap_or_default();

                //     if treasury_account.balance >= *amount {
                //         treasury_account.balance -= *amount;
                //         let mut recipient_account: Account = session.get_account(recipient)?
                //             .unwrap_or_default();
                //         recipient_account.balance += *amount;

                //         session.set_account(&TREASURY_ADDRESS, &treasury_account)?;
                //         session.set_account(recipient, &recipient_account)?;

                //         info!("Berhasil mentransfer {} dari kas ke alamat {}", amount, hex::encode(recipient.as_ref()));
                //     } else {
                //         warn!("Eksekusi proposal #{} gagal: dana kas tidak mencukupi.", proposal_state.id);
                //     }
                // }
                _ => {}
            }
        } else {
            info!("Proposal #{} ditolak.", proposal_state.id);
        }

        self.set_proposal_in_tx(ops, proposal_state)?;
        Ok(())
    }

    // pub fn apply_transaction(
    //     &self,
    //     tx: &Transaction,
    //     mut sender_account: Account,
    // ) -> Result<Account, BlockchainError> {
    //     if tx.nonce != sender_account.nonce {
    //         return Err(BlockchainError::StaleNonce { expected: sender_account.nonce, got: tx.nonce });
    //     }

    //     sender_account.nonce += 1;

    //     match &tx.data {
    //         TransactionData::Transfer { amount, .. } => {
    //             if sender_account.balance < *amount {
    //                 return Err(BlockchainError::InsufficientBalance { has: sender_account.balance, needs: *amount });
    //             }
    //             sender_account.balance -= *amount;
    //         }
    //         TransactionData::Stake { amount } => {
    //             if sender_account.balance < *amount {
    //                 return Err(BlockchainError::InsufficientBalance { has: sender_account.balance, needs: *amount });
    //             }
    //             sender_account.balance -= *amount;
    //             sender_account.staked_amount += *amount;
    //         }
    //         TransactionData::SubmitProposal { .. } => {
    //             if !self.validators.contains(&tx.sender) {
    //                 return Err(BlockchainError::TransactionInvalid("Hanya validator yang dapat mengajukan proposal.".into()));
    //             }
    //         }
    //         TransactionData::DepositToL2 { amount } => {
    //             if sender_account.balance < *amount {
    //                 return Err(BlockchainError::InsufficientBalance { has: sender_account.balance, needs: *amount });
    //             }
    //             sender_account.balance -= *amount;
    //         }
    //         TransactionData::WithdrawFromL2 { withdrawal_proof, .. } => {
    //             if withdrawal_proof.l2_state_root.is_empty() {
    //                 return Err(BlockchainError::TransactionInvalid("Bukti penarikan L2 tidak valid".into()));
    //             }
    //         }
    //         _ => {}
    //     }

    //     Ok(sender_account)
    // }

    pub fn initialize_from_genesis(
        &mut self,
        genesis: &Genesis,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Menginisialisasi state dari file genesis...");

        let mut mem_db = MemoryDB::<KeccakHasher, HashKey<KeccakHasher>, Vec<u8>>::default();
        let mut root: TrieRoot = Default::default();

        {
            let mut trie = TrieDBMutBuilder::<EviceTrieLayout>::new(&mut mem_db, &mut root).build();
            let mut sorted_accounts: Vec<_> = genesis.accounts.iter().collect();
            sorted_accounts.sort_by_key(|(address_hex, _)| *address_hex);

            for (address_hex, genesis_account) in sorted_accounts {
                let pub_key_bytes = hex::decode(&genesis_account.public_key)?;
                if pub_key_bytes.len() != PUBLIC_KEY_SIZE {
                    return Err("Kunci publik di genesis.json memiliki panjang yang salah.".into());
                }

                let derived_address =
                    public_key_to_address(&pub_key_bytes.as_slice().try_into().unwrap());

                let address_from_key = Address(
                    hex::decode(&address_hex[2..])?
                        .try_into()
                        .map_err(|_| "Alamat di kunci genesis tidak valid")?,
                );
                if derived_address != address_from_key {
                    return Err(format!(
                        "Alamat {} tidak cocok dengan kunci publiknya di genesis.json",
                        address_hex
                    )
                    .into());
                }

                let account = Account {
                    balance: genesis_account.balance.parse()?,
                    staked_amount: genesis_account.staked_amount.parse()?,
                    nonce: 0,
                    signing_public_key: FullPublicKey(
                        pub_key_bytes
                            .clone()
                            .try_into()
                            .expect("Panjang kunci publik sudah divalidasi"),
                    ),
                    vrf_public_key: genesis_account
                        .vrf_public_key
                        .as_ref()
                        .map(|k| hex::decode(k).unwrap().try_into().unwrap())
                        .unwrap_or_default(),
                    bls_public_key: genesis_account
                        .bls_public_key
                        .as_ref()
                        .map(|k| hex::decode(k).unwrap()),
                    network_identity: genesis_account
                        .network_identity
                        .as_ref()
                        .and_then(|s| s.parse::<Multiaddr>().ok())
                        .map(|ma| ma.to_vec()),
                    network_identity_version: 0,
                    code_hash: None,
                    storage_root: None,
                    last_seen_block: 0,
                };

                if account.staked_amount > 0 {
                    self.validators.insert(derived_address);
                }

                let account_data = bincode::encode_to_vec(&account, bincode::config::standard())?;
                let hashed_key = hash_key(&derived_address);
                trie.insert(hashed_key.as_ref(), &account_data)?;
            }

            self.validators = self.validators.clone();
            self.state_root = *trie.root();
        }

        let mut db_ops: Vec<(ColumnId, Vec<u8>, Option<Vec<u8>>)> = Vec::new();
        for (key, (value, _rc)) in mem_db.drain() {
            db_ops.push((COL_TRIE, key.to_vec(), Some(value)));
        }

        let genesis_block = crate::blockchain::Block {
            header: crate::blockchain::BlockHeader {
                index: 0,
                timestamp: genesis.genesis_time.into(),
                prev_hash: vec![0; 32],
                state_root: self.state_root.as_ref().to_vec(),
                transactions_root: crate::blockchain::Block::calculate_transactions_root(&[]),
                l2_transactions_hash: None,
                authority: Address([0; ADDRESS_SIZE]),
                gas_used: 0,
                base_fee_per_gas: 10,
                signature: [0; crate::crypto::SIGNATURE_SIZE],
            },
            transactions: vec![],
            round: 0,
            view_number: 0,
            justify: QuorumCertificate::genesis_qc(),
            vrf_output: vec![],
            vrf_proof: vec![],
        };
        db_ops.push((
            COL_BLOCKS,
            0u64.to_be_bytes().to_vec(),
            Some(bincode::encode_to_vec(
                &genesis_block,
                bincode::config::standard(),
            )?),
        ));

        db_ops.push((
            COL_METADATA,
            VALIDATORS_KEY.to_vec(),
            Some(bincode::encode_to_vec(
                &self.validators,
                bincode::config::standard(),
            )?),
        ));
        db_ops.push((
            COL_METADATA,
            STATE_ROOT_KEY.to_vec(),
            Some(self.state_root.as_ref().to_vec()),
        ));
        db_ops.push((
            COL_STATE_JOURNAL,
            0u64.to_be_bytes().to_vec(),
            Some(self.state_root.as_ref().to_vec()),
        ));

        self.db.commit(db_ops)?;
        info!(
            "Inisialisasi dari genesis selesai. State root: {}",
            hex::encode(self.state_root.as_ref())
        );
        Ok(())
    }

    pub fn check_for_pending_upgrade(&self, current_height: u64) -> Option<UpgradeInfo> {
        if let Ok(Some(data)) = self.db.get(COL_METADATA, PENDING_UPGRADE_KEY) {
            if let Ok((info, _)) =
                bincode::decode_from_slice::<UpgradeInfo, _>(&data, bincode::config::standard())
            {
                if current_height >= info.activation_block_height {
                    return Some(info);
                }
            }
        }
        None
    }

    // pub fn invalidate_account_cache(&self, address: &Address) {
    //     let mut cache = self.account_cache.lock().unwrap();
    //     cache.pop(address);
    //     debug!("[CACHE] Membatalkan cache untuk akun: {}", address);
    // }
}

#[derive(Clone)]
pub struct TrieSession {
    backend: ParityDbTrieBackend,
    root: TrieRoot,
}

impl TrieSession {
    pub fn new(db: Arc<Db>, root: TrieRoot, col: ColumnId) -> Self {
        Self {
            backend: ParityDbTrieBackend::new(db, col),
            root,
        }
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<DBValue>, StateError> {
        let trie = TrieDBBuilder::<EviceTrieLayout>::new(&self.backend, &self.root).build();
        Ok(trie.get(key)?)
    }

    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        let new_root = {
            let mut trie = TrieDBMutBuilder::<EviceTrieLayout>::from_existing(
                &mut self.backend,
                &mut self.root,
            )
            .build();
            trie.insert(key, value)?;
            *trie.root()
        };
        self.root = new_root;
        Ok(())
    }

    pub fn get_account(&self, address: &Address) -> Result<Option<Account>, StateError> {
        let hashed_key = KeccakHasher::hash(address.as_ref());
        match self
            .get(hashed_key.as_ref())
            .map_err(|e| StateError::TrieError(format!("{:?}", e)))?
        {
            Some(encoded_account) => {
                let account: Account =
                    bincode::decode_from_slice(&encoded_account, bincode::config::standard())
                        .map(|(a, _)| a)?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    pub fn set_account(&mut self, address: &Address, account: &Account) -> Result<(), StateError> {
        let account_data =
            bincode::encode_to_vec(account, bincode::config::standard()).map_err(Box::new)?;
        let hashed_key = KeccakHasher::hash(address.as_ref());
        self.insert(hashed_key.as_ref(), &account_data)
            .map_err(|e| StateError::TrieError(format!("{:?}", e)))?;
        Ok(())
    }

    pub fn root(&self) -> &TrieRoot {
        &self.root
    }

    pub fn commit(mut self) -> Result<TrieRoot, StateError> {
        self.backend.commit_pending()?;
        Ok(self.root)
    }

    pub fn rollback(mut self) {
        self.backend.rollback_pending();
    }

    pub fn backend_mut(&mut self) -> &mut ParityDbTrieBackend {
        &mut self.backend
    }

    pub fn set_root(&mut self, new_root: crate::state::TrieRoot) {
        self.root = new_root;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, SIGNATURE_SIZE};
    use tempfile::tempdir;

    fn create_test_tx(keys: &KeyPair, nonce: u64, data: TransactionData) -> Transaction {
        let mut tx = Transaction {
            sender: Address(keys.public_key_bytes()),
            data,
            nonce,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            signature: [0; SIGNATURE_SIZE],
        };
        let hash = tx.message_hash();
        tx.signature = keys.sign(&hash);
        tx
    }

    #[test]
    fn test_apply_transaction_increments_nonce() {
        let dir = tempdir().unwrap();
        let state = StateMachine::new(dir.path().to_str().unwrap()).unwrap();
        let user_keys = KeyPair::new();
        let user_account = Account::new(1000);

        let tx_data = TransactionData::Transfer {
            recipient: TREASURY_ADDRESS,
            amount: 100,
        };
        let tx = create_test_tx(&user_keys, 0, tx_data);

        let updated_account = state.apply_transaction(&tx, user_account).unwrap();

        assert_eq!(updated_account.nonce, 1);
        assert_eq!(updated_account.balance, 900);
    }

    #[test]
    fn test_bootstrap_genesis_state() {
        let dir = tempdir().unwrap();
        let mut state = StateMachine::new(dir.path()).unwrap();

        state
            .bootstrap_genesis_state()
            .expect("Bootstrap should succeed");

        assert_ne!(state.state_root, Default::default());
        assert_eq!(state.validators.len(), 3);
    }

    #[test]
    fn test_trie_session_operations() {
        let dir = tempdir().unwrap();
        let mut state = StateMachine::new(dir.path()).unwrap();
        state
            .bootstrap_genesis_state()
            .expect("Bootstrap should succeed");

        let mut session = state.create_trie_session();

        let test_address = Address([1; 32]);
        let test_account = Account::new(1000);

        session.set_account(&test_address, &test_account).unwrap();
        let retrieved = session.get_account(&test_address).unwrap().unwrap();

        assert_eq!(retrieved.balance, 1000);

        let new_root = session.commit().unwrap();
        assert_ne!(new_root, state.state_root);
    }
}
