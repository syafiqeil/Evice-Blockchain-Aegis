// evice_blockchain/src/mempool.rs

use log::{debug, info, warn};
use lru::LruCache;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use crate::blockchain::Blockchain;
use crate::metrics::{MEMPOOL_ADD_RESULT, MEMPOOL_TRANSACTIONS};
use crate::state::StateMachine;
use crate::{crypto, Address, Transaction, TransactionData};

pub struct Mempool {
    transactions: Arc<Mutex<Vec<Transaction>>>,
    tx_hashes: Arc<Mutex<HashSet<Vec<u8>>>>,
    pending_nonces: Arc<Mutex<HashMap<Address, u64>>>,
    future_queue: Arc<Mutex<HashMap<Address, BTreeMap<u64, Transaction>>>>,
    peer_tx_counts: Arc<Mutex<HashMap<String, usize>>>,
    peer_last_seen: Arc<Mutex<HashMap<String, Instant>>>,
    verification_cache: Arc<Mutex<LruCache<Vec<u8>, bool>>>,
}

impl Clone for Mempool {
    fn clone(&self) -> Self {
        Self {
            transactions: Arc::new(Mutex::new(Vec::new())),
            tx_hashes: Arc::new(Mutex::new(HashSet::new())),
            pending_nonces: Arc::new(Mutex::new(HashMap::new())),
            future_queue: Arc::new(Mutex::new(HashMap::new())),
            peer_tx_counts: Arc::new(Mutex::new(HashMap::new())),
            peer_last_seen: Arc::new(Mutex::new(HashMap::new())),
            verification_cache: Arc::clone(&self.verification_cache),
        }
    }
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            transactions: Arc::new(Mutex::new(Vec::new())),
            tx_hashes: Arc::new(Mutex::new(HashSet::new())),
            pending_nonces: Arc::new(Mutex::new(HashMap::new())),
            future_queue: Arc::new(Mutex::new(HashMap::new())),
            peer_tx_counts: Arc::new(Mutex::new(HashMap::new())),
            peer_last_seen: Arc::new(Mutex::new(HashMap::new())),
            verification_cache: Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(500).unwrap(),
            ))),
        }
    }

    pub fn peek_transactions(&self, count: usize) -> Vec<Transaction> {
        let mut pool_clone = self.transactions.lock().unwrap().clone();

        pool_clone.sort_by(|a, b| {
            b.max_priority_fee_per_gas
                .cmp(&a.max_priority_fee_per_gas)
                .then_with(|| a.nonce.cmp(&b.nonce))
                .then_with(|| a.message_hash().cmp(&b.message_hash()))
        });

        pool_clone.into_iter().take(count).collect()
    }

    pub async fn add_transaction(
        &self,
        tx: Transaction,
        peer_id: &str,
        state: &StateMachine,
        blockchain: &Blockchain,
    ) -> Result<(), &'static str> {
        const MIN_PEER_INTERVAL_MS: u128 = 50;
        const MAX_TX_PER_PEER: usize = 100;

        {
            let mut last_seen = self.peer_last_seen.lock().unwrap();
            let now = Instant::now();
            if let Some(prev) = last_seen.get(peer_id) {
                if now.duration_since(*prev) < Duration::from_millis(MIN_PEER_INTERVAL_MS as u64) {
                    MEMPOOL_ADD_RESULT
                        .with_label_values(&["rate_limited"])
                        .inc();
                    return Err("Terlalu banyak transaksi dari peer yang sama dalam waktu singkat");
                }
            }
            last_seen.insert(peer_id.to_string(), now);

            let mut counts = self.peer_tx_counts.lock().unwrap();
            let c = counts.entry(peer_id.to_string()).or_insert(0);
            if *c >= MAX_TX_PER_PEER {
                MEMPOOL_ADD_RESULT
                    .with_label_values(&["peer_limit_reached"])
                    .inc();
                return Err("Batas transaksi per peer di mempool telah tercapai");
            }
            *c += 1;
        }

        const MAX_CONTRACT_CODE_SIZE: usize = 24 * 1024;
        const MAX_ROLLUP_BATCH_SIZE: usize = 128 * 1024;
        const MAX_CALL_DATA_SIZE: usize = 4 * 1024;

        match &tx.data {
            TransactionData::DeployContract { code } => {
                if code.len() > MAX_CONTRACT_CODE_SIZE {
                    return Err("Ukuran kode kontrak melebihi batas maksimum");
                }
            }
            TransactionData::SubmitRollupBatch {
                compressed_batch, ..
            } => {
                if compressed_batch.len() > MAX_ROLLUP_BATCH_SIZE {
                    return Err("Ukuran batch rollup melebihi batas maksimum");
                }
            }
            TransactionData::CallContract { call_data, .. } => {
                if call_data.len() > MAX_CALL_DATA_SIZE {
                    return Err("Ukuran call_data melebihi batas maksimum");
                }
            }
            _ => {}
        }

        let tx_hash = tx.message_hash();
        if self.tx_hashes.lock().unwrap().contains(&tx_hash) {
            MEMPOOL_ADD_RESULT.with_label_values(&["duplicate"]).inc();
            return Err("Transaksi duplikat");
        }

        let sender_address = tx.sender();
        let sender_account = state
            .get_account(&sender_address)
            .map_err(|_| "Gagal akses database untuk verifikasi")?
            .ok_or("Akun pengirim tidak ditemukan")?;

        let last_header = blockchain.chain.last().map(|b| &b.header);
        let base_fee_per_gas = last_header.map_or(crate::blockchain::INITIAL_BASE_FEE, |h| {
            blockchain.calculate_next_base_fee(h)
        });

        if tx.max_fee_per_gas < base_fee_per_gas {
            return Err("max_fee_per_gas lebih rendah dari base_fee blok saat ini");
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
            return Err("Saldo tidak cukup");
        }

        if !crypto::verify(&tx.sender_public_key, &tx.message_hash(), &tx.signature) {
            return Err("Tanda tangan tidak valid");
        }

        let mut pending_nonces = self.pending_nonces.lock().unwrap();
        let expected_nonce = *pending_nonces
            .get(&sender_address)
            .unwrap_or(&sender_account.nonce);

        if tx.nonce < expected_nonce {
            return Err("Nonce sudah usang (replay attack?)");
        }

        if tx.nonce > expected_nonce {
            let mut future = self.future_queue.lock().unwrap();
            let sender_queue = future.entry(sender_address).or_default();
            sender_queue.insert(tx.nonce, tx.clone());
            info!("MEMPOOL: Transaksi nonce {} dari {} dimasukkan ke future queue (menunggu nonce {}).", tx.nonce, sender_address, expected_nonce);
            return Ok(());
        }

        self.add_to_pool_and_promote_future(tx, &mut pending_nonces);
        Ok(())
    }

    fn add_to_pool_and_promote_future(
        &self,
        tx: Transaction,
        pending_nonces: &mut HashMap<Address, u64>,
    ) {
        let sender = tx.sender();
        let next_nonce = tx.nonce + 1;

        let tx_hash = tx.message_hash();
        self.transactions.lock().unwrap().push(tx);
        self.tx_hashes.lock().unwrap().insert(tx_hash);
        pending_nonces.insert(sender, next_nonce);
        MEMPOOL_TRANSACTIONS.inc();

        let mut future_queue = self.future_queue.lock().unwrap();
        if let Some(sender_queue) = future_queue.get_mut(&sender) {
            if let Some(next_tx) = sender_queue.remove(&next_nonce) {
                self.add_to_pool_and_promote_future(next_tx, pending_nonces);
            }
        }
    }

    pub fn get_transactions(&self, count: usize) -> Vec<Transaction> {
        let at_most;
        let mut to_return;

        {
            let pool = self.transactions.lock().unwrap();
            if pool.is_empty() {
                return Vec::new();
            }
            at_most = std::cmp::min(count, pool.len());
            to_return = pool.clone();
        }
        to_return.sort_by(|a, b| {
            b.max_priority_fee_per_gas
                .cmp(&a.max_priority_fee_per_gas)
                .then_with(|| a.nonce.cmp(&b.nonce))
                .then_with(|| a.message_hash().cmp(&b.message_hash()))
        });

        to_return.truncate(at_most);
        let to_return_hashes: HashSet<Vec<u8>> =
            to_return.iter().map(|tx| tx.message_hash()).collect();

        {
            let mut pool = self.transactions.lock().unwrap();
            let mut hashes = self.tx_hashes.lock().unwrap();

            pool.retain(|tx| !to_return_hashes.contains(&tx.message_hash()));
            for hash in to_return_hashes {
                hashes.remove(&hash);
            }
        }

        if !to_return.is_empty() {
            debug!(
                "MEMPOOL: Mengambil {} transaksi untuk blok baru.",
                to_return.len()
            );
        }
        to_return
    }

    pub fn remove_single_transaction(&self, tx_to_remove: &Transaction) {
        let tx_hash = tx_to_remove.message_hash();
        info!(
            "MEMPOOL: Menghapus transaksi beracun/tidak valid: {}",
            hex::encode(&tx_hash)
        );
        let mut pool = self.transactions.lock().unwrap();
        let mut hashes = self.tx_hashes.lock().unwrap();

        pool.retain(|tx| tx.message_hash() != tx_hash);
        hashes.remove(&tx_hash);
    }

    pub async fn add_from_p2p(
        &self,
        tx: Transaction,
        _state: &StateMachine,
    ) -> Result<(), &'static str> {
        if !crypto::verify(&tx.sender_public_key, &tx.message_hash(), &tx.signature) {
            warn!("MEMPOOL: Transaksi dari P2P ditolak, tanda tangan tidak valid.");
            return Err("Tanda tangan tidak valid");
        }

        let tx_hash = tx.message_hash();
        let mut hashes = self.tx_hashes.lock().unwrap();
        if hashes.contains(&tx_hash) {
            return Err("Transaksi duplikat");
        }

        let mut pool = self.transactions.lock().unwrap();
        pool.push(tx);
        hashes.insert(tx_hash);

        debug!(
            "MEMPOOL: Transaksi dari P2P ditambahkan. Total di mempool: {}",
            pool.len()
        );
        Ok(())
    }

    pub fn remove_transactions(&self, transactions_to_remove: &[Transaction]) {
        if transactions_to_remove.is_empty() {
            return;
        }
        let mut pool = self.transactions.lock().unwrap();
        let mut hashes = self.tx_hashes.lock().unwrap();

        let remove_hashes: HashSet<Vec<u8>> = transactions_to_remove
            .iter()
            .map(|tx| tx.message_hash())
            .collect();

        pool.retain(|tx| !remove_hashes.contains(&tx.message_hash()));
        for hash in remove_hashes {
            hashes.remove(&hash);
        }

        debug!(
            "MEMPOOL: {} transaksi yang terkonfirmasi telah dihapus. Sisa: {}",
            transactions_to_remove.len(),
            pool.len()
        );
    }

    pub fn remove_transactions_by_hash(&self, hashes_to_remove: &[Vec<u8>]) {
        if hashes_to_remove.is_empty() {
            return;
        }

        let remove_set: HashSet<_> = hashes_to_remove.iter().collect();

        let mut pool = self.transactions.lock().unwrap();
        let mut hashes = self.tx_hashes.lock().unwrap();

        pool.retain(|tx| !remove_set.contains(&tx.message_hash()));

        for hash in hashes_to_remove {
            hashes.remove(hash);
        }

        debug!(
            "MEMPOOL: {} transaksi tidak valid telah dihapus.",
            hashes_to_remove.len()
        );
    }

    pub fn revalidate_against_new_state(&self, state: &StateMachine) {
        let initial_count;
        let txs_to_check;

        {
            let pool = self.transactions.lock().unwrap();
            initial_count = pool.len();
            if initial_count == 0 {
                return;
            }
            txs_to_check = pool.clone();
        }

        let invalid_hashes: HashSet<Vec<u8>> = txs_to_check
            .into_iter()
            .filter_map(|tx| match state.get_account(&tx.sender()) {
                Ok(Some(account)) => {
                    if tx.nonce >= account.nonce {
                        None
                    } else {
                        warn!(
                            "MEMPOOL (Re-validation): Menandai transaksi basi dari {} (nonce: {})",
                            hex::encode(tx.sender().as_ref()),
                            tx.nonce
                        );
                        Some(tx.message_hash())
                    }
                }
                _ => {
                    warn!(
                        "MEMPOOL (Re-validation): Menandai tx karena akun {} tidak ditemukan.",
                        hex::encode(tx.sender().as_ref())
                    );
                    Some(tx.message_hash())
                }
            })
            .collect();

        if invalid_hashes.is_empty() {
            return;
        }

        let final_count;
        {
            let mut pool = self.transactions.lock().unwrap();
            let mut hashes = self.tx_hashes.lock().unwrap();
            pool.retain(|tx| !invalid_hashes.contains(&tx.message_hash()));
            for hash in invalid_hashes {
                hashes.remove(&hash);
            }
            final_count = pool.len();
        }

        if initial_count > final_count {
            info!(
                "MEMPOOL (Re-validation): {} transaksi basi berhasil dibersihkan.",
                initial_count - final_count
            );
        }
    }

    pub fn get_transaction_by_hash(&self, hash_to_find: &[u8]) -> Option<Transaction> {
        let pool = self.transactions.lock().unwrap();
        pool.iter()
            .find(|tx| tx.message_hash() == hash_to_find)
            .cloned()
    }

    pub fn get_all_hashes(&self) -> Vec<Vec<u8>> {
        let hashes = self.tx_hashes.lock().unwrap();
        hashes.iter().cloned().collect()
    }

    pub fn get_transactions_by_hashes(&self, hashes: &[Vec<u8>]) -> Vec<Transaction> {
        let pool = self.transactions.lock().unwrap();
        let hash_set: HashSet<_> = hashes.iter().collect();
        pool.iter()
            .filter(|tx| hash_set.contains(&tx.message_hash()))
            .cloned()
            .collect()
    }

    pub fn calculate_mempool_hash(&self) -> Vec<u8> {
        let mut hashes = self.get_all_hashes();
        if hashes.is_empty() {
            return vec![0; 32];
        }

        hashes.sort();

        let combined: Vec<u8> = hashes.into_iter().flatten().collect();

        Sha256::digest(&combined).to_vec()
    }

    pub fn clear(&self) {
        let mut pool = self.transactions.lock().unwrap();
        let mut hashes = self.tx_hashes.lock().unwrap();
        if !pool.is_empty() {
            warn!(
                "MEMPOOL: Membersihkan {} transaksi dari mempool untuk mengatasi divergensi.",
                pool.len()
            );
            pool.clear();
            hashes.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, ValidatorKeys, SIGNATURE_SIZE};
    use crate::state::{Account, StateMachine};
    use crate::{Address, TransactionData};
    use tempfile::tempdir;

    fn create_test_tx(
        sender_key: &KeyPair,
        recipient: Address,
        amount: u64,
        nonce: u64,
        fee: u64,
    ) -> Transaction {
        let data = TransactionData::Transfer { recipient, amount };
        let mut tx = Transaction {
            sender: Address(sender_key.public_key_bytes()),
            data,
            fee,
            nonce,
            signature: [0; SIGNATURE_SIZE],
        };
        let hash = tx.message_hash();
        tx.signature = sender_key.sign(&hash);
        tx
    }

    #[test]
    fn test_add_valid_transaction() {
        let dir = tempdir().unwrap();
        let state = StateMachine::new(dir.path().to_str().unwrap()).unwrap();
        let mempool = Mempool::new();

        let user1_keys = KeyPair::new();
        let user1_address = Address(user1_keys.public_key_bytes());
        let user2_address = Address(KeyPair::new().public_key_bytes());

        let user1_account = Account {
            balance: 1000,
            nonce: 0,
            staked_amount: 0,
            vrf_public_key: [0u8; 32],
        };
        state
            .db
            .put(
                user1_address.as_ref(),
                bincode::serialize(&user1_account).unwrap(),
            )
            .unwrap();

        let tx = create_test_tx(&user1_keys, user2_address, 100, 0, 10);

        let result = mempool.add_transaction(tx.clone(), &state);
        assert!(result.is_ok());
        assert_eq!(mempool.transactions.lock().unwrap().len(), 1);
    }
}
