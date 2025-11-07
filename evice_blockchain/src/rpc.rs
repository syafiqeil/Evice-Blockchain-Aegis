// evice_blockchain/src/rpc.rs

use crate::{
    blockchain::{Block, Blockchain, ChainMessage},
    mempool::Mempool,
    rpc::rpc_proto::{
        LatestBlocksRequest, LatestBlocksResponse, TransactionByHashRequest,
        TransactionByHashResponse, TxInclusionProofResponse, TxInclusionRequest,
    },
    snapshot,
    state::{COL_BLOCKS, COL_METADATA, COL_TX_LOOKUP, L2_LAST_BATCH_L1_BLOCK_KEY},
    Address, Transaction,
};
use bincode::{Decode, Encode};
use log::{error, info, warn};
use merkle_cbt::merkle_tree::Merge;
use merkle_cbt::CBMT;
use rpc_proto::{
    rpc_service_server::{RpcService, RpcServiceServer},
    AccountInfoRequest, AccountInfoResponse, BlockByIndexRequest, BlockByIndexResponse,
    ChainInfoRequest, ChainInfoResponse, ChainSnapshotRequest, ChainSnapshotResponse,
    CreateSnapshotRequest, CreateSnapshotResponse, L2StateRootRequest, L2StateRootResponse,
    TransactionRequest, TransactionResponse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tonic::{
    transport::{Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};

pub mod rpc_proto {
    tonic::include_proto!("rpc");
}

#[derive(Serialize, Deserialize, Encode, Decode)]
struct SerializableProof {
    indices: Vec<u32>,
    lemmas: Vec<[u8; 32]>,
}

struct Sha256Merge;

impl Merge for Sha256Merge {
    type Item = [u8; 32];

    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        let out = hasher.finalize();
        out.as_slice()
            .try_into()
            .expect("sha256 output is 32 bytes")
    }
}

#[derive(Serialize, Deserialize, Debug, Encode, Decode)]
pub struct RpcChainSnapshot {
    pub active_sequencers: HashSet<Address>,
    pub accounts: HashMap<Address, (u64, u64)>,
    pub last_l2_batch_l1_block: u64,
}

pub struct MyRpcServer {
    blockchain: Arc<RwLock<Blockchain>>,
    mempool: Arc<Mempool>,
    tx_p2p: mpsc::Sender<ChainMessage>,
    snapshot_dir: PathBuf,
}

#[tonic::async_trait]
impl RpcService for MyRpcServer {
    async fn submit_transaction(
        &self,
        request: Request<TransactionRequest>,
    ) -> Result<Response<TransactionResponse>, Status> {
        let req_data = request.into_inner();

        let transaction: Transaction = match bincode::decode_from_slice(
            &req_data.transaction_data,
            bincode::config::standard(),
        ) {
            Ok((tx, _)) => tx,
            Err(e) => {
                warn!("[gRPC] Deserialize transaction failed: {:?}", e);
                return Ok(Response::new(TransactionResponse {
                    success: false,
                    error_message: "Invalid transaction data format".to_string(),
                    transaction_hash: "".to_string(),
                }));
            }
        };

        let tx_hash = hex::encode(transaction.message_hash());

        let (state_clone, blockchain_clone) = {
            let chain = self.blockchain.read().await;
            (chain.state.clone(), (*chain).clone())
        };

        let mempool_result = self
            .mempool
            .add_transaction(
                transaction.clone(),
                "grpc_local",
                &state_clone,
                &blockchain_clone,
            )
            .await;

        match mempool_result {
            Ok(_) => {
                info!(
                    "[gRPC] Menerima transaksi valid {}, menyiarkan ke P2P.",
                    tx_hash
                );
                if self
                    .tx_p2p
                    .send(ChainMessage::NewTransaction(transaction))
                    .await
                    .is_err()
                {
                    error!("[gRPC] Gagal mengirim transaksi ke kanal P2P");
                }

                Ok(Response::new(TransactionResponse {
                    success: true,
                    error_message: "".to_string(),
                    transaction_hash: tx_hash,
                }))
            }
            Err(e) => {
                warn!("[gRPC] Menerima transaksi tidak valid: {}", e);
                Ok(Response::new(TransactionResponse {
                    success: false,
                    error_message: e.to_string(),
                    transaction_hash: "".to_string(),
                }))
            }
        }
    }

    async fn create_snapshot(
        &self,
        _request: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        info!("[gRPC] Menerima permintaan untuk membuat snapshot.");
        let chain = match self.blockchain.try_read() {
            Ok(guard) => guard,
            Err(_) => {
                let msg = "Server sibuk (blockchain terkunci), coba lagi nanti.".to_string();
                warn!("[gRPC] {}", msg);
                return Ok(Response::new(CreateSnapshotResponse {
                    success: false,
                    message: msg,
                }));
            }
        };

        let last_block = match chain.chain.last() {
            Some(b) => b,
            None => {
                let msg = "Blockchain kosong, tidak bisa membuat snapshot".to_string();
                warn!("[gRPC] {}", msg);
                return Ok(Response::new(CreateSnapshotResponse {
                    success: false,
                    message: msg,
                }));
            }
        };

        let height = last_block.header.index;
        let state_root = chain.state.state_root;
        let db_clone = Arc::clone(&chain.state.db);
        let snapshot_dir_clone = self.snapshot_dir.clone();

        tokio::task::spawn_blocking(move || {
            match snapshot::create_snapshot(db_clone, height, state_root, snapshot_dir_clone) {
                Ok(metadata) => info!(
                    "[Snapshot Task] Pembuatan snapshot berhasil dipicu untuk blok #{}",
                    metadata.height
                ),
                Err(e) => error!(
                    "[Snapshot Task] Gagal membuat snapshot di background: {:?}",
                    e
                ),
            }
        });

        let msg =
            "Permintaan pembuatan snapshot diterima dan sedang diproses di background.".to_string();
        Ok(Response::new(CreateSnapshotResponse {
            success: true,
            message: msg,
        }))
    }

    async fn get_chain_snapshot(
        &self,
        _request: Request<ChainSnapshotRequest>,
    ) -> Result<Response<ChainSnapshotResponse>, Status> {
        let chain = self.blockchain.read().await;

        let mut accounts_data = HashMap::new();
        let relevant_addresses: HashSet<_> = chain
            .state
            .validators
            .union(&chain.state.active_sequencers)
            .cloned()
            .collect();

        for address in relevant_addresses {
            if let Ok(Some(account)) = chain.state.get_account(&address) {
                accounts_data.insert(address, (account.balance, account.staked_amount));
            }
        }

        let last_l2_batch_l1_block = chain
            .state
            .db
            .get(COL_METADATA, L2_LAST_BATCH_L1_BLOCK_KEY)
            .unwrap_or(None)
            .map(|bytes| u64::from_be_bytes(bytes.try_into().unwrap_or([0; 8])))
            .unwrap_or(0);

        let snapshot = RpcChainSnapshot {
            active_sequencers: chain.state.active_sequencers.clone(),
            accounts: accounts_data,
            last_l2_batch_l1_block,
        };

        let snapshot_data = bincode::encode_to_vec(&snapshot, bincode::config::standard())
            .map_err(|e| Status::internal(format!("Failed to serialize snapshot: {}", e)))?;

        Ok(Response::new(ChainSnapshotResponse { snapshot_data }))
    }

    async fn get_account_info(
        &self,
        request: Request<AccountInfoRequest>,
    ) -> Result<Response<AccountInfoResponse>, Status> {
        let req_data = request.into_inner();
        let address_bytes: [u8; crate::crypto::ADDRESS_SIZE] = req_data
            .address
            .try_into()
            .map_err(|_| Status::invalid_argument("Address must be 20 bytes"))?;
        let address = Address(address_bytes);

        let block_hash_hex = req_data.block_hash.unwrap_or_else(|| "latest".to_string());

        let chain = self.blockchain.read().await;
        let account = if block_hash_hex == "latest" {
            chain
                .state
                .get_account(&address)
                .map_err(|e| Status::internal(e.to_string()))?
        } else {
            let block_hash = hex::decode(block_hash_hex)
                .map_err(|_| Status::invalid_argument("Invalid block hash format"))?;

            let mut speculative_chain = chain.speculative_chain.write().await;
            let session = speculative_chain
                .create_session_for_hash(&block_hash, &chain.state)
                .await
                .map_err(|e| Status::not_found(e.to_string()))?;

            session
                .get_account(&address)
                .map_err(|e| Status::internal(e.to_string()))?
        };

        let account = account.unwrap_or_default();

        Ok(Response::new(AccountInfoResponse {
            balance: account.balance,
            nonce: account.nonce,
        }))
    }

    async fn get_block_by_index(
        &self,
        request: Request<BlockByIndexRequest>,
    ) -> Result<Response<BlockByIndexResponse>, Status> {
        let req_data = request.into_inner();
        let index = req_data.index;

        let chain = self.blockchain.read().await;

        let block_to_get = if index == u64::MAX {
            chain.chain.last()
        } else {
            chain.chain.get(index as usize)
        };

        if let Some(block) = block_to_get {
            let block_data = bincode::encode_to_vec(block, bincode::config::standard())
                .map_err(|e| Status::internal(format!("Failed to serialize block: {}", e)))?;
            Ok(Response::new(BlockByIndexResponse { block_data }))
        } else {
            Err(Status::not_found(format!(
                "Block with index {} not found",
                index
            )))
        }
    }

    async fn get_l2_state_root(
        &self,
        _request: Request<L2StateRootRequest>,
    ) -> Result<Response<L2StateRootResponse>, Status> {
        let chain = self.blockchain.read().await;
        let l2_root = chain.state.l2_state_root.clone();

        Ok(Response::new(L2StateRootResponse {
            state_root: l2_root,
        }))
    }
    async fn get_latest_blocks(
        &self,
        request: Request<LatestBlocksRequest>,
    ) -> Result<Response<LatestBlocksResponse>, Status> {
        let count = request.into_inner().count as usize;
        let chain = self.blockchain.read().await;
        let blocks_to_send: Vec<Vec<u8>> = chain
            .chain
            .iter()
            .rev()
            .take(count)
            .filter_map(|block| bincode::encode_to_vec(block, bincode::config::standard()).ok())
            .collect();
        Ok(Response::new(LatestBlocksResponse {
            blocks: blocks_to_send,
        }))
    }

    async fn get_transaction_by_hash(
        &self,
        request: Request<TransactionByHashRequest>,
    ) -> Result<Response<TransactionByHashResponse>, Status> {
        let req_data = request.into_inner();
        let hash_to_find = match hex::decode(&req_data.hash_hex) {
            Ok(h) => h,
            Err(_) => return Err(Status::invalid_argument("Hash hex tidak valid")),
        };

        if let Some(tx) = self.mempool.get_transaction_by_hash(&hash_to_find) {
            let tx_data = bincode::encode_to_vec(&tx, bincode::config::standard()).unwrap();
            info!(
                "[gRPC] Transaksi 0x{} ditemukan di Mempool.",
                req_data.hash_hex
            );
            return Ok(Response::new(TransactionByHashResponse {
                transaction_data: tx_data,
                block_height: None,
            }));
        }

        let chain = self.blockchain.read().await;
        if let Ok(Some(block_index_bytes)) = chain.state.db.get(COL_TX_LOOKUP, &hash_to_find) {
            let block_height = u64::from_be_bytes(block_index_bytes.try_into().unwrap());

            if let Ok(Some(block_bytes)) =
                chain.state.db.get(COL_BLOCKS, &block_height.to_be_bytes())
            {
                if let Ok((block, _)) = bincode::decode_from_slice::<Block, _>(
                    &block_bytes,
                    bincode::config::standard(),
                ) {
                    if let Some(tx) = block
                        .transactions
                        .iter()
                        .find(|t| t.message_hash() == hash_to_find)
                    {
                        let tx_data =
                            bincode::encode_to_vec(tx, bincode::config::standard()).unwrap();
                        info!(
                            "[gRPC] Transaksi 0x{} ditemukan di Blok #{}.",
                            req_data.hash_hex, block_height
                        );
                        return Ok(Response::new(TransactionByHashResponse {
                            transaction_data: tx_data,
                            block_height: Some(block_height),
                        }));
                    }
                }
            }
        }

        info!("[gRPC] Transaksi 0x{} tidak ditemukan.", req_data.hash_hex);
        Err(Status::not_found("Transaksi tidak ditemukan"))
    }

    async fn get_transaction_inclusion_proof(
        &self,
        request: Request<TxInclusionRequest>,
    ) -> Result<Response<TxInclusionProofResponse>, Status> {
        let tx_hash = request.into_inner().transaction_hash;
        let chain = self.blockchain.read().await;

        let block_index_bytes = match chain.state.db.get(COL_TX_LOOKUP, &tx_hash) {
            Ok(Some(bytes)) => bytes,
            _ => {
                return Ok(Response::new(TxInclusionProofResponse {
                    found: false,
                    ..Default::default()
                }))
            }
        };
        let block_index = u64::from_be_bytes(block_index_bytes.try_into().unwrap());

        let block = match chain.chain.get(block_index as usize) {
            Some(b) => b,
            None => return Err(Status::internal("Indeks ditemukan tapi blok tidak ada")),
        };

        let tx_position = match block
            .transactions
            .iter()
            .position(|tx| tx.message_hash() == tx_hash)
        {
            Some(pos) => pos,
            None => {
                return Err(Status::internal(
                    "Indeks menunjuk ke blok, tapi tx tidak ditemukan di dalamnya",
                ))
            }
        };

        let tx_hashes: Vec<Vec<u8>> = block
            .transactions
            .iter()
            .map(|tx| tx.message_hash())
            .collect();

        let leaves: Vec<[u8; 32]> = tx_hashes
            .into_iter()
            .map(|h| {
                h.try_into().unwrap_or_else(|v: Vec<u8>| {
                    panic!("Expected a Vec of length 32 but it was {}", v.len())
                })
            })
            .collect();

        if leaves.is_empty() {
            return Err(Status::internal(
                "Blok tidak memiliki transaksi (tidak ada leaf)",
            ));
        }

        let leaf_index_u32 = tx_position as u32;

        let proof = CBMT::<[u8; 32], Sha256Merge>::build_merkle_proof(&leaves, &[leaf_index_u32])
            .ok_or_else(|| Status::internal("Gagal membuat merkle proof"))?;

        let indices = proof.indices().to_vec();
        let lemmas = proof.lemmas().to_vec();

        let serializable_proof = SerializableProof { indices, lemmas };

        let proof_bytes = bincode::encode_to_vec(&serializable_proof, bincode::config::standard())
            .map_err(|e| Status::internal(format!("Gagal serialize proof: {}", e)))?;

        let tx_data = bincode::encode_to_vec(
            &block.transactions[tx_position],
            bincode::config::standard(),
        )
        .unwrap();

        Ok(Response::new(TxInclusionProofResponse {
            found: true,
            block_index,
            block_hash: block.header.calculate_hash(),
            merkle_path: proof_bytes,
            transaction_data: tx_data,
        }))
    }

    async fn get_chain_info(
        &self,
        _request: Request<ChainInfoRequest>,
    ) -> Result<Response<ChainInfoResponse>, Status> {
        let chain = self.blockchain.read().await;
        let last_block = chain.chain.last();

        let height = last_block.map_or(0, |b| b.header.index);
        let best_block_hash = last_block.map_or(vec![0; 32], |b| b.header.calculate_hash());

        Ok(Response::new(ChainInfoResponse {
            height,
            best_block_hash,
        }))
    }
}

pub async fn run(
    blockchain: Arc<RwLock<Blockchain>>,
    mempool: Arc<Mempool>,
    tx_p2p: mpsc::Sender<ChainMessage>,
    port: u16,
    snapshot_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("0.0.0.0:{}", port).parse()?;
    let rpc_server = MyRpcServer {
        blockchain,
        mempool,
        tx_p2p,
        snapshot_dir,
    };

    info!("Menjalankan server gRPC di https://{}", addr);

    let cert = tokio::fs::read("cert.pem").await.map_err(|e| {
        format!(
            "Gagal membaca cert.pem: {}. Jalankan openssl untuk membuatnya.",
            e
        )
    })?;
    let key = tokio::fs::read("key.pem").await.map_err(|e| {
        format!(
            "Gagal membaca key.pem: {}. Jalankan openssl untuk membuatnya.",
            e
        )
    })?;
    let identity = Identity::from_pem(cert, key);
    let tls_config = ServerTlsConfig::new().identity(identity);

    Server::builder()
        .tls_config(tls_config)?
        .add_service(RpcServiceServer::new(rpc_server))
        .serve(addr)
        .await?;

    Ok(())
}
