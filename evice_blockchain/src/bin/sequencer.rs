// evice_blockchain/src/bin/sequencer.rs

use ark_bls12_377::Bls12_377;
use ark_groth16::Proof;
use blst::min_pk::SecretKey as BlsSecretKey;
use clap::Parser;
use evice_blockchain::{
    crypto,
    crypto::{public_key_to_address, KeyPair, ValidatorKeys, PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE},
    genesis::Genesis,
    keystore::Keystore,
    l2_circuit::{BatchSystemCircuit, BatchTxInfo, PoseidonMerkleTreeParams},
    rpc_client::RpcClient,
    serde_helpers, FullPublicKey, Leaf, MerkleTreeConfig, Transaction, TransactionData,
};
use log::{error, info, warn};
use merlin::Transcript;
use rand::RngCore;
use rpassword::read_password;
use schnorrkel::SecretKey as SchnorrkelSecretKey;
use sha2::Digest;
use std::collections::HashMap;
use std::fs::{self, File};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::time::interval;

use ark_bls12_377::Fr;
use ark_crypto_primitives::{
    crh::CRHScheme,
    merkle_tree::{Config, MerkleTree, Path},
};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use actix_web::{error, post, web, App, HttpResponse, HttpServer, Responder};
use actix_web_ratelimit::{config::RateLimitConfig, store::MemoryStore, RateLimit};
use bincode::config;

const L2_CHAIN_ID: u64 = 77;

#[derive(Parser, Debug)]
#[clap(name = "sequencer-cli")]
struct Cli {
    #[clap(long, default_value = "http://127.0.0.1:8080")]
    l1_rpc_url: String,
    #[clap(long, default_value = "127.0.0.1:8081")]
    l2_listen_addr: String,
    #[clap(long)]
    keystore_path: String,
    #[clap(long)]
    vrf_private_key: String,
    #[clap(long, default_value = "./proving_key.bin")]
    proving_key_path: String,
    #[clap(
        long,
        help = "Pasangan kunci (public:private) anggota DAC dalam format hex, dipisahkan koma.",
        use_value_delimiter = true
    )]
    dac_keypairs: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct L2Transaction {
    from: String,
    to: String,
    amount: u64,
    nonce: u64,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    signature: String,
}

impl L2Transaction {
    fn message_hash(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&L2_CHAIN_ID.to_be_bytes());
        data.extend_from_slice(self.from.as_bytes());
        data.extend_from_slice(self.to.as_bytes());
        data.extend_from_slice(&self.amount.to_be_bytes());
        data.extend_from_slice(&self.nonce.to_be_bytes());
        data.extend_from_slice(&self.max_fee_per_gas.to_be_bytes());
        data.extend_from_slice(&self.max_priority_fee_per_gas.to_be_bytes());
        sha2::Sha256::digest(&data).to_vec()
    }
}

#[derive(Clone)]
struct SequencerState {
    l2_transactions: Arc<Mutex<Vec<L2Transaction>>>,
    l2_state: Arc<Mutex<L2State>>,
    poseidon_params: Arc<PoseidonMerkleTreeParams>,
    pending_proof_for_aggregation: Arc<Mutex<Option<(Proof<Bls12_377>, Vec<Fr>)>>>,
}

struct L2State {
    merkle_tree: MerkleTree<MerkleTreeConfig>,
    account_map: HashMap<String, usize>,
    leaves: Vec<Leaf>,
}

#[post("/l2_sendTransaction")]
async fn l2_send_transaction(
    state: web::Data<SequencerState>,
    tx: web::Json<L2Transaction>,
) -> Result<impl Responder, error::Error> {
    let l2_tx = tx.into_inner();
    info!(
        "L2_RPC: Menerima transaksi: dari {} ke {} sejumlah {}",
        l2_tx.from, l2_tx.to, l2_tx.amount
    );

    let from_bytes_result = hex::decode(&l2_tx.from);
    let pub_key_bytes = match from_bytes_result {
        Ok(bytes) if bytes.len() == PUBLIC_KEY_SIZE => bytes,
        _ => {
            return Err(error::ErrorBadRequest(
                "Format atau panjang public key 'from' tidak valid.",
            ))
        }
    };

    let signature_bytes = hex::decode(&l2_tx.signature)
        .map_err(|_| error::ErrorBadRequest("Format signature tidak valid."))?;

    let full_pub_key_array: [u8; PUBLIC_KEY_SIZE] = pub_key_bytes
        .try_into()
        .map_err(|_| error::ErrorInternalServerError("Gagal mengonversi kunci publik."))?;
    let full_pub_key = FullPublicKey(full_pub_key_array);

    if !crypto::verify(&full_pub_key, &l2_tx.message_hash(), &signature_bytes) {
        warn!("L2_RPC: Tanda tangan transaksi L2 tidak valid!");
        return Err(error::ErrorUnauthorized("Tanda tangan tidak valid."));
    }

    let mut transactions_guard = state
        .l2_transactions
        .lock()
        .map_err(|_| error::ErrorInternalServerError("Gagal mengunci mempool L2."))?;
    transactions_guard.push(l2_tx);

    Ok(HttpResponse::Ok().json("Transaksi L2 diterima dan valid"))
}

#[serde_as]
#[derive(Serialize, Deserialize)]
struct MerkleProofResponse {
    #[serde_as(as = "serde_helpers::ArkFrArray<2>")]
    pub leaf_data: Leaf,
    #[serde_as(as = "serde_helpers::ArkPath")]
    pub merkle_path: Path<MerkleTreeConfig>,
}

#[post("/l2_getMerkleProof")]
async fn l2_get_merkle_proof(
    state: web::Data<SequencerState>,
    params: web::Json<(String, String)>,
) -> Result<impl Responder, error::Error> {
    let (address_hex, l2_root_hex) = params.into_inner();
    info!(
        "L2_RPC: Permintaan bukti merkle untuk alamat {} pada root {}",
        address_hex, l2_root_hex
    );

    let l2_state = state.l2_state.lock().unwrap();

    let current_root_bytes = l2_state.merkle_tree.root().into_bigint().to_bytes_be();
    if hex::encode(&current_root_bytes) != l2_root_hex {
        return Err(error::ErrorBadRequest(
            "State root L2 tidak cocok atau sudah usang.",
        ));
    }

    if let Some(index) = l2_state.account_map.get(&address_hex) {
        let leaf_data = l2_state.leaves[*index];
        let merkle_path = l2_state.merkle_tree.generate_proof(*index).map_err(|e| {
            error::ErrorInternalServerError(format!("Gagal membuat bukti Merkle: {}", e))
        })?;

        Ok(HttpResponse::Ok().json(MerkleProofResponse {
            leaf_data,
            merkle_path,
        }))
    } else {
        Err(error::ErrorNotFound("Alamat tidak ditemukan di state L2."))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let cli = Cli::parse();

    let genesis = Genesis::from_file("genesis.json").map_err(|e| {
        format!(
            "Gagal memuat genesis.json: {}. Pastikan file ada di direktori yang sama.",
            e
        )
    })?;
    let chain_id = genesis.chain_id;
    info!(
        "SEQUENCER: Berjalan di jaringan dengan chain_id: {}",
        chain_id
    );

    if cli.dac_keypairs.is_empty() {
        return Err("Diperlukan setidaknya satu pasangan kunci DAC (`--dac-keypairs`)".into());
    }
    let dac_keypairs: Vec<KeyPair> = cli
        .dac_keypairs
        .iter()
        .map(|kp_str| {
            let parts: Vec<&str> = kp_str.split(':').collect();
            if parts.len() != 2 {
                return Err(
                    "Format pasangan kunci DAC tidak valid. Gunakan 'publicKeyHex:privateKeyHex'"
                        .into(),
                );
            }
            let pk_hex = parts[0];
            let sk_hex = parts[1];

            let pk_bytes =
                hex::decode(pk_hex).map_err(|e| format!("Kunci publik DAC tidak valid: {}", e))?;
            let sk_bytes =
                hex::decode(sk_hex).map_err(|e| format!("Kunci privat DAC tidak valid: {}", e))?;

            if pk_bytes.len() != PUBLIC_KEY_SIZE || sk_bytes.len() != PRIVATE_KEY_SIZE {
                return Err(format!(
                    "Panjang kunci DAC tidak valid. Publik: {}/{}, Privat: {}/{}",
                    pk_bytes.len(),
                    PUBLIC_KEY_SIZE,
                    sk_bytes.len(),
                    PRIVATE_KEY_SIZE
                )
                .into());
            }

            KeyPair::from_key_bytes(&pk_bytes, &sk_bytes).map_err(|e| e.into())
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    info!(
        "SEQUENCER: Berhasil memuat {} pasangan kunci anggota DAC.",
        dac_keypairs.len()
    );

    let keystore = Keystore::from_path(&cli.keystore_path)?;
    println!(
        "🔒 Masukkan kata sandi untuk keystore sequencer '{}':",
        cli.keystore_path
    );
    let password = read_password()?;
    let private_key_bytes = keystore.decrypt(&password)?;
    let pub_key_bytes = hex::decode(&keystore.public_key)?;

    let signing_keys = KeyPair::from_key_bytes(&pub_key_bytes, &private_key_bytes)?;
    let sequencer_address = public_key_to_address(&signing_keys.public_key_bytes());
    info!(
        "SEQUENCER: Berjalan dengan alamat: 0x{}",
        hex::encode(sequencer_address.as_ref())
    );

    let vrf_secret_bytes = hex::decode(&cli.vrf_private_key)?;
    let vrf_secret = SchnorrkelSecretKey::from_bytes(&vrf_secret_bytes)
        .map_err(|_| "Kunci privat VRF tidak valid. Pastikan panjangnya 64-byte.")?;
    let vrf_keys = vrf_secret.to_keypair();

    let mut ikm = [0u8; 32];
    rand::rng().fill_bytes(&mut ikm);
    let bls_secret_key = BlsSecretKey::key_gen(&ikm, &[]).unwrap();

    let sequencer_keys = Arc::new(ValidatorKeys {
        signing_keys,
        vrf_keys,
        bls_secret_key,
    });

    let params_file = File::open("./poseidon_params.bin")
        .map_err(|_| format!("Gagal membuka file parameter Poseidon di: ./poseidon_params.bin"))?;
    let poseidon_params_loaded = Arc::new(PoseidonMerkleTreeParams::deserialize_uncompressed(
        params_file,
    )?);

    let initial_leaves: Vec<Leaf> = vec![];

    let initial_leaf_digests: Vec<_> = initial_leaves
        .iter()
        .map(|leaf| {
            <MerkleTreeConfig as Config>::LeafHash::evaluate(
                &poseidon_params_loaded.leaf_crh_params,
                leaf,
            )
        })
        .collect::<Result<_, _>>()?;

    let initial_tree = MerkleTree::<MerkleTreeConfig>::new_with_leaf_digest(
        &poseidon_params_loaded.leaf_crh_params,
        &poseidon_params_loaded.two_to_one_crh_params,
        initial_leaf_digests,
    )?;

    let l2_state = Arc::new(Mutex::new(L2State {
        merkle_tree: initial_tree,
        account_map: HashMap::new(),
        leaves: initial_leaves,
    }));

    let sequencer_state = SequencerState {
        l2_transactions: Arc::new(Mutex::new(Vec::new())),
        l2_state,
        poseidon_params: poseidon_params_loaded,
        pending_proof_for_aggregation: Arc::new(Mutex::new(None)),
    };

    let state_for_server = web::Data::new(sequencer_state.clone());
    let l2_listen_addr = cli.l2_listen_addr.clone();

    let store = Arc::new(MemoryStore::new());

    tokio::spawn(async move {
        info!(
            "SEQUENCER: Menjalankan server RPC L2 di http://{}",
            l2_listen_addr
        );

        HttpServer::new(move || {
            let config = RateLimitConfig::default().max_requests(500).window_secs(60);

            let ratelimiter = RateLimit::new(config, store.clone());
            App::new()
                .wrap(ratelimiter)
                .app_data(state_for_server.clone())
                .service(l2_send_transaction)
                .service(l2_get_merkle_proof)
        })
        .bind(&l2_listen_addr)
        .unwrap_or_else(|e| {
            panic!(
                "Gagal melakukan bind ke alamat L2 {}: {}",
                l2_listen_addr, e
            );
        })
        .run()
        .await
    });

    info!("SEQUENCER: Loop utama dimulai, menunggu interval batch...");
    let mut l1_rpc_client =
        RpcClient::new(cli.l1_rpc_url.clone(), cli.l2_listen_addr.clone()).await?;
    let mut batch_interval = interval(Duration::from_secs(30));

    loop {
        batch_interval.tick().await;

        let last_l1_block = match l1_rpc_client.get_block_by_index(u64::MAX).await {
            Ok(block) => block,
            Err(e) => {
                error!("SEQUENCER: Tidak dapat mengambil blok L1 terakhir dari RPC: {}. Melewati ronde ini.", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        let last_l1_hash = last_l1_block.header.calculate_hash();

        let chain_snapshot = match l1_rpc_client.get_l1_chain_snapshot().await {
            Ok(snapshot) => snapshot,
            Err(e) => {
                error!(
                    "SEQUENCER: Gagal mendapatkan snapshot state L1: {}. Melewati ronde.",
                    e
                );
                continue;
            }
        };

        use evice_blockchain::sequencer_selection::{SequencerSelector, StakeWeightedVrfSelector};
        let selector = StakeWeightedVrfSelector;
        let selection_material = last_l1_hash.clone();

        let leader = match selector.select_leader(&chain_snapshot, &selection_material) {
            Some(addr) => addr,
            None => {
                info!("SEQUENCER: Tidak ada sequencer aktif yang bisa dipilih. Melewati ronde.");
                continue;
            }
        };

        let i_am_leader = leader == sequencer_address;
        let mut should_i_act = i_am_leader;

        if !i_am_leader {
            info!(
                "SEQUENCER: Bukan giliran saya. Pemimpin terpilih: 0x{}",
                hex::encode(leader.as_ref())
            );
            const L1_BLOCK_TOLERANCE: u64 = 5;

            let last_batch_block = chain_snapshot.last_l2_batch_l1_block;
            let current_l1_block = last_l1_block.header.index;

            if last_batch_block > 0 {
                let blocks_since_last_batch = current_l1_block.saturating_sub(last_batch_block);

                if blocks_since_last_batch >= L1_BLOCK_TOLERANCE {
                    warn!(
                        "SEQUENCER: Pemimpin 0x{} tampaknya tidak aktif. Sudah {} blok L1 sejak batch terakhir (di blok #{}). Mencoba mengambil alih!",
                        hex::encode(leader.as_ref()),
                        blocks_since_last_batch,
                        last_batch_block
                    );
                    should_i_act = true;
                } else {
                    info!(
                        "SEQUENCER: Memantau pemimpin. {} blok L1 telah berlalu sejak batch terakhir (toleransi: {}).",
                        blocks_since_last_batch, L1_BLOCK_TOLERANCE
                    );
                }
            }
        }

        if !should_i_act {
            continue;
        }

        if i_am_leader {
            info!("SEQUENCER: Terpilih sebagai pemimpin batch L2 berdasarkan stake-weighted VRF!");
        }

        let mut transcript = Transcript::new(b"EVICE_L2_SEQUENCER_ELECTION_STAKE_WEIGHTED");
        transcript.append_message(b"selection_material", &selection_material);
        transcript.append_message(b"candidate_addr", sequencer_address.as_ref());

        let (vrf_in_out, vrf_proof, _) = sequencer_keys.vrf_keys.vrf_sign(transcript);

        let l2_txs_to_process = {
            let mut txs = sequencer_state.l2_transactions.lock().unwrap();
            if txs.is_empty() {
                info!("SEQUENCER: Tidak ada transaksi L2 untuk diproses.");
                continue;
            }

            txs.sort_by(|a, b| b.max_priority_fee_per_gas.cmp(&a.max_priority_fee_per_gas));
            info!(
                "SEQUENCER: Mengurutkan {} txs berdasarkan tip prioritas.",
                txs.len()
            );

            const BATCH_SIZE_LIMIT: usize = 100;
            let num_to_take = std::cmp::min(txs.len(), BATCH_SIZE_LIMIT);
            txs.drain(..num_to_take).collect::<Vec<_>>()
        };

        info!(
            "SEQUENCER: Memproses {} transaksi L2 dengan prioritas tertinggi dalam satu batch.",
            l2_txs_to_process.len()
        );

        let (initial_root_fr, final_root_fr, circuit_input) = {
            let mut l2_state = sequencer_state.l2_state.lock().unwrap();
            let initial_root = l2_state.merkle_tree.root();

            let mut batch_tx_infos = Vec::new();
            let initial_leaves_clone = l2_state.leaves.clone();

            let mut temp_leaves = l2_state.leaves.clone();
            let mut temp_account_map = l2_state.account_map.clone();

            let mut current_root_fr = initial_root;

            for tx in &l2_txs_to_process {
                let sender_pubkey_bytes = hex::decode(&tx.from).unwrap();
                let sender_pubkey_fr = Fr::from_be_bytes_mod_order(&sender_pubkey_bytes[..32]);
                let recipient_pubkey_bytes = hex::decode(&tx.to).unwrap();
                let recipient_pubkey_fr =
                    Fr::from_be_bytes_mod_order(&recipient_pubkey_bytes[..32]);

                let sender_idx = *temp_account_map.entry(tx.from.clone()).or_insert_with(|| {
                    let new_idx = temp_leaves.len();
                    temp_leaves.push([sender_pubkey_fr, Fr::from(1_000_000_u64)]);
                    new_idx
                });

                let recipient_idx = *temp_account_map.entry(tx.to.clone()).or_insert_with(|| {
                    let new_idx = temp_leaves.len();
                    temp_leaves.push([recipient_pubkey_fr, Fr::from(0u64)]);
                    new_idx
                });

                let amount_fr = Fr::from(tx.amount);
                if temp_leaves[sender_idx][1] < amount_fr {
                    warn!(
                        "SEQUENCER: Saldo tidak cukup untuk tx dari {}. Dilewati.",
                        tx.from
                    );
                    continue;
                }

                let temp_leaf_digests: Vec<_> = temp_leaves
                    .iter()
                    .map(|leaf| {
                        <MerkleTreeConfig as Config>::LeafHash::evaluate(
                            &sequencer_state.poseidon_params.leaf_crh_params,
                            leaf,
                        )
                    })
                    .collect::<Result<_, _>>()?;
                let current_tree_for_proof = MerkleTree::<MerkleTreeConfig>::new_with_leaf_digest(
                    &sequencer_state.poseidon_params.leaf_crh_params,
                    &sequencer_state.poseidon_params.two_to_one_crh_params,
                    temp_leaf_digests,
                )?;
                assert_eq!(
                    current_tree_for_proof.root(),
                    current_root_fr,
                    "Root sebelum transaksi tidak konsisten"
                );

                let sender_path = current_tree_for_proof.generate_proof(sender_idx)?;
                let recipient_path = current_tree_for_proof.generate_proof(recipient_idx)?;

                temp_leaves[sender_idx][1] -= &amount_fr;
                temp_leaves[recipient_idx][1] += &amount_fr;

                let temp_leaf_digests_2: Vec<_> = temp_leaves
                    .iter()
                    .map(|leaf| {
                        <MerkleTreeConfig as Config>::LeafHash::evaluate(
                            &sequencer_state.poseidon_params.leaf_crh_params,
                            leaf,
                        )
                    })
                    .collect::<Result<_, _>>()?;
                let new_tree = MerkleTree::<MerkleTreeConfig>::new_with_leaf_digest(
                    &sequencer_state.poseidon_params.leaf_crh_params,
                    &sequencer_state.poseidon_params.two_to_one_crh_params,
                    temp_leaf_digests_2,
                )?;
                let new_root_fr = new_tree.root();

                batch_tx_infos.push(BatchTxInfo {
                    amount: amount_fr,
                    sender_leaf_index: sender_idx as u32,
                    recipient_leaf_index: recipient_idx as u32,
                    sender_path,
                    recipient_path,
                });

                current_root_fr = new_root_fr;
            }

            l2_state.leaves = temp_leaves;
            l2_state.account_map = temp_account_map;

            let final_leaf_digests: Vec<_> = l2_state
                .leaves
                .iter()
                .map(|leaf| {
                    <MerkleTreeConfig as Config>::LeafHash::evaluate(
                        &sequencer_state.poseidon_params.leaf_crh_params,
                        leaf,
                    )
                })
                .collect::<Result<_, _>>()?;
            l2_state.merkle_tree = MerkleTree::<MerkleTreeConfig>::new_with_leaf_digest(
                &sequencer_state.poseidon_params.leaf_crh_params,
                &sequencer_state.poseidon_params.two_to_one_crh_params,
                final_leaf_digests,
            )?;
            let final_root = l2_state.merkle_tree.root();
            assert_eq!(
                final_root, current_root_fr,
                "Root final tidak konsisten setelah semua transaksi"
            );

            let circuit = BatchSystemCircuit {
                initial_root,
                final_root,
                transactions: batch_tx_infos,
                initial_leaves: initial_leaves_clone,
                leaf_crh_params: sequencer_state.poseidon_params.leaf_crh_params.clone(),
                two_to_one_crh_params: sequencer_state
                    .poseidon_params
                    .two_to_one_crh_params
                    .clone(),
            };
            (initial_root, final_root, circuit)
        };

        let mut circuit_data_bytes = Vec::new();
        circuit_input.serialize_uncompressed(&mut circuit_data_bytes)?;
        let circuit_data_hex = hex::encode(circuit_data_bytes);

        let prover_task = {
            let pk_path = cli.proving_key_path.clone();
            move || {
                info!("PROVER_TASK: Memulai pembuatan bukti ZK di thread terpisah...");
                Command::new("cargo")
                    .args(&[
                        "run",
                        "--bin",
                        "prover",
                        "--release",
                        "--",
                        "--proving-key-path",
                        &pk_path,
                        "--circuit-data-hex",
                        &circuit_data_hex,
                    ])
                    .output()
            }
        };

        let prover_output = match tokio::task::spawn_blocking(prover_task).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                error!("SEQUENCER: Prover task I/O error: {}", e);
                continue;
            }
            Err(e) => {
                error!("SEQUENCER: Gagal menjalankan prover task (panic?): {}", e);
                continue;
            }
        };

        if !prover_output.status.success() {
            error!(
                "SEQUENCER: Prover gagal dengan stderr: {}",
                String::from_utf8_lossy(&prover_output.stderr)
            );
            continue;
        }

        let proof_hex = String::from_utf8(prover_output.stdout)?.trim().to_string();
        if proof_hex.is_empty() {
            error!("SEQUENCER: Prover berhasil tetapi tidak menghasilkan output (proof).");
            continue;
        }

        let zk_proof = hex::decode(proof_hex)?;
        info!("SEQUENCER: Bukti ZK berhasil didapatkan dari prover.");

        let current_proof = Proof::<Bls12_377>::deserialize_uncompressed(&zk_proof[..])?;
        let current_public_inputs = vec![initial_root_fr, final_root_fr];

        let mut pending_proof_guard = sequencer_state
            .pending_proof_for_aggregation
            .lock()
            .unwrap();

        if let Some((first_proof, first_public_inputs)) = pending_proof_guard.take() {
            info!("SEQUENCER: Bukti kedua diterima. Memulai proses agregasi...");

            let mut proof1_file = NamedTempFile::new()?;
            first_proof.serialize_uncompressed(&mut proof1_file)?;

            let mut proof2_file = NamedTempFile::new()?;
            current_proof.serialize_uncompressed(&mut proof2_file)?;

            let inputs1_hex = format!(
                "0x{},0x{}",
                hex::encode(first_public_inputs[0].into_bigint().to_bytes_be()),
                hex::encode(first_public_inputs[1].into_bigint().to_bytes_be())
            );
            let inputs2_hex = format!(
                "0x{},0x{}",
                hex::encode(current_public_inputs[0].into_bigint().to_bytes_be()),
                hex::encode(current_public_inputs[1].into_bigint().to_bytes_be())
            );

            if first_public_inputs[1] != current_public_inputs[0] {
                error!("SEQUENCER: GAGAL AGREGASI! State root tidak cocok antara batch 1 dan 2.");
                *pending_proof_guard = None;
                continue;
            }

            info!("SEQUENCER: Memanggil aggregator subprocess...");
            let leaf_vk_path = cli
                .proving_key_path
                .replace("proving_key.bin", "verifying_key.bin");
            let output_proof_path = "./aggregated_proof.bin";
            let agg_output = Command::new("cargo")
                .args(&[
                    "run",
                    "--bin",
                    "aggregator",
                    "--release",
                    "--",
                    "aggregate",
                    "--leaf-vk-path",
                    &leaf_vk_path,
                    "--agg-pk-path",
                    "./agg_proving_key.bin",
                    "--agg-vk-path",
                    "./agg_verifying_key.bin",
                    "--proof1-path",
                    proof1_file.path().to_str().unwrap(),
                    "--inputs1-hex",
                    &inputs1_hex,
                    "--proof2-path",
                    proof2_file.path().to_str().unwrap(),
                    "--inputs2-hex",
                    &inputs2_hex,
                    "--output-proof-path",
                    output_proof_path,
                ])
                .output()?;

            if !agg_output.status.success() {
                error!(
                    "SEQUENCER: Subprocess aggregator gagal: {}",
                    String::from_utf8_lossy(&agg_output.stderr)
                );
                *pending_proof_guard = None;
                continue;
            }

            info!("SEQUENCER: Agregasi berhasil. Menyiapkan transaksi L1...");

            let aggregated_proof_bytes = fs::read(output_proof_path)?;
            let nonce = l1_rpc_client
                .get_l1_account_info(sequencer_address)
                .await?
                .nonce;

            let agg_data = TransactionData::SubmitAggregateRollupBatch {
                initial_state_root: first_public_inputs[0].into_bigint().to_bytes_be(),
                final_state_root: current_public_inputs[1].into_bigint().to_bytes_be(),
                aggregated_proof: aggregated_proof_bytes,
                num_batches: 2,
            };

            let mut tx = Transaction {
                sender_public_key: FullPublicKey(sequencer_keys.signing_keys.public_key_bytes()),
                data: agg_data,
                nonce,
                max_fee_per_gas: 30,
                max_priority_fee_per_gas: 3,
                signature: [0; evice_blockchain::crypto::SIGNATURE_SIZE],
                chain_id: chain_id.clone(),
            };
            tx.signature = sequencer_keys.signing_keys.sign(&tx.message_hash());

            if let Err(e) = l1_rpc_client.submit_l1_transaction(&tx).await {
                error!("SEQUENCER: Gagal mengirim BATCH AGREGAT ke L1: {}", e);
            } else {
                info!("SEQUENCER: BATCH AGREGAT berhasil dikirim ke L1 untuk finalisasi.");
            }
        } else {
            // KASUS 1: Ini adalah bukti pertama. Kirim sebagai batch tunggal untuk sekarang.
            // Di masa depan, logika ini bisa diubah untuk selalu menunggu.
            info!("SEQUENCER: Bukti pertama dibuat. Mengirim sebagai batch tunggal.");

            let nonce = l1_rpc_client
                .get_l1_account_info(sequencer_address)
                .await?
                .nonce;
            let compressed_batch_data =
                bincode::serde::encode_to_vec(&l2_txs_to_process, config::standard())?;

            let batch_data_hash = sha2::Sha256::digest(&compressed_batch_data);
            let mut dac_signatures = Vec::new();

            for keypair in &dac_keypairs {
                let signature = keypair.sign(&batch_data_hash);
                dac_signatures.push(signature);
            }

            info!(
                "SEQUENCER: Berhasil mengumpulkan {} tanda tangan DAC untuk batch tunggal.",
                dac_signatures.len()
            );

            let data = TransactionData::SubmitRollupBatch {
                old_state_root: initial_root_fr.into_bigint().to_bytes_be(),
                new_state_root: final_root_fr.into_bigint().to_bytes_be(),
                compressed_batch: compressed_batch_data,
                zk_proof,
                is_test_tx: false,
                vrf_output: vrf_in_out.to_preout().to_bytes().to_vec(),
                vrf_proof: vrf_proof.to_bytes().to_vec(),
                dac_signatures,
            };

            let mut tx = Transaction {
                sender_public_key: FullPublicKey(sequencer_keys.signing_keys.public_key_bytes()),
                data,
                nonce,
                max_fee_per_gas: 20,
                max_priority_fee_per_gas: 2,
                signature: [0; evice_blockchain::crypto::SIGNATURE_SIZE],
                chain_id: chain_id.clone(),
            };
            tx.signature = sequencer_keys.signing_keys.sign(&tx.message_hash());

            if let Err(e) = l1_rpc_client.submit_l1_transaction(&tx).await {
                error!("SEQUENCER: Gagal mengirim batch tunggal ke L1: {}", e);
            } else {
                info!("SEQUENCER: Batch tunggal berhasil dikirim ke L1 untuk finalisasi.");
            }
        }
    }
}
