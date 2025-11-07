// evice_blockchain/src/bin/faucet.rs

use actix_web::{
    error::ErrorInternalServerError, post, web, App, HttpResponse, HttpServer, Responder,
};
use actix_web_ratelimit::{config::RateLimitConfig, store::MemoryStore, RateLimit};
use clap::Parser;
use evice_blockchain::{
    crypto::{KeyPair, ADDRESS_SIZE, SIGNATURE_SIZE},
    genesis::Genesis,
    keystore::Keystore,
    rpc_client::RpcClient,
    Address, FullPublicKey, Transaction, TransactionData,
};
use serde::Deserialize;
use std::sync::{Arc, Mutex};

#[derive(Parser, Debug)]
#[clap(
    name = "faucet-service",
    about = "Menjalankan API service untuk Evice Testnet Faucet."
)]
struct Cli {
    #[clap(
        long,
        env = "EVICE_L1_RPC_URL",
        default_value = "https://127.0.0.1:8080"
    )]
    l1_rpc_url: String,

    #[clap(
        long,
        help = "Path ke keystore yang akan digunakan sebagai dompet faucet."
    )]
    keystore_path: String,

    #[clap(long, help = "Kata sandi untuk keystore faucet.")]
    password: String,

    #[clap(long, default_value = "127.0.0.1")]
    listen_addr: String,

    #[clap(long, default_value_t = 8001)]
    port: u16,

    #[clap(
        long,
        default_value_t = 100,
        help = "Jumlah token yang dikirim per permintaan."
    )]
    drip_amount: u64,
}

struct AppState {
    rpc_client: Arc<Mutex<RpcClient>>,
    faucet_keypair: KeyPair,
    faucet_public_key: FullPublicKey,
    chain_id: String,
    drip_amount: u64,
}

#[derive(Deserialize)]
struct FaucetRequest {
    address: String,
}

#[post("/api/v1/faucet/drip")]
async fn drip(state: web::Data<AppState>, req: web::Json<FaucetRequest>) -> impl Responder {
    let recipient_hex = req.address.trim_start_matches("0x");
    if recipient_hex.len() != ADDRESS_SIZE * 2 {
        return HttpResponse::BadRequest().body("Format alamat tidak valid.");
    }

    let mut recipient_bytes = [0u8; ADDRESS_SIZE];
    match hex::decode_to_slice(recipient_hex, &mut recipient_bytes) {
        Ok(_) => (),
        Err(_) => return HttpResponse::BadRequest().body("Alamat mengandung karakter non-hex."),
    };

    let recipient_address = Address(recipient_bytes);
    let mut rpc_client = state.rpc_client.lock().unwrap();

    let faucet_address =
        evice_blockchain::crypto::public_key_to_address(&state.faucet_public_key.0);

    // Dapatkan nonce terbaru untuk akun faucet
    let nonce = match rpc_client.get_l1_account_info(faucet_address).await {
        Ok(info) => info.nonce,
        Err(e) => {
            log::error!("Gagal mendapatkan info akun faucet: {}", e);
            return ErrorInternalServerError("Gagal berkomunikasi dengan node L1.").into();
        }
    };

    // Buat transaksi transfer
    let data = TransactionData::Transfer {
        recipient: recipient_address,
        amount: state.drip_amount,
    };

    let mut tx = Transaction {
        sender_public_key: state.faucet_public_key.clone(),
        data,
        nonce: nonce + 1, // Gunakan nonce selanjutnya
        max_fee_per_gas: 20,
        max_priority_fee_per_gas: 2,
        signature: [0; SIGNATURE_SIZE],
        chain_id: state.chain_id.clone(),
    };

    let data_to_sign_hash = tx.message_hash();
    tx.signature = state.faucet_keypair.sign(&data_to_sign_hash);

    // Kirim transaksi ke node L1
    match rpc_client.submit_l1_transaction(&tx).await {
        Ok(tx_hash) => {
            log::info!(
                "Faucet berhasil mengirimkan {} token ke 0x{} (Tx: {})",
                state.drip_amount,
                recipient_hex,
                tx_hash
            );
            HttpResponse::Ok().json(serde_json::json!({ "tx_hash": tx_hash }))
        }
        Err(e) => {
            log::error!("Gagal menyiarkan transaksi faucet: {}", e);
            ErrorInternalServerError("Gagal menyiarkan transaksi ke jaringan.").into()
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // Muat keystore faucet
    let keystore = Keystore::from_path(&cli.keystore_path)
        .expect("Gagal memuat keystore faucet. Pastikan path benar.");
    let private_key_bytes = keystore
        .decrypt(&cli.password)
        .expect("Kata sandi salah atau keystore corrupt.");
    let public_key_bytes =
        hex::decode(&keystore.public_key).expect("Kunci publik di keystore tidak valid.");

    let faucet_keypair = KeyPair::from_key_bytes(&public_key_bytes, &private_key_bytes)
        .expect("Gagal merekonstruksi keypair dari keystore.");
    let faucet_public_key = FullPublicKey(public_key_bytes.try_into().unwrap());

    // Muat genesis untuk mendapatkan chain_id
    let genesis = Genesis::from_file("genesis.json").expect("Gagal memuat genesis.json.");

    // Inisialisasi RPC Client
    let rpc_client = RpcClient::new(cli.l1_rpc_url.clone(), "".to_string())
        .await
        .unwrap_or_else(|e| panic!("Gagal terhubung ke node L1 di {}: {}", &cli.l1_rpc_url, e));

    let app_state = web::Data::new(AppState {
        rpc_client: Arc::new(Mutex::new(rpc_client)),
        faucet_keypair,
        faucet_public_key,
        chain_id: genesis.chain_id,
        drip_amount: cli.drip_amount,
    });

    // Konfigurasi Rate Limiting (1 permintaan per IP setiap 5 menit)
    let store = Arc::new(MemoryStore::new());
    let ratelimit_config = RateLimitConfig::default().max_requests(1).window_secs(300); // 5 menit

    let bind_addr = format!("{}:{}", cli.listen_addr, cli.port);
    log::info!("🚀 Evice Faucet Service berjalan di http://{}", bind_addr);

    HttpServer::new(move || {
        let ratelimiter = RateLimit::new(ratelimit_config.clone(), store.clone());
        App::new()
            .app_data(app_state.clone())
            .wrap(ratelimiter)
            .service(drip)
    })
    .bind(&bind_addr)?
    .run()
    .await
}

// Alat create_keystore untuk membuat dompet baru yang akan berfungsi sebagai dompet faucet
// target/debug/create_keystore --password "supersecretpassword"

// Server faucet di terminal terpisah yang mengarahkan ke keystore faucet
// RUST_LOG=info target/debug/faucet \
//    --keystore-path ./path/ke/keystore-faucet.json \
//    --password "supersecretpassword" \
//    --l1-rpc-url "https://127.0.0.1:8080"
