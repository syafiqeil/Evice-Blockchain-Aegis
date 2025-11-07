// evice_blockchain/src/bin/wallet_generator.rs

use actix_web::{
    error::ErrorInternalServerError, get, post, web, App, HttpResponse, HttpServer, Responder,
};
use clap::Parser;
use evice_blockchain::{
    crypto::{public_key_to_address, PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE},
    rpc_client::RpcClient,
};
use serde::{Deserialize, Serialize};

// --- MODUL 1: CORE LOGIC ---
mod core_logic {
    use super::*;
    use evice_blockchain::crypto::ValidatorKeys;
    use evice_blockchain::keystore::Keystore;

    #[derive(Serialize)]
    pub struct FullWalletInfo {
        pub full_public_key: String,
        pub address: String,
        pub private_key: String,
        pub vrf_public_key: String,
        pub vrf_secret_key: String,
        pub bls_public_key: String,
        pub bls_secret_key: String,
    }

    pub fn generate_new_keys() -> FullWalletInfo {
        let keys = ValidatorKeys::new();
        let bls_public_key = keys.bls_secret_key.sk_to_pk();
        let address = public_key_to_address(&keys.signing_keys.public_key_bytes());

        FullWalletInfo {
            full_public_key: hex::encode(keys.signing_keys.public_key_bytes()),
            address: format!("0x{}", hex::encode(address.as_ref())),
            private_key: hex::encode(keys.signing_keys.private_key_bytes()),
            vrf_public_key: hex::encode(keys.vrf_keys.public.to_bytes()),
            vrf_secret_key: hex::encode(keys.vrf_keys.secret.to_bytes()),
            bls_public_key: hex::encode(bls_public_key.to_bytes()),
            bls_secret_key: hex::encode(keys.bls_secret_key.to_bytes()),
        }
    }

    pub fn create_keystore_from_keys(
        full_public_key_hex: &str,
        private_key_hex: &str,
        password: &str,
    ) -> Result<Keystore, String> {
        let pk_bytes_vec = hex::decode(private_key_hex).map_err(|e| e.to_string())?;
        let pub_key_bytes_vec = hex::decode(full_public_key_hex).map_err(|e| e.to_string())?;

        let pk_bytes: [u8; PRIVATE_KEY_SIZE] = pk_bytes_vec
            .try_into()
            .map_err(|_| "Panjang private key tidak valid".to_string())?;

        let pub_key_bytes: [u8; PUBLIC_KEY_SIZE] = pub_key_bytes_vec
            .try_into()
            .map_err(|_| "Panjang public key tidak valid".to_string())?;

        Keystore::new(&pk_bytes, password, &pub_key_bytes).map_err(|e| e.to_string())
    }
}

// --- MODUL 2: API HANDLERS ---
mod api_handlers {
    use super::*;
    use evice_blockchain::Transaction;

    #[derive(Deserialize)]
    pub struct CreateKeystoreRequest {
        pub full_public_key: String,
        pub private_key: String,
        pub password: String,
    }

    #[get("/api/v1/wallet/generate")]
    pub async fn generate_new_wallet() -> impl Responder {
        let wallet_info = core_logic::generate_new_keys();
        HttpResponse::Ok().json(wallet_info)
    }

    #[post("/api/v1/wallet/create_keystore")]
    pub async fn create_keystore(req: web::Json<CreateKeystoreRequest>) -> impl Responder {
        match core_logic::create_keystore_from_keys(
            &req.full_public_key,
            &req.private_key,
            &req.password,
        ) {
            Ok(keystore) => HttpResponse::Ok().json(keystore),
            Err(e) => HttpResponse::BadRequest().body(e),
        }
    }

    #[derive(Deserialize)]
    pub struct BroadcastRequest {
        pub signed_tx_hex: String,
    }

    #[derive(Serialize)]
    pub struct BroadcastResponse {
        pub tx_hash: String,
    }

    #[post("/api/v1/rpc/broadcast_transaction")]
    pub async fn broadcast_transaction(
        app_state: web::Data<AppState>,
        req: web::Json<BroadcastRequest>,
    ) -> impl Responder {
        let tx_bytes = match hex::decode(&req.signed_tx_hex) {
            Ok(bytes) => bytes,
            Err(_) => return HttpResponse::BadRequest().body("Format signed_tx_hex tidak valid"),
        };

        let tx: Transaction =
            match bincode::decode_from_slice(&tx_bytes, bincode::config::standard()) {
                Ok((decoded_tx, _)) => decoded_tx,
                Err(_) => {
                    return HttpResponse::BadRequest().body("Gagal men-decode data transaksi")
                }
            };

        let mut rpc_client = app_state.rpc_client.lock().unwrap();

        match rpc_client.submit_l1_transaction(&tx).await {
            Ok(tx_hash) => HttpResponse::Ok().json(BroadcastResponse { tx_hash }),
            Err(e) => {
                ErrorInternalServerError(format!("Gagal menyiarkan transaksi ke node L1: {}", e))
                    .into()
            }
        }
    }
}

#[derive(Parser, Debug)]
#[clap(name = "evice-wallet-service", version = "1.0", author = "Evice Devs")]
#[clap(about = "Menjalankan backend API service untuk Evice Wallet", long_about = None)]
struct Cli {
    #[clap(
        long,
        env = "EVICE_L1_RPC_URL",
        default_value = "https://127.0.0.1:8080"
    )]
    l1_rpc_url: String,
    #[clap(long, default_value = "127.0.0.1")]
    listen_addr: String,
    #[clap(long, default_value_t = 8000)]
    port: u16,
}

struct AppState {
    rpc_client: std::sync::Mutex<RpcClient>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    println!("Menghubungkan ke node L1 di: {}", &cli.l1_rpc_url);
    let rpc_url_for_client = cli.l1_rpc_url.clone();
    let rpc_client = RpcClient::new(rpc_url_for_client, "".to_string())
        .await
        .unwrap_or_else(|e| {
            panic!(
                "Gagal terhubung ke node L1 Evice di {}: {}",
                &cli.l1_rpc_url, e
            )
        });

    let app_state = web::Data::new(AppState {
        rpc_client: std::sync::Mutex::new(rpc_client),
    });

    let bind_addr = format!("{}:{}", cli.listen_addr, cli.port);
    println!(
        "🚀 Evice Wallet Core Service berjalan di http://{}",
        bind_addr
    );
    println!("Endpoint yang tersedia:");
    println!("  GET  /api/v1/wallet/generate          -> Membuat satu set kunci baru");
    println!("  POST /api/v1/wallet/create_keystore     -> Membuat keystore dari kunci yang ada");
    println!("  POST /api/v1/rpc/broadcast_transaction -> Menyiarkan transaksi yang sudah ditandatangani");

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(api_handlers::generate_new_wallet)
            .service(api_handlers::create_keystore)
            .service(api_handlers::broadcast_transaction)
    })
    .bind(&bind_addr)?
    .run()
    .await
}
