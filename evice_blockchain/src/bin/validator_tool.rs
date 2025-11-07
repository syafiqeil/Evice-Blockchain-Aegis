// evice_blockchain/src/bin/validator_tool.rs

use clap::Parser;
use evice_blockchain::{
    crypto::{public_key_to_address, ValidatorKeys},
    keystore::Keystore,
};
use rpassword::read_password;
use serde::Serialize;
use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

#[derive(Parser, Debug)]
#[clap(
    name = "validator-tool",
    about = "Alat untuk mendaftar sebagai validator atau membuat aset testnet."
)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    /// (Untuk Publik) Hasilkan file pendaftaran dan keystore untuk satu validator.
    GenerateSingle {
        #[clap(long, help = "Alamat IP publik atau DNS Anda.")]
        public_ip: String,
        #[clap(
            long,
            default_value_t = 50000,
            help = "Port P2P yang Anda buka di firewall."
        )]
        p2p_port: u16,
        #[clap(
            long,
            default_value = "./registration",
            help = "Direktori output untuk file pendaftaran dan keystore."
        )]
        output_dir: PathBuf,
    },
    /// (Untuk Lokal) Hasilkan aset untuk beberapa node sekaligus dan cetak ke stdout.
    GenerateBatch {
        #[clap(long, default_value_t = 6)]
        num_nodes: u32,
    },
}

#[derive(Serialize)]
struct RegistrationFile {
    address: String,
    public_key: String,
    vrf_public_key: String,
    bls_public_key: String,
    network_identity: String,
}

#[derive(Serialize)]
struct NodeAssetOutput {
    node_index: u32,
    address: String,
    public_key: String,
    private_key: String,
    vrf_public_key: String,
    vrf_secret_key: String,
    bls_public_key: String,
    bls_secret_key: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateSingle {
            public_ip,
            p2p_port,
            output_dir,
        } => {
            println!("🚀 Memulai proses pendaftaran validator (mode publik)...");

            let keys = ValidatorKeys::new();
            let address = public_key_to_address(&keys.signing_keys.public_key_bytes());
            let bls_pk = keys.bls_secret_key.sk_to_pk();

            println!("\n🔒 Buat kata sandi untuk mengamankan keystore Anda. JANGAN SAMPAI HILANG!");
            let password = read_password()?;
            let keystore = Keystore::new(
                &keys.signing_keys.private_key_bytes(),
                &password,
                &keys.signing_keys.public_key_bytes(),
            )?;

            fs::create_dir_all(&output_dir)?;
            let address_hex = hex::encode(address.as_ref());

            let keystore_path = output_dir.join(format!("keystore-{}.json", address_hex));
            keystore.save_to_path(&keystore_path)?;
            println!(
                "\n✅ Keystore Anda berhasil disimpan di: {}",
                keystore_path.display()
            );
            println!("   Jaga file ini dan kata sandi Anda dengan sangat aman!");

            let p2p_key_path = output_dir.join("p2p_keypair.bin");
            let p2p_keypair = libp2p::identity::Keypair::generate_ed25519();
            fs::write(&p2p_key_path, p2p_keypair.to_protobuf_encoding()?)?;
            let peer_id = p2p_keypair.public().to_peer_id();

            let registration = RegistrationFile {
                address: format!("0x{}", address_hex),
                public_key: hex::encode(keys.signing_keys.public_key_bytes()),
                vrf_public_key: hex::encode(keys.vrf_keys.public.to_bytes()),
                bls_public_key: hex::encode(bls_pk.to_bytes()),
                network_identity: format!("/ip4/{}/tcp/{}/p2p/{}", public_ip, p2p_port, peer_id),
            };

            let registration_path = output_dir.join(format!("registration-{}.json", address_hex));
            let mut file = File::create(&registration_path)?;
            file.write_all(serde_json::to_string_pretty(&registration)?.as_bytes())?;

            println!(
                "\n✅ File pendaftaran Anda telah dibuat di: {}",
                registration_path.display()
            );
            println!("   Kirimkan HANYA file 'registration-....json' ke koordinator testnet.");
        }
        Commands::GenerateBatch { num_nodes } => {
            let mut all_assets = Vec::new();

            for i in 1..=num_nodes {
                let keys = ValidatorKeys::new();
                let address = public_key_to_address(&keys.signing_keys.public_key_bytes());
                let bls_pk = keys.bls_secret_key.sk_to_pk();

                let assets = NodeAssetOutput {
                    node_index: i,
                    address: format!("0x{}", hex::encode(address.as_ref())),
                    public_key: hex::encode(keys.signing_keys.public_key_bytes()),
                    private_key: hex::encode(keys.signing_keys.private_key_bytes()),
                    vrf_public_key: hex::encode(keys.vrf_keys.public.to_bytes()),
                    vrf_secret_key: hex::encode(keys.vrf_keys.secret.to_bytes()),
                    bls_public_key: hex::encode(bls_pk.to_bytes()),
                    bls_secret_key: hex::encode(keys.bls_secret_key.to_bytes()),
                };
                all_assets.push(assets);
            }
            println!("{}", serde_json::to_string_pretty(&all_assets)?);
        }
    }

    Ok(())
}
