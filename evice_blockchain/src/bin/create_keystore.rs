// evice_blockchain/src/bin/create_keystore.rs

use clap::Parser;
use evice_blockchain::{
    crypto::{KeyPair, PRIVATE_KEY_SIZE},
    keystore::Keystore,
};
use rpassword::read_password;
use sha3::{Digest, Keccak256};
use std::path::Path;
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(
        long,
        help = "Impor kunci publik mentah (hex) yang sudah ada.",
        requires = "import_private_key"
    )]
    import_public_key: Option<String>,
    #[clap(
        long,
        help = "Impor kunci privat mentah (hex) yang sudah ada.",
        requires = "import_public_key"
    )]
    import_private_key: Option<String>,
    #[clap(
        long,
        help = "Berikan kata sandi secara langsung (hanya untuk skrip pengujian!)."
    )]
    password: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let keypair;
    let mut priv_key_bytes_vec;

    if let (Some(pub_key_hex), Some(priv_key_hex)) = (cli.import_public_key, cli.import_private_key)
    {
        println!("🔐 Mengimpor pasangan kunci yang ada...");

        let pk_bytes = hex::decode(pub_key_hex)?;

        priv_key_bytes_vec = hex::decode(priv_key_hex)?;
        if priv_key_bytes_vec.len() != PRIVATE_KEY_SIZE {
            return Err("Panjang kunci privat yang diimpor tidak valid.".into());
        }

        keypair = KeyPair::from_key_bytes(&pk_bytes, &priv_key_bytes_vec)?;
    } else {
        println!("🔐 Membuat file Keystore baru...");
        keypair = KeyPair::new();
        priv_key_bytes_vec = keypair.private_key_bytes().to_vec();
    }

    let pub_key_bytes_full = keypair.public_key_bytes();
    println!("🔑 Kunci berhasil diproses.");
    println!(
        "   Kunci Publik (penuh): 0x{}...",
        &hex::encode(&pub_key_bytes_full[..32])
    );

    let password = match cli.password {
        Some(p) => {
            println!("\n🔒 Menggunakan kata sandi yang disediakan untuk enkripsi...");
            p
        }
        None => {
            println!("\n🔒 Masukkan kata sandi BARU untuk mengenkripsi keystore ini:");
            let pass = read_password()?;
            println!("   Konfirmasi kata sandi:");
            let pass_confirm = read_password()?;
            if pass != pass_confirm {
                return Err("Kata sandi tidak cocok. Proses dibatalkan.".into());
            }
            pass
        }
    };

    let keystore = Keystore::new(
        &priv_key_bytes_vec.as_slice().try_into()?,
        &password,
        &pub_key_bytes_full,
    )?;

    let dir = Path::new("./keystores");
    if !dir.exists() {
        std::fs::create_dir(dir)?;
    }

    let _address_hash_bytes = Keccak256::digest(keypair.public_key_bytes());
    let address_hex_for_filename = &keystore.address;

    let filename = format!(
        "UTC--{}--{}",
        chrono::Utc::now().to_rfc3339(),
        address_hex_for_filename
    );
    let path = dir.join(filename);

    keystore.save_to_path(&path)?;
    priv_key_bytes_vec.zeroize();

    println!(
        "\n✅ Keystore berhasil dibuat dan disimpan di: {}",
        path.display()
    );
    println!(
        "   Alamat (Identifier untuk Nama File): 0x{}",
        address_hex_for_filename
    );
    Ok(())
}
