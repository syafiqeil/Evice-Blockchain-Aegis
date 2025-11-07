// evice_blockchain/src/bin/create_evidence.rs

use evice_blockchain::{
    blockchain::BlockHeader,
    crypto::{public_key_to_address, KeyPair, SIGNATURE_SIZE},
};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Penggunaan: cargo run --bin create_evidence <PUBLIC_KEY_HEX> <PRIVATE_KEY_HEX> <INDEX> <PREV_HASH_HEX>");
        return Ok(());
    }

    let pk_hex = &args[1];
    let sk_hex = &args[2];
    let index: u64 = args[3].parse().expect("Index harus berupa angka");
    let prev_hash_hex = &args[4];

    let pk_bytes = hex::decode(pk_hex)?;
    let sk_bytes = hex::decode(sk_hex)?;

    let keypair = KeyPair::from_key_bytes(&pk_bytes, &sk_bytes)?;

    let authority_address = public_key_to_address(&keypair.public_key_bytes());

    let prev_hash = hex::decode(prev_hash_hex).expect("Invalid prev_hash hex");

    let mut header1 = BlockHeader {
        index,
        timestamp: 1,
        prev_hash: prev_hash.clone(),
        authority: authority_address,
        signature: [0; SIGNATURE_SIZE],
        state_root: vec![0; 32],
        transactions_root: vec![0; 32],
        l2_transactions_hash: None,
        base_fee_per_gas: 10,
        gas_used: 0,
    };

    let data_to_sign1 = header1.canonical_bytes_for_signing();
    header1.signature = keypair.sign(&data_to_sign1);

    let mut header2 = BlockHeader {
        index,
        timestamp: 2,
        prev_hash,
        authority: authority_address,
        signature: [0; SIGNATURE_SIZE],
        state_root: vec![1; 32],
        transactions_root: vec![1; 32],
        l2_transactions_hash: Some(vec![42; 32]),
        base_fee_per_gas: 10,
        gas_used: 0,
    };

    let data_to_sign2 = header2.canonical_bytes_for_signing();
    header2.signature = keypair.sign(&data_to_sign2);

    println!("\n--- Header 1 (JSON) ---");
    println!("{}", serde_json::to_string(&header1).unwrap());
    println!("\n--- Header 2 (JSON) ---");
    println!("{}", serde_json::to_string(&header2).unwrap());

    Ok(())
}
