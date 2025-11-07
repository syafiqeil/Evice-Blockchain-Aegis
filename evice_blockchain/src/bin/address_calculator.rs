// evice_blockchain/src/bin/address_calculator.rs

use evice_blockchain::crypto::public_key_to_address;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: address_calculator <full_public_key_hex>");
        return Err("Invalid arguments".into());
    }

    let pub_key_hex = &args[1];
    let pub_key_bytes_vec = hex::decode(pub_key_hex)?;

    let pub_key_bytes: [u8; evice_blockchain::crypto::PUBLIC_KEY_SIZE] =
        match pub_key_bytes_vec.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return Err(format!(
                    "Invalid public key length. Expected {} bytes.",
                    evice_blockchain::crypto::PUBLIC_KEY_SIZE
                )
                .into())
            }
        };

    let address = public_key_to_address(&pub_key_bytes);
    println!("{}", hex::encode(address.as_ref()));

    Ok(())
}
