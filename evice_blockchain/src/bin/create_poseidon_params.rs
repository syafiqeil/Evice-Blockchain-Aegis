// evice_blockchain/src/bin/create_poseidon_params.rs

use ark_serialize::CanonicalSerialize;
use evice_blockchain::l2_circuit::{get_poseidon_parameters, PoseidonMerkleTreeParams};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔥 Menghasilkan parameter untuk Poseidon Hash...");

    // Mengambil parameter yang sudah didefinisikan
    let params_config = get_poseidon_parameters();

    // Membungkusnya dalam struct yang digunakan oleh Merkle Tree
    let merkle_tree_params = PoseidonMerkleTreeParams {
        leaf_crh_params: params_config.clone(),
        two_to_one_crh_params: params_config,
    };

    // Menyimpannya ke file
    let mut file = File::create("poseidon_params.bin")?;
    merkle_tree_params.serialize_uncompressed(&mut file)?;

    println!("✅ Parameter Poseidon berhasil disimpan ke 'poseidon_params.bin'");
    Ok(())
}
