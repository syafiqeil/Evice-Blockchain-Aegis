// evice_blockchain/src/bin/generate_zk_params.rs

use ark_bls12_377::{Bls12_377, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
use evice_blockchain::l2_circuit::{get_poseidon_parameters, BatchSystemCircuit};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔥 Menghasilkan Proving Key dan Verifying Key untuk Sirkuit L2...");

    let poseidon_config = get_poseidon_parameters();
    let dummy_circuit = BatchSystemCircuit {
        initial_root: Fr::default(),
        final_root: Fr::default(),
        transactions: vec![],
        initial_leaves: vec![],
        leaf_crh_params: poseidon_config.clone(),
        two_to_one_crh_params: poseidon_config,
    };

    let mut rng = thread_rng();
    let (pk, vk) = Groth16::<Bls12_377>::circuit_specific_setup(dummy_circuit, &mut rng)?;

    let mut pk_file = File::create("proving_key.bin")?;
    pk.serialize_uncompressed(&mut pk_file)?;
    println!("✅ Proving Key berhasil disimpan ke 'proving_key.bin'");

    let mut vk_file = File::create("verifying_key.bin")?;
    vk.serialize_uncompressed(&mut vk_file)?;
    println!("✅ Verifying Key berhasil disimpan ke 'verifying_key.bin'");

    Ok(())
}
