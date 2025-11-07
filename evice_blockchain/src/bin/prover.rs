// evice_blockchain/src/bin/prover.rs

use ark_bls12_377::Bls12_377;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
use clap::Parser;
use evice_blockchain::l2_circuit::{BatchSystemCircuit, PoseidonMerkleTreeParams};
use std::fs::File;

#[derive(Parser, Debug)]
#[clap(name = "prover-cli")]
struct Cli {
    #[clap(long)]
    params_path: String,
    #[clap(long)]
    proving_key_path: String,
    #[clap(long)]
    circuit_data_hex: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut rng = thread_rng();

    let params_file = File::open(&cli.params_path)?;
    let _params = PoseidonMerkleTreeParams::deserialize_uncompressed(params_file)?;
    let mut pk_file = File::open(&cli.proving_key_path)?;
    let pk = ProvingKey::deserialize_uncompressed_unchecked(&mut pk_file)?;

    let circuit_data_bytes = hex::decode(cli.circuit_data_hex)?;
    let circuit: BatchSystemCircuit =
        BatchSystemCircuit::deserialize_uncompressed(&circuit_data_bytes[..])?;

    let proof = Groth16::<Bls12_377>::prove(&pk, circuit, &mut rng)?;

    let mut proof_bytes = Vec::new();
    proof.serialize_uncompressed(&mut proof_bytes)?;
    println!("{}", hex::encode(&proof_bytes));

    Ok(())
}
