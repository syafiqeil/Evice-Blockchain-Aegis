// evice_blockchain/src/bin/aggregator.rs

use ark_bls12_377::{Bls12_377, Fr as Bls12_377Fr};
use ark_bw6_761::{Fr as Bw6_761Fr, BW6_761};
use ark_crypto_primitives::snark::constraints::EmulatedFieldInputVar;
use ark_crypto_primitives::snark::FromFieldElementsGadget;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::thread_rng;
use clap::Parser;
use evice_blockchain::l2_aggregation::AggregationCircuit;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(name = "aggregator-cli", version = "1.0", author = "Evice Devs")]
#[clap(about = "Utilitas untuk membuat kunci dan mengagregasi bukti ZK.", long_about = None)]
enum Cli {
    GenerateKeys {
        #[clap(long, help = "Path ke verifying key dari sirkuit L2 batch (leaf).")]
        leaf_vk_path: PathBuf,
        #[clap(long, help = "Path untuk menyimpan proving key agregasi.")]
        agg_pk_path: PathBuf,
        #[clap(long, help = "Path untuk menyimpan verifying key agregasi.")]
        agg_vk_path: PathBuf,
    },
    Aggregate {
        #[clap(long, help = "Path ke verifying key dari sirkuit L2 batch (leaf).")]
        leaf_vk_path: PathBuf,
        #[clap(long, help = "Path ke proving key agregasi.")]
        agg_pk_path: PathBuf,
        #[clap(long, help = "Path ke verifying key agregasi untuk verifikasi akhir.")]
        agg_vk_path: PathBuf,
        #[clap(long, help = "Path ke bukti pertama (leaf).")]
        proof1_path: PathBuf,
        #[clap(
            long,
            help = "Public input pertama (old_root_hex,new_root_hex) dipisah koma."
        )]
        inputs1_hex: String,
        #[clap(long, help = "Path ke bukti kedua (leaf).")]
        proof2_path: PathBuf,
        #[clap(
            long,
            help = "Public input kedua (old_root_hex,new_root_hex) dipisah koma."
        )]
        inputs2_hex: String,
        #[clap(long, help = "Path untuk menyimpan bukti agregat yang baru.")]
        output_proof_path: PathBuf,
    },
}

fn hex_to_bls12_377_fr(hex_str: &str) -> Result<Bls12_377Fr, Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))?;
    Ok(Bls12_377Fr::from_be_bytes_mod_order(&bytes))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut rng = thread_rng();

    match cli {
        Cli::GenerateKeys {
            leaf_vk_path,
            agg_pk_path,
            agg_vk_path,
        } => {
            println!("🔥 Menghasilkan kunci untuk Sirkuit Agregasi...");

            let mut leaf_vk_file = File::open(leaf_vk_path)?;
            let leaf_vk =
                VerifyingKey::<Bls12_377>::deserialize_uncompressed_unchecked(&mut leaf_vk_file)?;

            // Membuat sirkuit dummy untuk setup
            let dummy_circuit = AggregationCircuit {
                leaf_vk,
                proof_1: Proof::default(),
                proof_2: Proof::default(),
                public_inputs_1: vec![Bls12_377Fr::default(), Bls12_377Fr::default()],
                public_inputs_2: vec![Bls12_377Fr::default(), Bls12_377Fr::default()],
            };

            println!("Membuat proving key dan verifying key (ini mungkin memakan waktu)...");
            let (pk, vk) = Groth16::<BW6_761>::setup(dummy_circuit.clone(), &mut rng)?;

            let mut pk_file = File::create(agg_pk_path)?;
            pk.serialize_uncompressed(&mut pk_file)?;
            println!("✅ Proving key agregasi disimpan.");

            let mut vk_file = File::create(agg_vk_path)?;
            vk.serialize_uncompressed(&mut vk_file)?;
            println!("✅ Verifying key agregasi disimpan.");
        }
        Cli::Aggregate {
            leaf_vk_path,
            agg_pk_path,
            agg_vk_path,
            proof1_path,
            inputs1_hex,
            proof2_path,
            inputs2_hex,
            output_proof_path,
        } => {
            println!("🔥 Mengagregasi dua bukti...");

            // Memuat kunci-kunci yang diperlukan
            let mut leaf_vk_file = File::open(leaf_vk_path)?;
            let leaf_vk =
                VerifyingKey::<Bls12_377>::deserialize_uncompressed_unchecked(&mut leaf_vk_file)?;

            let mut agg_pk_file = File::open(agg_pk_path)?;
            let agg_pk =
                ProvingKey::<BW6_761>::deserialize_uncompressed_unchecked(&mut agg_pk_file)?;

            let mut agg_vk_file = File::open(agg_vk_path)?;
            let agg_vk =
                VerifyingKey::<BW6_761>::deserialize_uncompressed_unchecked(&mut agg_vk_file)?;

            // Memuat bukti-bukti
            let mut proof1_file = File::open(proof1_path)?;
            let proof_1 = Proof::<Bls12_377>::deserialize_uncompressed_unchecked(&mut proof1_file)?;

            let mut proof2_file = File::open(proof2_path)?;
            let proof_2 = Proof::<Bls12_377>::deserialize_uncompressed_unchecked(&mut proof2_file)?;

            // Mem-parsing public inputs
            let inputs1: Vec<Bls12_377Fr> = inputs1_hex
                .split(',')
                .map(|s| hex_to_bls12_377_fr(s).unwrap())
                .collect();
            let inputs2: Vec<Bls12_377Fr> = inputs2_hex
                .split(',')
                .map(|s| hex_to_bls12_377_fr(s).unwrap())
                .collect();

            if inputs1.len() != 2 || inputs2.len() != 2 {
                return Err(
                    "Setiap public input harus terdiri dari dua elemen: old_root,new_root".into(),
                );
            }

            if inputs1[1] != inputs2[0] {
                return Err("Bukti tidak berkesinambungan: new_root dari bukti 1 tidak cocok dengan old_root dari bukti 2".into());
            }

            // Membuat sirkuit agregasi dengan data yang sebenarnya
            let aggregation_circuit = AggregationCircuit {
                leaf_vk,
                proof_1,
                public_inputs_1: inputs1.clone(),
                proof_2,
                public_inputs_2: inputs2.clone(),
            };

            println!("Menciptakan bukti agregat (ini mungkin memakan waktu)...");
            let proof = Groth16::<BW6_761>::prove(&agg_pk, aggregation_circuit, &mut rng)?;

            // Menyiapkan public inputs untuk verifikasi bukti agregat
            let public_inputs_bls: Vec<Bls12_377Fr> = vec![inputs1[0], inputs2[1]];
            let aggregated_public_inputs: Vec<Bw6_761Fr> =
                EmulatedFieldInputVar::<Bls12_377Fr, Bw6_761Fr>::repack_input(&public_inputs_bls);

            // Verifikasi bukti yang baru dibuat
            println!("Memverifikasi bukti agregat yang baru...");
            let is_valid = Groth16::<BW6_761>::verify(&agg_vk, &aggregated_public_inputs, &proof)?;
            if !is_valid {
                return Err("Bukti agregat yang dihasilkan tidak valid!".into());
            }
            println!("✅ Verifikasi berhasil.");

            // Menyimpan bukti
            let mut proof_bytes = Vec::new();
            proof.serialize_uncompressed(&mut proof_bytes)?;

            let mut output_file = File::create(output_proof_path)?;
            output_file.write_all(&proof_bytes)?;

            println!("✅ Bukti agregat berhasil dibuat dan disimpan!");
            println!(
                "   - Public Input Awal : 0x{}",
                hex::encode(inputs1[0].into_bigint().to_bytes_be())
            );
            println!(
                "   - Public Input Akhir: 0x{}",
                hex::encode(inputs2[1].into_bigint().to_bytes_be())
            );
        }
    }

    Ok(())
}
