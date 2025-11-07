// evice_blockchain/src/l2_aggregation.rs

use ark_bls12_377::{Bls12_377, Config as Bls12_377Config, Fr as Bls12_377Fr};
use ark_bw6_761::Fr as Bw6_761Fr;
use ark_groth16::{constraints::Groth16VerifierGadget, Groth16, Proof, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

use ark_crypto_primitives::snark::constraints::{
    BooleanInputVar, EmulatedFieldInputVar, SNARKGadget,
};
use ark_r1cs_std::{
    fields::emulated_fp::EmulatedFpVar, pairing::bls12::PairingVar as Bls12PairingVar, prelude::*,
};

type Bls12_377PairingGadget = Bls12PairingVar<Bls12_377Config>;
type Groth16Verifier = Groth16VerifierGadget<Bls12_377, Bls12_377PairingGadget>;

#[derive(Clone)]
pub struct AggregationCircuit {
    pub leaf_vk: VerifyingKey<Bls12_377>,
    pub proof_1: Proof<Bls12_377>,
    pub proof_2: Proof<Bls12_377>,
    pub public_inputs_1: Vec<Bls12_377Fr>,
    pub public_inputs_2: Vec<Bls12_377Fr>,
}

impl ConstraintSynthesizer<Bw6_761Fr> for AggregationCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Bw6_761Fr>,
    ) -> Result<(), SynthesisError> {
        // PUBLIC INPUTS UNTUK SIRKUIT AGREGASI
        let initial_root_emulated = <EmulatedFpVar<Bls12_377Fr, Bw6_761Fr>>::new_input(
            ark_relations::ns!(cs, "initial_root"),
            || Ok(self.public_inputs_1[0]),
        )?;
        let final_root_emulated = <EmulatedFpVar<Bls12_377Fr, Bw6_761Fr>>::new_input(
            ark_relations::ns!(cs, "final_root"),
            || Ok(self.public_inputs_2[1]),
        )?;

        // WITNESSES (DATA PRIVAT UNTUK SIRKUIT AGREGASI)
        let leaf_vk_var = <Groth16Verifier as SNARKGadget<
            Bls12_377Fr,
            Bw6_761Fr,
            Groth16<Bls12_377>,
        >>::VerifyingKeyVar::new_witness(
            ark_relations::ns!(cs, "leaf_vk"), || Ok(self.leaf_vk)
        )?;

        let proof1_var = <Groth16Verifier as SNARKGadget<
            Bls12_377Fr,
            Bw6_761Fr,
            Groth16<Bls12_377>,
        >>::ProofVar::new_witness(
            ark_relations::ns!(cs, "proof1"), || Ok(self.proof_1)
        )?;

        let proof2_var = <Groth16Verifier as SNARKGadget<
            Bls12_377Fr,
            Bw6_761Fr,
            Groth16<Bls12_377>,
        >>::ProofVar::new_witness(
            ark_relations::ns!(cs, "proof2"), || Ok(self.proof_2)
        )?;

        let inputs1_emulated = EmulatedFieldInputVar::<Bls12_377Fr, Bw6_761Fr>::new_witness(
            ark_relations::ns!(cs, "inputs1_emulated"),
            || Ok(self.public_inputs_1),
        )?;

        let inputs2_emulated = EmulatedFieldInputVar::<Bls12_377Fr, Bw6_761Fr>::new_witness(
            ark_relations::ns!(cs, "inputs2_emulated"),
            || Ok(self.public_inputs_2),
        )?;

        let inputs1_bits: Vec<Vec<Boolean<Bw6_761Fr>>> = inputs1_emulated
            .val
            .iter()
            .map(|f| f.to_bits_le())
            .collect::<Result<_, _>>()?;
        let inputs1_boolean = BooleanInputVar::new(inputs1_bits);

        let inputs2_bits: Vec<Vec<Boolean<Bw6_761Fr>>> = inputs2_emulated
            .val
            .iter()
            .map(|f| f.to_bits_le())
            .collect::<Result<_, _>>()?;
        let inputs2_boolean = BooleanInputVar::new(inputs2_bits);

        inputs1_emulated.val[1].enforce_equal(&inputs2_emulated.val[0])?;
        initial_root_emulated.enforce_equal(&inputs1_emulated.val[0])?;
        final_root_emulated.enforce_equal(&inputs2_emulated.val[1])?;

        // VERIFIKASI BUKTI-BUKTI ZK DI DALAM SIRKUIT
        Groth16Verifier::verify(&leaf_vk_var, &inputs1_boolean, &proof1_var)?
            .enforce_equal(&Boolean::TRUE)?;

        Groth16Verifier::verify(&leaf_vk_var, &inputs2_boolean, &proof2_var)?
            .enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}
