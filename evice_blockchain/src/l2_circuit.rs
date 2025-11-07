// evice_blockchain/src/l2_circuit.rs

use ark_bls12_377::{Bls12_377, Fr};
use ark_crypto_primitives::{
    crh::{
        poseidon::{constraints::TwoToOneCRHGadget, TwoToOneCRH},
        CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
    },
    merkle_tree::{
        constraints::{DigestVarConverter, PathVar},
        Path,
    },
    sponge::poseidon::PoseidonConfig,
};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Valid, Write,
};
use ark_snark::SNARK;
use evice_core::{Leaf, LeafCRH, MerkleTreeConfig};
use std::marker::PhantomData;
use std::str::FromStr;
use thiserror::Error;
use tokio::task;
use tokio::time::{timeout, Duration};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BatchTxInfo {
    pub amount: Fr,
    pub sender_leaf_index: u32,
    pub recipient_leaf_index: u32,
    pub sender_path: Path<MerkleTreeConfig>,
    pub recipient_path: Path<MerkleTreeConfig>,
}

#[derive(Clone, Debug)]
pub struct BatchSystem {
    pub initial_root: Fr,
    pub final_root: Fr,
    pub transactions: Vec<BatchTxInfo>,
    pub initial_leaves: Vec<Leaf>,
    pub initial_paths: Vec<Path<MerkleTreeConfig>>,
    pub leaf_crh_params: <LeafCRH<Fr> as CRHScheme>::Parameters,
    pub two_to_one_crh_params: <TwoToOneCRH<Fr> as TwoToOneCRHScheme>::Parameters,
}

#[derive(Clone, Debug)]
pub struct BatchSystemCircuit {
    pub initial_root: Fr,
    pub final_root: Fr,
    pub transactions: Vec<BatchTxInfo>,
    pub initial_leaves: Vec<Leaf>,
    pub leaf_crh_params: <LeafCRH<Fr> as CRHScheme>::Parameters,
    pub two_to_one_crh_params: <TwoToOneCRH<Fr> as TwoToOneCRHScheme>::Parameters,
}

impl CanonicalSerialize for BatchSystemCircuit {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        self.initial_root
            .serialize_with_mode(&mut writer, compress)?;
        self.final_root.serialize_with_mode(&mut writer, compress)?;
        self.transactions
            .serialize_with_mode(&mut writer, compress)?;
        self.initial_leaves
            .serialize_with_mode(&mut writer, compress)?;

        self.leaf_crh_params
            .full_rounds
            .serialize_with_mode(&mut writer, compress)?;
        self.leaf_crh_params
            .partial_rounds
            .serialize_with_mode(&mut writer, compress)?;
        self.leaf_crh_params
            .alpha
            .serialize_with_mode(&mut writer, compress)?;
        self.leaf_crh_params
            .ark
            .serialize_with_mode(&mut writer, compress)?;
        self.leaf_crh_params
            .mds
            .serialize_with_mode(&mut writer, compress)?;
        self.leaf_crh_params
            .rate
            .serialize_with_mode(&mut writer, compress)?;
        self.leaf_crh_params
            .capacity
            .serialize_with_mode(&mut writer, compress)?;

        self.two_to_one_crh_params
            .full_rounds
            .serialize_with_mode(&mut writer, compress)?;
        self.two_to_one_crh_params
            .partial_rounds
            .serialize_with_mode(&mut writer, compress)?;
        self.two_to_one_crh_params
            .alpha
            .serialize_with_mode(&mut writer, compress)?;
        self.two_to_one_crh_params
            .ark
            .serialize_with_mode(&mut writer, compress)?;
        self.two_to_one_crh_params
            .mds
            .serialize_with_mode(&mut writer, compress)?;
        self.two_to_one_crh_params
            .rate
            .serialize_with_mode(&mut writer, compress)?;
        self.two_to_one_crh_params
            .capacity
            .serialize_with_mode(&mut writer, compress)?;

        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.initial_root.serialized_size(compress)
            + self.final_root.serialized_size(compress)
            + self.transactions.serialized_size(compress)
            + self.initial_leaves.serialized_size(compress)
            + self.leaf_crh_params.full_rounds.serialized_size(compress)
            + self
                .leaf_crh_params
                .partial_rounds
                .serialized_size(compress)
            + self.leaf_crh_params.alpha.serialized_size(compress)
            + self.leaf_crh_params.ark.serialized_size(compress)
            + self.leaf_crh_params.mds.serialized_size(compress)
            + self.leaf_crh_params.rate.serialized_size(compress)
            + self.leaf_crh_params.capacity.serialized_size(compress)
            + self
                .two_to_one_crh_params
                .full_rounds
                .serialized_size(compress)
            + self
                .two_to_one_crh_params
                .partial_rounds
                .serialized_size(compress)
            + self.two_to_one_crh_params.alpha.serialized_size(compress)
            + self.two_to_one_crh_params.ark.serialized_size(compress)
            + self.two_to_one_crh_params.mds.serialized_size(compress)
            + self.two_to_one_crh_params.rate.serialized_size(compress)
            + self
                .two_to_one_crh_params
                .capacity
                .serialized_size(compress)
    }
}

impl CanonicalDeserialize for BatchSystemCircuit {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        let initial_root = Fr::deserialize_with_mode(&mut reader, compress, validate)?;
        let final_root = Fr::deserialize_with_mode(&mut reader, compress, validate)?;
        let transactions =
            Vec::<BatchTxInfo>::deserialize_with_mode(&mut reader, compress, validate)?;
        let initial_leaves = Vec::<Leaf>::deserialize_with_mode(&mut reader, compress, validate)?;

        let leaf_full_rounds = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_partial_rounds = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_alpha = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_ark = Vec::<Vec<Fr>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_mds = Vec::<Vec<Fr>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_rate = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_capacity = usize::deserialize_with_mode(&mut reader, compress, validate)?;

        let leaf_crh_params = PoseidonConfig::new(
            leaf_full_rounds,
            leaf_partial_rounds,
            leaf_alpha,
            leaf_mds,
            leaf_ark,
            leaf_rate,
            leaf_capacity,
        );

        let two_to_one_full_rounds = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let two_to_one_partial_rounds =
            usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let two_to_one_alpha = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let two_to_one_ark =
            Vec::<Vec<Fr>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let two_to_one_mds =
            Vec::<Vec<Fr>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let two_to_one_rate = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let two_to_one_capacity = usize::deserialize_with_mode(&mut reader, compress, validate)?;

        let two_to_one_crh_params = PoseidonConfig::new(
            two_to_one_full_rounds,
            two_to_one_partial_rounds,
            two_to_one_alpha,
            two_to_one_mds,
            two_to_one_ark,
            two_to_one_rate,
            two_to_one_capacity,
        );

        Ok(Self {
            initial_root,
            final_root,
            transactions,
            initial_leaves,
            leaf_crh_params,
            two_to_one_crh_params,
        })
    }
}

impl Valid for BatchSystemCircuit {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

pub type Circuit = BatchSystemCircuit;

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("Prover timed out")]
    Timeout,
    #[error("Internal prover error: {0}")]
    Internal(String),
}

impl From<SynthesisError> for ProverError {
    fn from(e: SynthesisError) -> Self {
        ProverError::Internal(e.to_string())
    }
}

pub fn prove(
    circuit: Circuit,
    pk: &ProvingKey<Bls12_377>,
) -> Result<Proof<Bls12_377>, ark_relations::r1cs::SynthesisError> {
    let mut rng = ark_std::rand::thread_rng();
    Groth16::<Bls12_377>::prove(pk, circuit, &mut rng)
}

pub async fn prove_async(
    circuit: Circuit,
    proving_key: ProvingKey<Bls12_377>,
) -> Result<Proof<Bls12_377>, ProverError> {
    let res = timeout(
        Duration::from_secs(60),
        task::spawn_blocking(move || prove(circuit, &proving_key)),
    )
    .await;

    match res {
        Ok(join_result) => match join_result {
            Ok(proof_result) => Ok(proof_result?),
            Err(e) => Err(ProverError::Internal(format!("Join error: {}", e))),
        },
        Err(_) => Err(ProverError::Timeout),
    }
}

#[derive(Debug, Clone)]
pub struct IdentityConverterGadget<T: ?Sized>(PhantomData<T>);
impl<F: PrimeField> DigestVarConverter<FpVar<F>, FpVar<F>> for IdentityConverterGadget<FpVar<F>> {
    type TargetType = FpVar<F>;
    fn convert(digest: FpVar<F>) -> Result<Self::TargetType, SynthesisError> {
        Ok(digest)
    }
}

#[derive(Clone, Debug)]
pub struct LeafCRHGadget<F: PrimeField>(PhantomData<F>);

impl<F: PrimeField + ark_crypto_primitives::sponge::Absorb> CRHSchemeGadget<LeafCRH<F>, F>
    for LeafCRHGadget<F>
{
    type InputVar = [FpVar<F>; 2];
    type OutputVar = FpVar<F>;
    type ParametersVar =
        <TwoToOneCRHGadget<F> as TwoToOneCRHSchemeGadget<TwoToOneCRH<F>, F>>::ParametersVar;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        <TwoToOneCRHGadget<F> as TwoToOneCRHSchemeGadget<TwoToOneCRH<F>, F>>::evaluate(
            parameters, &input[0], &input[1],
        )
    }
}

pub struct MerkleTreeConfigGadget;
impl ark_crypto_primitives::merkle_tree::constraints::ConfigGadget<MerkleTreeConfig, Fr>
    for MerkleTreeConfigGadget
{
    type Leaf = [FpVar<Fr>; 2];
    type LeafDigest = FpVar<Fr>;
    type LeafInnerConverter = IdentityConverterGadget<FpVar<Fr>>;
    type LeafHash = LeafCRHGadget<Fr>;
    type InnerDigest = FpVar<Fr>;
    type TwoToOneHash = TwoToOneCRHGadget<Fr>;
}

#[derive(Clone, Debug)]
pub struct PoseidonMerkleTreeParams {
    pub leaf_crh_params: <LeafCRH<Fr> as CRHScheme>::Parameters,
    pub two_to_one_crh_params: <TwoToOneCRH<Fr> as TwoToOneCRHScheme>::Parameters,
}

impl PoseidonMerkleTreeParams {
    pub fn new(
        leaf_crh_params: <LeafCRH<Fr> as CRHScheme>::Parameters,
        two_to_one_crh_params: <TwoToOneCRH<Fr> as TwoToOneCRHScheme>::Parameters,
    ) -> Self {
        Self {
            leaf_crh_params,
            two_to_one_crh_params,
        }
    }
}

impl CanonicalSerialize for PoseidonMerkleTreeParams {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        self.leaf_crh_params
            .full_rounds
            .serialize_with_mode(&mut writer, compress)?;
        self.leaf_crh_params
            .partial_rounds
            .serialize_with_mode(&mut writer, compress)?;
        self.leaf_crh_params
            .alpha
            .serialize_with_mode(&mut writer, compress)?;
        self.leaf_crh_params
            .ark
            .serialize_with_mode(&mut writer, compress)?;
        self.leaf_crh_params
            .mds
            .serialize_with_mode(&mut writer, compress)?;
        self.leaf_crh_params
            .rate
            .serialize_with_mode(&mut writer, compress)?;
        self.leaf_crh_params
            .capacity
            .serialize_with_mode(&mut writer, compress)?;

        self.two_to_one_crh_params
            .full_rounds
            .serialize_with_mode(&mut writer, compress)?;
        self.two_to_one_crh_params
            .partial_rounds
            .serialize_with_mode(&mut writer, compress)?;
        self.two_to_one_crh_params
            .alpha
            .serialize_with_mode(&mut writer, compress)?;
        self.two_to_one_crh_params
            .ark
            .serialize_with_mode(&mut writer, compress)?;
        self.two_to_one_crh_params
            .mds
            .serialize_with_mode(&mut writer, compress)?;
        self.two_to_one_crh_params
            .rate
            .serialize_with_mode(&mut writer, compress)?;
        self.two_to_one_crh_params
            .capacity
            .serialize_with_mode(&mut writer, compress)?;

        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.leaf_crh_params.full_rounds.serialized_size(compress)
            + self
                .leaf_crh_params
                .partial_rounds
                .serialized_size(compress)
            + self.leaf_crh_params.alpha.serialized_size(compress)
            + self.leaf_crh_params.ark.serialized_size(compress)
            + self.leaf_crh_params.mds.serialized_size(compress)
            + self.leaf_crh_params.rate.serialized_size(compress)
            + self.leaf_crh_params.capacity.serialized_size(compress)
            + self
                .two_to_one_crh_params
                .full_rounds
                .serialized_size(compress)
            + self
                .two_to_one_crh_params
                .partial_rounds
                .serialized_size(compress)
            + self.two_to_one_crh_params.alpha.serialized_size(compress)
            + self.two_to_one_crh_params.ark.serialized_size(compress)
            + self.two_to_one_crh_params.mds.serialized_size(compress)
            + self.two_to_one_crh_params.rate.serialized_size(compress)
            + self
                .two_to_one_crh_params
                .capacity
                .serialized_size(compress)
    }
}

impl CanonicalDeserialize for PoseidonMerkleTreeParams {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        let leaf_full_rounds = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_partial_rounds = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_alpha = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_ark = Vec::<Vec<Fr>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_mds = Vec::<Vec<Fr>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_rate = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_capacity = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_crh_params = PoseidonConfig::new(
            leaf_full_rounds,
            leaf_partial_rounds,
            leaf_alpha,
            leaf_mds,
            leaf_ark,
            leaf_rate,
            leaf_capacity,
        );
        let two_to_one_full_rounds = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let two_to_one_partial_rounds =
            usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let two_to_one_alpha = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let two_to_one_ark =
            Vec::<Vec<Fr>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let two_to_one_mds =
            Vec::<Vec<Fr>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let two_to_one_rate = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let two_to_one_capacity = usize::deserialize_with_mode(&mut reader, compress, validate)?;

        let two_to_one_crh_params = PoseidonConfig::new(
            two_to_one_full_rounds,
            two_to_one_partial_rounds,
            two_to_one_alpha,
            two_to_one_mds,
            two_to_one_ark,
            two_to_one_rate,
            two_to_one_capacity,
        );

        Ok(Self {
            leaf_crh_params,
            two_to_one_crh_params,
        })
    }
}

impl Valid for PoseidonMerkleTreeParams {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl ConstraintSynthesizer<Fr> for BatchSystemCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let initial_root_var = FpVar::new_input(cs.clone(), || Ok(self.initial_root))?;
        let final_root_var = FpVar::new_input(cs.clone(), || Ok(self.final_root))?;

        let leaf_crh_params_var =
            <LeafCRHGadget<Fr> as CRHSchemeGadget<LeafCRH<Fr>, Fr>>::ParametersVar::new_constant(
                cs.clone(),
                &self.leaf_crh_params,
            )?;
        let two_to_one_crh_params_var = <TwoToOneCRHGadget<Fr> as TwoToOneCRHSchemeGadget<
            TwoToOneCRH<Fr>,
            Fr,
        >>::ParametersVar::new_constant(
            cs.clone(), &self.two_to_one_crh_params
        )?;

        let mut leaf_vars: Vec<[FpVar<Fr>; 2]> = self
            .initial_leaves
            .iter()
            .map(|leaf| {
                Ok([
                    FpVar::new_witness(cs.clone(), || Ok(leaf[0]))?,
                    FpVar::new_witness(cs.clone(), || Ok(leaf[1]))?,
                ])
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut current_root_var = initial_root_var;

        for tx_info in &self.transactions {
            let sender_idx = tx_info.sender_leaf_index as usize;
            let recipient_idx = tx_info.recipient_leaf_index as usize;

            let amount_var = FpVar::new_witness(cs.clone(), || Ok(tx_info.amount))?;
            let sender_path_var =
                PathVar::<MerkleTreeConfig, Fr, MerkleTreeConfigGadget>::new_witness(
                    cs.clone(),
                    || Ok(tx_info.sender_path.clone()),
                )?;
            let recipient_path_var =
                PathVar::<MerkleTreeConfig, Fr, MerkleTreeConfigGadget>::new_witness(
                    cs.clone(),
                    || Ok(tx_info.recipient_path.clone()),
                )?;

            let sender_leaf_before = leaf_vars[sender_idx].clone();
            let recipient_leaf_before = leaf_vars[recipient_idx].clone();

            sender_path_var
                .verify_membership(
                    &leaf_crh_params_var,
                    &two_to_one_crh_params_var,
                    &current_root_var,
                    &sender_leaf_before,
                )?
                .enforce_equal(&Boolean::TRUE)?;
            recipient_path_var
                .verify_membership(
                    &leaf_crh_params_var,
                    &two_to_one_crh_params_var,
                    &current_root_var,
                    &recipient_leaf_before,
                )?
                .enforce_equal(&Boolean::TRUE)?;

            sender_leaf_before[1].enforce_cmp(&amount_var, std::cmp::Ordering::Greater, false)?;

            let sender_balance_after = &sender_leaf_before[1] - &amount_var;
            let recipient_balance_after = &recipient_leaf_before[1] + &amount_var;
            let sender_leaf_after = [sender_leaf_before[0].clone(), sender_balance_after];
            let recipient_leaf_after = [recipient_leaf_before[0].clone(), recipient_balance_after];
            let _intermediate_root = sender_path_var.calculate_root(
                &leaf_crh_params_var,
                &two_to_one_crh_params_var,
                &sender_leaf_after,
            )?;
            let next_root_var = recipient_path_var.calculate_root(
                &leaf_crh_params_var,
                &two_to_one_crh_params_var,
                &recipient_leaf_after,
            )?;

            leaf_vars[sender_idx] = sender_leaf_after;
            leaf_vars[recipient_idx] = recipient_leaf_after;
            current_root_var = next_root_var;
        }

        current_root_var.enforce_equal(&final_root_var)?;

        Ok(())
    }
}

pub fn get_poseidon_parameters() -> PoseidonConfig<Fr> {
    let full_rounds = 8;
    let partial_rounds = 29;
    let alpha = 17;
    let rate = 2;
    let capacity = 1;

    let mds = vec![
        vec![
            Fr::from_str(
                "43228725308391137369947362226390319299014033584574058394339561338097152657858",
            )
            .unwrap(),
            Fr::from_str(
                "20729134655727743386784826341366384914431326428651109729494295849276339718592",
            )
            .unwrap(),
            Fr::from_str(
                "14275792724825301816674509766636153429127896752891673527373812580216824074377",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "3039440043015681380498693766234886011876841428799441709991632635031851609481",
            )
            .unwrap(),
            Fr::from_str(
                "6678863357926068615342013496680930722082156498064457711885464611323928471101",
            )
            .unwrap(),
            Fr::from_str(
                "37355038393562575053091209735467454314247378274125943833499651442997254948957",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "26481612700543967643159862864328231943993263806649000633819754663276818191580",
            )
            .unwrap(),
            Fr::from_str(
                "30103264397473155564098369644643015994024192377175707604277831692111219371047",
            )
            .unwrap(),
            Fr::from_str(
                "5712721806190262694719203887224391960978962995663881615739647362444059585747",
            )
            .unwrap(),
        ],
    ];

    let ark = vec![
        vec![
            Fr::from_str(
                "9478896780421655835758496955063136571251874317427585180076394551808670301829",
            )
            .unwrap(),
            Fr::from_str(
                "1410220424381727336803825453763847584610565307685015130563813219659976870089",
            )
            .unwrap(),
            Fr::from_str(
                "12324248147325396388933912754817224521085038231095815415485781874375379288849",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "5869197693688547188262203345939784760013629955870738354032535473827837048029",
            )
            .unwrap(),
            Fr::from_str(
                "7027675418691353855077049716619550622043312043660992344940177187528247727783",
            )
            .unwrap(),
            Fr::from_str(
                "12525656923125347519081182951439180216858859245949104467678704676398049957654",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "2393593257638453164081539737606611596909105394156134386135868506931280124380",
            )
            .unwrap(),
            Fr::from_str(
                "21284282509779560826339329447865344953337633312148348516557075030360788076689",
            )
            .unwrap(),
            Fr::from_str(
                "9426009547297688316907727916185688178981799243406990694957955230529774886223",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "5340930120720868177469579986808462005013697381998009281661327587975132166755",
            )
            .unwrap(),
            Fr::from_str(
                "13224952063922250960936823741448973692264041750100990569445192064567307041002",
            )
            .unwrap(),
            Fr::from_str(
                "5263772922985715307758718731861278699232625525745635678504665316187832057553",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "12905140589386545724352113723305099554526316070018892915579084990225436501424",
            )
            .unwrap(),
            Fr::from_str(
                "3682692866591423277196501877256311982914914533289815428970072263880360882202",
            )
            .unwrap(),
            Fr::from_str(
                "19681976272543335942352939522328215645129363120562038296975370569202780487598",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "5636115553781577891149626756201577064573186936824720926267940879716772984728",
            )
            .unwrap(),
            Fr::from_str(
                "9501050736957980494328252533770324735114766672253853282051029963140075785396",
            )
            .unwrap(),
            Fr::from_str(
                "2809392708032113981798687947163092027958611686144429680366467696224014505992",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "18433043696013996573551852847056868761017170818820490351056924728720017242180",
            )
            .unwrap(),
            Fr::from_str(
                "1600424531609887868281118752288673305222025191763201214001133841689879221076",
            )
            .unwrap(),
            Fr::from_str(
                "4077863666335789263839414578443702921867998881654209770993100224779179660280",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "10750183821931976144366649760909312224094512474274826686974526305203678408743",
            )
            .unwrap(),
            Fr::from_str(
                "5876585841304782856135279046524906005004905983316552629403091395701737015709",
            )
            .unwrap(),
            Fr::from_str(
                "13484299981373196201166722380389594773562113262309564134825386266765751213853",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "17382139184029132729706972098151128411278461930818849113274328379445169530719",
            )
            .unwrap(),
            Fr::from_str(
                "20539300163698134245746932972121993866388520784246731402041866252259697791654",
            )
            .unwrap(),
            Fr::from_str(
                "149101987103211771991327927827692640556911620408176100290586418839323044234",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "3772300053282831651551351000101118094165364582047053942163129913249479587871",
            )
            .unwrap(),
            Fr::from_str(
                "1859494671365748569037492975272316924127197175139843386363551067183747450207",
            )
            .unwrap(),
            Fr::from_str(
                "6056775412522970299341516426839343188000696076848171109448990325789072743616",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "13535861576199801040709157556664030757939966797019046516538528720719863222691",
            )
            .unwrap(),
            Fr::from_str(
                "3166287940256215995277151981354337176516077219230228956292184356796876826882",
            )
            .unwrap(),
            Fr::from_str(
                "3878105211417696553129343540655091450996375987051865710523878345663272335218",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "3234972450165117119793849127765475568944145932922109597427102281521349833458",
            )
            .unwrap(),
            Fr::from_str(
                "4245107901241859301876588161430872878162557070919886440605528540426123750702",
            )
            .unwrap(),
            Fr::from_str(
                "14797507122636944484020484450153618519329103538375805997650508264647579279513",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "3893725073760673244819994221888005992135922325903832357013427303988853516024",
            )
            .unwrap(),
            Fr::from_str(
                "21641836396029226240087625131527365621781742784615208902930655613239471409203",
            )
            .unwrap(),
            Fr::from_str(
                "4622082908476410083286670201138165773322781640914243047922441301693321472984",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "14738633807199650048753490173004870343158648561341211428780666160270584694255",
            )
            .unwrap(),
            Fr::from_str(
                "2635090520059500019661864086615522409798872905401305311748231832709078452746",
            )
            .unwrap(),
            Fr::from_str(
                "19070766579582338321241892986615538320421651429118757507174186491084617237586",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "12622420533971517050761060317049369208980632120901481436392835424625664738526",
            )
            .unwrap(),
            Fr::from_str(
                "4395637216713203985567958440367812800809784906642242330796693491855644277207",
            )
            .unwrap(),
            Fr::from_str(
                "13856237567677889405904897420967317137820909836352033096836527506967315017500",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "2152570847472117965131784005129148028733701170858744625211808968788882229984",
            )
            .unwrap(),
            Fr::from_str(
                "6585203416839617436007268534508514569040432229287367393560615429950244309612",
            )
            .unwrap(),
            Fr::from_str(
                "2153122337593625580331500314713439203221416612327349850130027435376816262006",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "7340485916200743279276570085958556798507770452421357119145466906520506506342",
            )
            .unwrap(),
            Fr::from_str(
                "12717879727828017519339312786933302720905962296193775803009326830415523871745",
            )
            .unwrap(),
            Fr::from_str(
                "5392903649799167854181087360481925061021040403603926349022734894553054536405",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "7221669722700687417346373353960536661883467014204005276831020252277657076044",
            )
            .unwrap(),
            Fr::from_str(
                "8259126917996748375739426565773281408349947402369855975457055235880500335093",
            )
            .unwrap(),
            Fr::from_str(
                "9272385735015968356236075957906198733226196415690072035874639311675477515202",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "10999027991078055598627757097261950281899485771669414759870674222957875237568",
            )
            .unwrap(),
            Fr::from_str(
                "15453393396765207016379045014101989306173462885430532298601655955681532648226",
            )
            .unwrap(),
            Fr::from_str(
                "5478929644476681096437469958231489102974161353940993351588559414552523375472",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "6864274099016679903139678736335228538241825704814597078997020342617052506183",
            )
            .unwrap(),
            Fr::from_str(
                "12133526413093116990739357861671284889661106676453313677855438696597541491864",
            )
            .unwrap(),
            Fr::from_str(
                "4363234898901124667709814170397096827222883770682185860994495523839008586252",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "16799465577487943696587954846666404704275729737273450161871875150400464433797",
            )
            .unwrap(),
            Fr::from_str(
                "3466902930973160737502426090330438125630820207992414876720169645462530526357",
            )
            .unwrap(),
            Fr::from_str(
                "10062441698891350053170325824989022858836994651376301483266809451301259521913",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "5849282602749563270643968237860161465694876981255295041960826011116890638924",
            )
            .unwrap(),
            Fr::from_str(
                "18460093993858702487671589299005229942046272739124591066186726570539410116617",
            )
            .unwrap(),
            Fr::from_str(
                "9812100862165422922235757591915383485338044715409891361026651619010947646011",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "3387849124775103843519196664933515074848119722071551419682472701704619249120",
            )
            .unwrap(),
            Fr::from_str(
                "5283840871671971215904992681385681067319154145921438770232973796570506340281",
            )
            .unwrap(),
            Fr::from_str(
                "14450974197863079729258614455552607708855872944526185987072755641686663205867",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "12613293459867195704822743599193025685229122593088639435739984309110321350551",
            )
            .unwrap(),
            Fr::from_str(
                "6228273556621778927381918766322387348845347649737780310185999880647567569148",
            )
            .unwrap(),
            Fr::from_str(
                "7482296435079443913598332362891173417094991594500715575107878549173583070413",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "18655449861670697203232484600163743308157596453845950955559776266093852537258",
            )
            .unwrap(),
            Fr::from_str(
                "19948920146235041970991269588233091409704340607794045065548049409652881283328",
            )
            .unwrap(),
            Fr::from_str(
                "13866078374565054775555309394949653928903776100036987352339975076159400168494",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "19398653685274645718325650121748668221118186023117741800737442235635318532994",
            )
            .unwrap(),
            Fr::from_str(
                "4234154881267169381851681265196336178292466185695662916289548353755778788440",
            )
            .unwrap(),
            Fr::from_str(
                "12763628380946395634691260884409562631856128057257959813602172954351304541746",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "7882453112990894293341171586279209575183467873317150236705310601775347127762",
            )
            .unwrap(),
            Fr::from_str(
                "5669812778237054435250482766817044415794242063465169363632154286378940417646",
            )
            .unwrap(),
            Fr::from_str(
                "16998738906020038479274018881471127087312245548341958049900081105113388112420",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "3923902724726826782251513956816550869721438812970437824859252798290604500141",
            )
            .unwrap(),
            Fr::from_str(
                "8649850619802776810849631749100283821801281306919958924112424995025830909252",
            )
            .unwrap(),
            Fr::from_str(
                "11095642206650177249637693917287763476332497377393343056089442602164577098005",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "6935839211798937659784055008131602708847374430164859822530563797964932598700",
            )
            .unwrap(),
            Fr::from_str(
                "7009671085960032501857416946339379996865118520008277046653124221544059312084",
            )
            .unwrap(),
            Fr::from_str(
                "14361753917538892938870644779277430374939140280641641154553910654644462796654",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "6296738827713642491839335218022320853584196754765009910619998033694434027436",
            )
            .unwrap(),
            Fr::from_str(
                "13849351053619304861036345979638534258290466678610892122310972291285921828452",
            )
            .unwrap(),
            Fr::from_str(
                "434708832289952835651719825370636597763362139118091644948171210201038442144",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "16633750393567936099837698146248798150044883935695159627422586429892098538881",
            )
            .unwrap(),
            Fr::from_str(
                "12944939557587269500508410478785174192748264930676627398550886896505925728421",
            )
            .unwrap(),
            Fr::from_str(
                "13132297714437965464312509267711212830308064898189789451541658159340762509645",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "3197382106307730326149017386920960267079843887376371149099833465681078850285",
            )
            .unwrap(),
            Fr::from_str(
                "1219439673853113792340300173186247996249367102884530407862469123523013083971",
            )
            .unwrap(),
            Fr::from_str(
                "3493891993991676033939225547105305872211028239751045376877382816726002847983",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "17474961424148900675164871904345354895260557993970869987490270849177572737815",
            )
            .unwrap(),
            Fr::from_str(
                "14496326112831768456074139601688618143496262542471380389977686658437504436331",
            )
            .unwrap(),
            Fr::from_str(
                "2924472580096769678506212811457662807142794313402961128576445038927398235897",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "4628296006426596599826873705217702584581936573072175641058168144816722698331",
            )
            .unwrap(),
            Fr::from_str(
                "21191637522268746884323101636631937283436518241594045635071026927358145697662",
            )
            .unwrap(),
            Fr::from_str(
                "16951212238971640283544926666565087199118390400059790490897089817025688673127",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "19613695336435411200907478310503966803576648245805018042761984388590288078910",
            )
            .unwrap(),
            Fr::from_str(
                "19408817842355340096520725353160494939342325645253279486424056603334799168015",
            )
            .unwrap(),
            Fr::from_str(
                "21454045045501902703155952158575095010854214688097850310899813261125869452799",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "7770328480231095569114093553841085793308707788942057894109603074902652929530",
            )
            .unwrap(),
            Fr::from_str(
                "16464571997310094273270381226660568195148193554716113613093103468413654931642",
            )
            .unwrap(),
            Fr::from_str(
                "17470702407108506528534764015553049093186219898758900659217736458688524875937",
            )
            .unwrap(),
        ],
        vec![
            Fr::from_str(
                "18550730212998825286534234924565339469725380540133305684933015562293032312245",
            )
            .unwrap(),
            Fr::from_str(
                "2896017217286658654468296502214232988965841950467453595108246966331694256153",
            )
            .unwrap(),
            Fr::from_str(
                "14675299739240143232464986549869467617250208852063994519435190317578889428919",
            )
            .unwrap(),
        ],
    ];

    let ark_total_len = ark.len();
    let expected_rounds = full_rounds + partial_rounds;
    assert_eq!(
        ark_total_len, expected_rounds,
        "Jumlah ARK harus sama dengan total ronde"
    );

    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, capacity)
}
