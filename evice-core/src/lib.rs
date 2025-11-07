// evice-core/src/lib.rs

#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use ark_bls12_377::Fr;
use ark_crypto_primitives::merkle_tree::Path;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bincode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, Bytes};

pub mod borsh_helpers;

pub const ADDRESS_SIZE: usize = 20;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Copy,
    Default,
    BorshSerialize,
    BorshDeserialize,
    Ord,
    PartialOrd,
    Encode,
    Decode,
)]
pub struct Address(pub [u8; ADDRESS_SIZE]);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(&self.0, serializer)
    }
}
impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        let array: [u8; ADDRESS_SIZE] = bytes.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::invalid_length(v.len(), &"expected byte array of specific size")
        })?;
        Ok(Address(array))
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq<[u8; ADDRESS_SIZE]> for Address {
    fn eq(&self, other: &[u8; ADDRESS_SIZE]) -> bool {
        self.0 == *other
    }
}

pub type Leaf = [Fr; 2];

use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use core::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct LeafCRH<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField + ark_crypto_primitives::sponge::Absorb> CRHScheme for LeafCRH<F> {
    type Input = [F; 2];
    type Output = F;
    type Parameters =
        <ark_crypto_primitives::crh::poseidon::TwoToOneCRH<F> as TwoToOneCRHScheme>::Parameters;
    fn setup<R: ark_std::rand::Rng>(
        _r: &mut R,
    ) -> Result<PoseidonConfig<F>, ark_crypto_primitives::Error> {
        unimplemented!("Parameter generation should only happen in a `std` environment");
    }
    fn evaluate<T: core::borrow::Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        _input: T,
    ) -> Result<F, ark_crypto_primitives::Error> {
        unimplemented!("Evaluation logic is complex and not needed for type definition");
    }
}

pub struct MerkleTreeConfig;
impl ark_crypto_primitives::merkle_tree::Config for MerkleTreeConfig {
    type Leaf = Leaf;
    type LeafDigest = Fr;
    type LeafInnerDigestConverter =
        ark_crypto_primitives::merkle_tree::IdentityDigestConverter<Self::LeafDigest>;
    type LeafHash = LeafCRH<Fr>;
    type InnerDigest = Fr;
    type TwoToOneHash = ark_crypto_primitives::crh::poseidon::TwoToOneCRH<Fr>;
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WithdrawalProof {
    #[serde_as(as = "Bytes")]
    pub l2_state_root: Vec<u8>,

    #[serde_as(as = "crate::serde_helpers_placeholder::ArkFrArray<2>")]
    pub leaf_data: Leaf,

    #[serde_as(as = "crate::serde_helpers_placeholder::ArkPath")]
    pub merkle_path: Path<MerkleTreeConfig>,
}

impl BorshSerialize for WithdrawalProof {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.l2_state_root, writer)?;
        borsh_helpers::serialize_leaf(&self.leaf_data, writer)?;
        borsh_helpers::serialize_path(&self.merkle_path, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for WithdrawalProof {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        Ok(Self {
            l2_state_root: BorshDeserialize::deserialize_reader(reader)?,
            leaf_data: borsh_helpers::deserialize_leaf(reader)?,
            merkle_path: borsh_helpers::deserialize_path(reader)?,
        })
    }
}

// Helper sementara untuk kompilasi, karena tidak bisa memindahkan serde_helpers ke `no_std` dengan mudah
mod serde_helpers_placeholder {
    use super::*;
    use serde::{de::Error, Deserializer, Serializer};
    use serde_with::{Bytes, DeserializeAs, SerializeAs};

    pub struct ArkFrArray<const N: usize>;
    impl<const N: usize> SerializeAs<[Fr; N]> for ArkFrArray<N> {
        fn serialize_as<S>(source: &[Fr; N], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = Vec::new();
            for fr in source {
                fr.serialize_uncompressed(&mut bytes).unwrap();
            }
            Bytes::serialize_as(&bytes, serializer)
        }
    }
    impl<'de, const N: usize> DeserializeAs<'de, [Fr; N]> for ArkFrArray<N> {
        fn deserialize_as<D>(deserializer: D) -> Result<[Fr; N], D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: Vec<u8> = Bytes::deserialize_as(deserializer)?;
            let mut result = [Fr::default(); N];
            let mut reader = &bytes[..];
            for i in 0..N {
                result[i] = Fr::deserialize_uncompressed(&mut reader).map_err(D::Error::custom)?;
            }
            Ok(result)
        }
    }

    pub struct ArkPath;
    impl SerializeAs<Path<MerkleTreeConfig>> for ArkPath {
        fn serialize_as<S>(
            source: &Path<MerkleTreeConfig>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = Vec::new();
            source.serialize_uncompressed(&mut bytes).unwrap();
            Bytes::serialize_as(&bytes, serializer)
        }
    }
    impl<'de> DeserializeAs<'de, Path<MerkleTreeConfig>> for ArkPath {
        fn deserialize_as<D>(deserializer: D) -> Result<Path<MerkleTreeConfig>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: Vec<u8> = Bytes::deserialize_as(deserializer)?;
            Path::deserialize_uncompressed(&bytes[..]).map_err(D::Error::custom)
        }
    }
}

impl PartialEq for WithdrawalProof {
    fn eq(&self, other: &Self) -> bool {
        self.l2_state_root == other.l2_state_root
            && self.leaf_data == other.leaf_data
            && self.merkle_path.auth_path == other.merkle_path.auth_path
    }
}
impl Eq for WithdrawalProof {}
impl core::hash::Hash for WithdrawalProof {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.l2_state_root.hash(state);
        for fr in &self.leaf_data {
            fr.into_bigint().to_bytes_be().hash(state);
        }
        for p in &self.merkle_path.auth_path {
            <Fr as PrimeField>::into_bigint(p.0.into())
                .to_bytes_be()
                .hash(state);
            p.1.hash(state);
        }
    }
}
