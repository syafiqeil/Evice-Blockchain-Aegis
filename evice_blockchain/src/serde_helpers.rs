// evice_blockchain/src/serde_helpers.rs

use ark_bls12_377::Fr;
use ark_crypto_primitives::merkle_tree::Path;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use evice_core::MerkleTreeConfig;
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
    fn serialize_as<S>(source: &Path<MerkleTreeConfig>, serializer: S) -> Result<S::Ok, S::Error>
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

pub mod option_vec_u8 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{serde_as, Bytes};

    pub fn serialize<S>(vec: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[serde_as]
        #[derive(Serialize)]
        struct Wrapper<'a>(#[serde_as(as = "Option<Bytes>")] &'a Option<Vec<u8>>);
        Wrapper(vec).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[serde_as]
        #[derive(Deserialize)]
        struct Wrapper(#[serde_as(as = "Option<Bytes>")] Option<Vec<u8>>);
        Wrapper::deserialize(deserializer).map(|w| w.0)
    }
}
