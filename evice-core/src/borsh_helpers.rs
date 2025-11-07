// evice-core/src/borsh_helpers.rs

use crate::{MerkleTreeConfig, Vec};
use ark_bls12_377::Fr;
use ark_crypto_primitives::merkle_tree::Path;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use borsh::io::{self, Read, Write};

pub fn serialize_fr<W: Write>(fr: &Fr, writer: &mut W) -> io::Result<()> {
    let mut buf = Vec::new();
    fr.serialize_uncompressed(&mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    writer.write_all(&buf)?;
    Ok(())
}

pub fn deserialize_fr<R: Read>(reader: &mut R) -> io::Result<Fr> {
    Fr::deserialize_uncompressed(reader).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

pub fn serialize_leaf<W: Write>(leaf: &[Fr; 2], writer: &mut W) -> io::Result<()> {
    for fr in leaf {
        serialize_fr(fr, writer)?;
    }
    Ok(())
}

pub fn deserialize_leaf<R: Read>(reader: &mut R) -> io::Result<[Fr; 2]> {
    let mut arr = [Fr::default(); 2];
    for i in 0..2 {
        arr[i] = deserialize_fr(reader)?;
    }
    Ok(arr)
}

/// Serialize Merkle Path
pub fn serialize_path<W: Write>(path: &Path<MerkleTreeConfig>, writer: &mut W) -> io::Result<()> {
    let mut buf = Vec::new();
    path.serialize_uncompressed(&mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    writer.write_all(&buf)?;
    Ok(())
}

/// Deserialize Merkle Path
pub fn deserialize_path<R: Read>(reader: &mut R) -> io::Result<Path<MerkleTreeConfig>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Path::<MerkleTreeConfig>::deserialize_uncompressed(&buf[..])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}
