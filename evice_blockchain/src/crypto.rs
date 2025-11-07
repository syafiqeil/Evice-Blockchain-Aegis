// evice_blockchain/src/crypto.rs

use blst::min_pk::{
    AggregateSignature, PublicKey as BlsPublicKey, SecretKey as BlsSecretKey,
    Signature as BlsSignature,
};
use hash_db::Hasher;
use keccak_hasher::KeccakHasher;
use pqcrypto_dilithium::dilithium2::{
    detached_sign, keypair as dilithium_keypair, verify_detached_signature, DetachedSignature,
    PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey,
};
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
    SecretKey as SecretKeyTrait,
};
use rand::RngCore;
use schnorrkel::Keypair as SchnorrkelKeypair;
use std::collections::HashMap;
use log::warn;
use crate::{
    consensus::{FinalityCertificate, FinalityVote},
    Address, FullPublicKey,
};

pub const PUBLIC_KEY_SIZE: usize = 1312;
pub const ADDRESS_SIZE: usize = 20;
pub const PRIVATE_KEY_SIZE: usize = 2560;
pub const SIGNATURE_SIZE: usize = 2420;
pub const BLS_PUBLIC_KEY_SIZE: usize = 48;
pub const BLS_SECRET_KEY_SIZE: usize = 32;
pub const BLS_SIGNATURE_SIZE: usize = 96;

pub fn public_key_to_address(public_key: &[u8; PUBLIC_KEY_SIZE]) -> Address {
    let hash = KeccakHasher::hash(public_key);
    let mut address_bytes = [0u8; ADDRESS_SIZE];
    address_bytes.copy_from_slice(&hash[hash.len() - ADDRESS_SIZE..]);
    Address(address_bytes)
}

pub struct ValidatorKeys {
    pub signing_keys: KeyPair,
    pub vrf_keys: SchnorrkelKeypair,
    pub bls_secret_key: BlsSecretKey,
}

impl ValidatorKeys {
    pub fn new() -> Self {
        let mut ikm = [0u8; 32];
        rand::rng().fill_bytes(&mut ikm);

        Self {
            signing_keys: KeyPair::new(),
            vrf_keys: SchnorrkelKeypair::generate(),
            bls_secret_key: BlsSecretKey::key_gen(&ikm, &[]).unwrap(),
        }
    }
}

pub struct KeyPair {
    pub public_key: DilithiumPublicKey,
    pub private_key: DilithiumSecretKey,
}

impl KeyPair {
    pub fn new() -> Self {
        let (pk, sk) = dilithium_keypair();
        Self {
            public_key: pk,
            private_key: sk,
        }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
        let signature = detached_sign(message, &self.private_key);
        signature
            .as_bytes()
            .try_into()
            .expect("Signature length mismatch")
    }

    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.public_key
            .as_bytes()
            .try_into()
            .expect("Public key length mismatch")
    }

    pub fn private_key_bytes(&self) -> [u8; PRIVATE_KEY_SIZE] {
        self.private_key
            .as_bytes()
            .try_into()
            .expect("Secret key length mismatch")
    }

    pub fn from_key_bytes(pk_bytes: &[u8], sk_bytes: &[u8]) -> Result<Self, &'static str> {
        let public_key = DilithiumPublicKey::from_bytes(pk_bytes)
            .map_err(|_| "Gagal membuat public key dari bytes: panjang tidak valid")?;

        let private_key = DilithiumSecretKey::from_bytes(sk_bytes)
            .map_err(|_| "Gagal membuat secret key dari bytes: panjang tidak valid")?;

        Ok(Self {
            public_key,
            private_key,
        })
    }
}

pub fn verify(public_key: &FullPublicKey, message: &[u8], signature_bytes: &[u8]) -> bool {
    let pk = match DilithiumPublicKey::from_bytes(public_key.as_ref()) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = match DetachedSignature::from_bytes(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    verify_detached_signature(&sig, message, &pk).is_ok()
}

#[derive(Clone)]
pub struct DkgState {
    pub participants: HashMap<Address, BlsPublicKey>,
    pub threshold: usize,
}

pub fn verify_finality_certificate(dkg_state: &DkgState, cert: &FinalityCertificate) -> bool {
    if cert.aggregated_signature.is_empty() {
        return cert.epoch == 0;
    }
    let Ok(sig) = BlsSignature::from_bytes(&cert.aggregated_signature) else {
        return false;
    };

    let mut pk_refs: Vec<&BlsPublicKey> = Vec::new();
    for voter_addr in &cert.voters {
        if let Some(pk) = dkg_state.participants.get(voter_addr) {
            pk_refs.push(pk);
        } else {
            warn!("[VERIFY CERT] Voter 0x{} dari sertifikat tidak ditemukan di DKG state.", hex::encode(voter_addr.as_ref()));
            return false;
        }
    }

    if pk_refs.len() < dkg_state.threshold {
        return false;
    }

    let result = sig.fast_aggregate_verify(
        true,
        cert.checkpoint_hash.as_slice(),
        b"aegis_finality_vote",
        &pk_refs,
    );
    result == blst::BLST_ERROR::BLST_SUCCESS
}

pub fn aggregate_finality_votes(
    votes: &[FinalityVote],
    threshold: usize,
) -> Option<FinalityCertificate> {
    if votes.len() < threshold {
        return None;
    }

    let first_vote = &votes[0];
    let epoch = first_vote.epoch;
    let checkpoint_hash = &first_vote.checkpoint_hash;

    if !votes
        .iter()
        .all(|v| v.epoch == epoch && v.checkpoint_hash == *checkpoint_hash)
    {
        log::error!("[AGGREGATE] Ditemukan suara finalitas dari epoch/hash yang berbeda. Agregasi dibatalkan.");
        return None;
    }

    let mut unique_votes = std::collections::HashMap::new();
    for vote in votes {
        if let Ok(sig) = BlsSignature::from_bytes(&vote.signature_share) {
            unique_votes.insert(vote.voter_address, sig);
        }
    }

    if unique_votes.len() < threshold {
        return None;
    }

    let mut sorted_voters: Vec<Address> = unique_votes.keys().cloned().collect();
    sorted_voters.sort();

    let sig_refs: Vec<&BlsSignature> = sorted_voters
        .iter()
        .map(|addr| unique_votes.get(addr).unwrap())
        .collect();

    match AggregateSignature::aggregate(&sig_refs, true) {
        Ok(aggregate_sig) => Some(FinalityCertificate {
            checkpoint_hash: checkpoint_hash.clone(),
            epoch,
            aggregated_signature: aggregate_sig.to_signature().to_bytes().to_vec(),
            voters: sorted_voters,
        }),
        Err(e) => {
            log::error!(
                "[AGGREGATE] Kegagalan saat mengagregasi tanda tangan BLS: {:?}",
                e
            );
            None
        }
    }
}
