// src/consensus.rs

use bincode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
use libp2p::PeerId;
use log::warn;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use sha2::{Digest, Sha256}; 
use std::num::NonZeroUsize; 
use std::time::Instant;
use tokio::sync::RwLock;
use lru::LruCache; 

use crate::crypto::KeyPair;
use crate::{
    blockchain::{Block, BlockHeader},
    Address, Signature, Transaction,
};

#[derive(Clone)]
pub struct ConsensusState {
    pub core_state: Arc<RwLock<CoreConsensusState>>,
    pub pending_proposals: Arc<RwLock<HashMap<Vec<u8>, PendingBlock>>>,
    pub gravity_layer: Arc<RwLock<GravityLayerState>>,
    pub proposal_queues: Arc<RwLock<ProposalQueues>>,
    pub recently_processed_hashes: Arc<RwLock<LruCache<[u8; 32], ()>>>,
}

pub struct CoreConsensusState {
    pub current_round: u64,
    pub current_step: u64,
    pub step_start_time: Instant,
    pub highest_seen_qc: QuorumCertificate,
    pub velocity_votes: HashMap<Vec<u8>, Vec<VelocityVote>>,
    pub processed_optimistic_blocks: HashSet<Vec<u8>>,
    pub optimistically_confirmed_blocks: Vec<Block>,
}

pub struct GravityLayerState {
    pub current_epoch: u64,
    pub finality_votes: HashMap<u64, HashMap<Address, FinalityVote>>,
    pub last_finalized_block_hash: Vec<u8>,
}

pub struct ProposalQueues {
    pub pending_proposals_waiting_for_parent:
        HashMap<Vec<u8>, Vec<(ConsensusMessage, PeerId, Option<Vec<Transaction>>)>>,
    pub pending_proposals_awaiting_parent_state:
        HashMap<Vec<u8>, Vec<(ConsensusMessage, PeerId, Option<Vec<Transaction>>)>>,
    pub premature_proposals:
        HashMap<u64, Vec<(ConsensusMessage, PeerId, Option<Vec<Transaction>>)>>,
    pub stale_qc_request: HashMap<Vec<u8>, (u64, Instant)>,
    pub pending_qc_waiting_for_block: HashMap<Vec<u8>, Vec<(QuorumCertificate, PeerId)>>,
}

impl ConsensusState {
    pub fn new(initial_qc: QuorumCertificate, initial_block_hash: Vec<u8>) -> Self {
        Self {
            core_state: Arc::new(RwLock::new(CoreConsensusState {
                current_round: 0,
                current_step: 0,
                step_start_time: Instant::now(),
                highest_seen_qc: initial_qc.clone(),
                velocity_votes: HashMap::new(),
                processed_optimistic_blocks: HashSet::new(),
                optimistically_confirmed_blocks: Vec::new(),
            })),
            pending_proposals: Arc::new(RwLock::new(HashMap::new())),
            gravity_layer: Arc::new(RwLock::new(GravityLayerState {
                current_epoch: 0,
                finality_votes: HashMap::new(),
                last_finalized_block_hash: initial_block_hash,
            })),
            proposal_queues: Arc::new(RwLock::new(ProposalQueues {
                pending_proposals_waiting_for_parent: HashMap::new(),
                pending_proposals_awaiting_parent_state: HashMap::new(),
                premature_proposals: HashMap::new(),
                stale_qc_request: HashMap::new(),
                pending_qc_waiting_for_block: HashMap::new(),
            })),
            recently_processed_hashes: Arc::new(RwLock::new(LruCache::new(NonZeroUsize::new(1000).unwrap()))),
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct PendingBlock {
    pub header: BlockHeader,
    pub transactions: Vec<crate::Transaction>,
    pub parent_qc: QuorumCertificate,
    pub round: u64,
}

// --- Lapisan Velocity (Konfirmasi Cepat) ---
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct VelocityVote {
    pub round_id: u64,
    pub block_hash: Vec<u8>,
    pub voter_address: Address,
    #[serde(with = "serde_bytes")]
    pub signature: Signature,
}

impl VelocityVote {
    pub fn sign(mut self, keypair: &KeyPair) -> Self {
        let data_to_sign = self.canonical_bytes(&keypair.public_key_bytes());
        self.signature = keypair.sign(&data_to_sign);
        self
    }

    pub fn canonical_bytes(&self, voter_public_key: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.round_id.to_be_bytes());
        data.extend_from_slice(&self.block_hash);
        data.extend_from_slice(voter_public_key);
        data
    }

    pub fn collect_verified_votes<'a>(
        votes: impl IntoIterator<Item = &'a VelocityVote>,
        blockchain: &crate::blockchain::Blockchain,
        expected_round: u64,
    ) -> Option<Vec<(Address, Signature)>> {
        let mut verified_signatures = Vec::new();
        let mut unique_voters = std::collections::HashSet::new();
        let vote_list: Vec<_> = votes.into_iter().collect();

        if vote_list.is_empty() {
            return None;
        }

        for vote in vote_list.iter().filter(|v| v.round_id == expected_round) {
            if !unique_voters.insert(vote.voter_address) {
                continue;
            }

            if let Ok(Some(voter_account)) = blockchain.state.get_account(&vote.voter_address) {
                let data_to_verify =
                    vote.canonical_bytes(voter_account.signing_public_key.as_ref());

                if crate::crypto::verify(
                    &voter_account.signing_public_key,
                    &data_to_verify,
                    &vote.signature,
                ) {
                    verified_signatures.push((vote.voter_address, vote.signature));
                } else {
                    warn!("[QC COLLECT] Menerima suara dengan tanda tangan tidak valid dari 0x{} untuk ronde target #{}, suara diabaikan.", hex::encode(vote.voter_address.as_ref()), expected_round);
                    return None;
                }
            } else {
                warn!(
                    "[QC COLLECT] Tidak dapat menemukan akun untuk voter 0x{}, suara diabaikan.",
                    hex::encode(vote.voter_address.as_ref())
                );
                return None;
            }
        }
        Some(verified_signatures)
    }
}

#[serde_as]
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct OptimisticConfirmation {
    pub header: BlockHeader,
    #[serde_as(as = "Vec<Bytes>")]
    pub transaction_hashes: Vec<Vec<u8>>,
    pub parent_qc: QuorumCertificate,
    pub round: u64,
}

// --- Lapisan Gravity (Finalitas Absolut) ---
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct FinalityVote {
    pub checkpoint_hash: Vec<u8>,
    pub epoch: u64,
    pub voter_address: Address,
    #[serde(with = "serde_bytes")]
    pub signature_share: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FinalityCertificate {
    pub checkpoint_hash: Vec<u8>,
    pub epoch: u64,
    #[serde(with = "serde_bytes")]
    pub aggregated_signature: Vec<u8>,
    pub voters: Vec<Address>,
}

// --- Enum Pesan Konsensus Utama ---
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub enum ConsensusMessage {
    // Pesan Lapisan Velocity
    AegisBlockProposal(Box<Block>),
    AegisVelocityVote(VelocityVote),
    AegisNewQuorumCertificate(QuorumCertificate),

    // Pesan Lapisan Gravity
    AegisInitiateFinality {
        epoch: u64,
        checkpoint_hash: Vec<u8>,
    },
    AegisFinalityVote(FinalityVote),
    AegisFinalityCertificate(FinalityCertificate),
}

impl ConsensusMessage {
    pub fn hash(&self) -> [u8; 32] {
        borsh::to_vec(self)
            .map(|encoded| Sha256::digest(&encoded).into())
            .unwrap_or_default()
    }
}


#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct PartialVote {
    pub block_hash: Vec<u8>,
    pub view_number: u64,
    pub voter_address: Address,
    #[serde(with = "serde_bytes")]
    pub signature_share: Vec<u8>,
}

#[serde_as]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
)]
pub struct QuorumCertificate {
    pub block_hash: Vec<u8>,
    pub view_number: u64,
    #[serde_as(as = "Vec<(_, Bytes)>")]
    pub signatures: Vec<(Address, Signature)>,
}

impl QuorumCertificate {
    pub fn genesis_qc() -> Self {
        Self {
            block_hash: vec![0; 32],
            view_number: 0,
            signatures: vec![],
        }
    }
}