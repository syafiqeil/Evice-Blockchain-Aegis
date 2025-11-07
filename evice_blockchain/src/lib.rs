// evice_blockchain/src/lib.rs

use bincode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
use keccak_hasher::KeccakHasher;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use sha2::Digest;
use std::cmp::Ordering;
use std::convert::AsRef;
use trie_db::TrieLayout;

use crate::blockchain::{DoubleSignEvidence, Signature};
use crate::crypto::{public_key_to_address, PUBLIC_KEY_SIZE};
use crate::governance::Proposal;

pub use evice_core::{Address, Leaf, MerkleTreeConfig, WithdrawalProof};

pub mod blockchain;
pub mod consensus;
pub mod crypto;
pub mod genesis;
pub mod governance;
pub mod keystore;
pub mod l2_aggregation;
pub mod l2_circuit;
pub mod mempool;
pub mod metrics;
pub mod p2p;
pub mod rpc;
pub mod rpc_client;
pub mod sequencer_selection;
pub mod serde_helpers;
pub mod snapshot;
pub mod state;
pub mod trie_codec;
pub mod wasm_runtime;
pub mod block_tree;

#[derive(Debug)]
pub struct EviceTrieLayout;
impl TrieLayout for EviceTrieLayout {
    type Hash = KeccakHasher;
    type Codec = crate::trie_codec::ProductionNodeCodec<KeccakHasher>;
    const USE_EXTENSION: bool = false;
    const ALLOW_EMPTY: bool = true;
    const MAX_INLINE_VALUE: Option<u32> = Some(32);
}

pub type VrfPublicKeyBytes = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct FullPublicKey(#[serde(with = "serde_bytes")] pub [u8; PUBLIC_KEY_SIZE]);

impl BorshSerialize for FullPublicKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
    }
}

impl BorshDeserialize for FullPublicKey {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        reader.read_exact(&mut bytes)?;
        Ok(FullPublicKey(bytes))
    }
}

impl AsRef<[u8]> for FullPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Default for FullPublicKey {
    fn default() -> Self {
        Self([0u8; PUBLIC_KEY_SIZE])
    }
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
    Hash,
    Encode,
    Decode,
)]
pub enum TransactionData {
    Transfer {
        recipient: Address,
        amount: u64,
    },
    Stake {
        amount: u64,
    },
    ReportDoubleSigning {
        evidence: DoubleSignEvidence,
    },
    ReportInvalidState {
        offending_header: blockchain::BlockHeader,
        #[serde(with = "serde_bytes")]
        computed_state_root: Vec<u8>,
    },
    SubmitProposal {
        proposal: Proposal,
    },
    CastVote {
        proposal_id: u64,
        vote: bool,
    },
    SubmitRollupBatch {
        #[serde(with = "serde_bytes")]
        old_state_root: Vec<u8>,
        #[serde(with = "serde_bytes")]
        new_state_root: Vec<u8>,
        #[serde(with = "serde_bytes")]
        compressed_batch: Vec<u8>,
        #[serde(with = "serde_bytes")]
        zk_proof: Vec<u8>,
        #[serde(default)]
        is_test_tx: bool,
        #[serde(with = "serde_bytes")]
        vrf_output: Vec<u8>,
        #[serde(with = "serde_bytes")]
        vrf_proof: Vec<u8>,
        #[serde_as(as = "Vec<Bytes>")]
        dac_signatures: Vec<Signature>,
    },
    SubmitAggregateRollupBatch {
        #[serde(with = "serde_bytes")]
        initial_state_root: Vec<u8>,
        #[serde(with = "serde_bytes")]
        final_state_root: Vec<u8>,
        #[serde(with = "serde_bytes")]
        aggregated_proof: Vec<u8>,
        num_batches: u32,
    },
    DepositToL2 {
        amount: u64,
    },
    UpdateVrfKey {
        #[serde(with = "serde_bytes")]
        new_vrf_public_key: VrfPublicKeyBytes,
    },
    RegisterAsSequencer,
    DeregisterAsSequencer,
    DeployContract {
        #[serde(with = "serde_bytes")]
        code: Vec<u8>,
    },
    CallContract {
        contract_address: Address,
        #[serde(with = "serde_bytes")]
        call_data: Vec<u8>,
    },
    // WithdrawFromTreasury {
    //     recipient: Address,
    //     amount: u64,
    //     #[serde_as(as = "Vec<Bytes>")]
    //     approvals: Vec<Signature>,
    // },
    UpdateNetworkIdentity {
        #[serde(with = "serde_bytes")]
        multiaddr: Vec<u8>,
    },
    ImAlive,
}

impl TransactionData {
    pub fn base_gas_cost(&self) -> u64 {
        const BASE_TX_GAS: u64 = 21_000;
        match self {
            TransactionData::Transfer { .. } => BASE_TX_GAS,
            TransactionData::Stake { .. } => BASE_TX_GAS + 5_000,
            TransactionData::SubmitProposal { proposal } => {
                BASE_TX_GAS + 10_000 + (proposal.description.len() as u64 * 10)
            }
            TransactionData::CastVote { .. } => BASE_TX_GAS + 2_000,
            TransactionData::ReportDoubleSigning { .. } => BASE_TX_GAS + 15_000,
            TransactionData::ReportInvalidState { .. } => BASE_TX_GAS + 25_000,
            TransactionData::DepositToL2 { .. } => BASE_TX_GAS + 20_000,
            TransactionData::SubmitRollupBatch {
                compressed_batch, ..
            } => BASE_TX_GAS + 300_000 + (compressed_batch.len() as u64 * 50),
            TransactionData::SubmitAggregateRollupBatch { num_batches, .. } => {
                BASE_TX_GAS + 500_000 + (u64::from(*num_batches) * 10_000)
            }
            TransactionData::DeployContract { code } => {
                BASE_TX_GAS + 150_000 + (code.len() as u64 * 200)
            }
            TransactionData::CallContract { .. } => BASE_TX_GAS + 5_000,
            TransactionData::UpdateVrfKey { .. } => BASE_TX_GAS + 7_000,
            TransactionData::RegisterAsSequencer | TransactionData::DeregisterAsSequencer => {
                BASE_TX_GAS + 10_000
            }
            // TransactionData::WithdrawFromTreasury { approvals, .. } => {
            //     BASE_TX_GAS + 25_000 + (approvals.len() as u64 * 5_000)
            // }
            TransactionData::UpdateNetworkIdentity { multiaddr } => {
                BASE_TX_GAS + 1_000 + (multiaddr.len() as u64 * 20)
            }
            TransactionData::ImAlive => BASE_TX_GAS,
        }
    }
}

#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, Eq, Encode, Decode,
)]
pub struct Transaction {
    pub sender_public_key: FullPublicKey,
    pub data: TransactionData,
    pub nonce: u64,
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    #[serde(with = "serde_bytes")]
    pub signature: Signature,
    pub chain_id: String,
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        self.message_hash() == other.message_hash()
    }
}

impl Ord for Transaction {
    fn cmp(&self, other: &Self) -> Ordering {
        const FAKE_BASE_FEE: u64 = 10;
        let self_effective_tip = self
            .max_fee_per_gas
            .saturating_sub(FAKE_BASE_FEE)
            .min(self.max_priority_fee_per_gas);
        let other_effective_tip = other
            .max_fee_per_gas
            .saturating_sub(FAKE_BASE_FEE)
            .min(other.max_priority_fee_per_gas);
        self_effective_tip
            .cmp(&other_effective_tip)
            .then_with(|| other.nonce.cmp(&self.nonce))
    }
}

impl PartialOrd for Transaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::hash::Hash for Transaction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.message_hash().hash(state);
    }
}

impl Transaction {
    pub fn sender(&self) -> Address {
        public_key_to_address(&self.sender_public_key.0)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.chain_id.as_bytes());
        data.extend_from_slice(self.sender_public_key.as_ref());
        data.extend_from_slice(
            &bincode::encode_to_vec(&self.data, bincode::config::standard()).unwrap(),
        );
        data.extend_from_slice(&self.nonce.to_be_bytes());
        data.extend_from_slice(&self.max_fee_per_gas.to_be_bytes());
        data.extend_from_slice(&self.max_priority_fee_per_gas.to_be_bytes());
        data
    }

    pub fn message_hash(&self) -> Vec<u8> {
        let data = self.canonical_bytes();
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}
