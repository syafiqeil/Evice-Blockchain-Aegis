// evice_blockchain/src/governance.rs

use crate::Address;
use bincode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub type ProposalId = u64;

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
pub struct Proposal {
    pub title: String,
    pub description: String,
    pub action: ProposalAction,
}

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
pub enum ProposalAction {
    UpdateParameter {
        key: String,
        value: String,
    },
    Text,
    UpgradeRuntime {
        binary_hash: Vec<u8>,
        download_url: String,
        activation_block_height: u64,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub struct ProposalState {
    pub id: ProposalId,
    pub proposal: Proposal,
    pub proposer: Address,
    pub start_block: u64,
    pub end_block: u64,
    pub yes_votes: u64,
    pub no_votes: u64,
    pub executed: bool,
    pub voters: std::collections::HashSet<Address>,
}
