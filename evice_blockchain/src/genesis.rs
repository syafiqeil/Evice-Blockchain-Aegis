// evice_blockchain/src/genesis.rs

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs::File, path::Path};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenesisParameters {
    pub aegis_sub_committee_size: usize,
    pub aegis_gravity_epoch_length: u64,
    pub proposer_timeout_ms: u64,
    pub max_transactions_per_block: usize,
    pub minimum_stake: String,
    pub proposal_voting_period_blocks: u64,

    // --- PARAMETER EKONOMI DINAMIS ---
    #[serde(default = "default_base_reward_factor")]
    pub base_reward_factor: u64,
    #[serde(default = "default_total_supply")]
    pub initial_total_supply: u64,
    #[serde(default = "default_blocks_per_epoch")]
    pub blocks_per_epoch_for_reward: u64,
}

fn default_base_reward_factor() -> u64 { 64 } 
fn default_total_supply() -> u64 { 1_000_000_000 }
fn default_blocks_per_epoch() -> u64 { 28800 }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Genesis {
    pub genesis_time: u64,
    pub chain_id: String,
    pub parameters: GenesisParameters,
    pub accounts: HashMap<String, GenesisAccount>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenesisAccount {
    pub public_key: String,
    pub balance: String,
    pub staked_amount: String,
    pub vrf_public_key: Option<String>,
    pub bls_public_key: Option<String>,
    pub network_identity: Option<String>,
}

impl Genesis {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let genesis: Self = serde_json::from_reader(file)?;
        Ok(genesis)
    }
}
