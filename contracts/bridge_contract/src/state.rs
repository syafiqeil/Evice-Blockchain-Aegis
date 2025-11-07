// contracts/bridge_contract/src/state.rs

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use evice_core::{Address, WithdrawalProof};

pub const STATE_KEY: &[u8] = b"STATE";

#[derive(BorshSerialize, BorshDeserialize, Debug, Default)]
pub struct BridgeState {
    pub daily_limit: u64,
    pub last_withdrawal_day: u64,
    pub withdrawn_today: u64,
    pub owner: Address,
    pub processed_l2_roots: Vec<Vec<u8>>,
}

#[derive(BorshDeserialize)]
pub enum CallAction {
    Initialize { daily_limit: u64, owner: Address },
    Withdraw { amount: u64, proof: WithdrawalProof },
    SetDailyLimit { new_limit: u64 },
}
