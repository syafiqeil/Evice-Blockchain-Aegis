// contracts/bridge_contract/src/handlers.rs

extern crate alloc;
use crate::state::{BridgeState, STATE_KEY};
use alloc::format;
use ark_bls12_377::Fr;
use ark_ff::{BigInteger, PrimeField};
use evice_contract_sdk as sdk;
use evice_core::{Address, WithdrawalProof};

fn verify_merkle_proof(proof: &WithdrawalProof) {
    let valid_l2_root_bytes = sdk::bridge::host::l2_state_root();

    if proof.l2_state_root != valid_l2_root_bytes {
        sdk::env::revert("Proof is for an outdated or invalid L2 state root");
    }

    let mut leaf_0_bytes = [0u8; 32];
    leaf_0_bytes.copy_from_slice(&proof.leaf_data[0].into_bigint().to_bytes_be());
    let mut leaf_1_bytes = [0u8; 32];
    leaf_1_bytes.copy_from_slice(&proof.leaf_data[1].into_bigint().to_bytes_be());

    let mut current_hash_bytes =
        sdk::bridge::host::poseidon_two_to_one(&leaf_0_bytes, &leaf_1_bytes);

    let mut current_leaf_index = proof.merkle_path.leaf_index;
    for node_hash in &proof.merkle_path.auth_path {
        let mut node_bytes = [0u8; 32];
        node_bytes.copy_from_slice(&node_hash.into_bigint().to_bytes_be());

        if current_leaf_index % 2 == 0 {
            current_hash_bytes =
                sdk::bridge::host::poseidon_two_to_one(&current_hash_bytes, &node_bytes);
        } else {
            current_hash_bytes =
                sdk::bridge::host::poseidon_two_to_one(&node_bytes, &current_hash_bytes);
        }
        current_leaf_index /= 2;
    }

    if current_hash_bytes != valid_l2_root_bytes {
        sdk::env::revert("Invalid Merkle proof");
    }
}

pub fn initialize(daily_limit: u64, owner: Address) {
    if sdk::storage::read::<BridgeState>(STATE_KEY).is_some() {
        sdk::env::revert("Contract already initialized");
    }
    let initial_state = BridgeState {
        daily_limit,
        owner,
        ..Default::default()
    };
    sdk::storage::write(STATE_KEY, &initial_state);
    sdk::env::log_message("Bridge initialized");
}

pub fn set_daily_limit(new_limit: u64) {
    let mut state: BridgeState = sdk::storage::read(STATE_KEY).expect("Contract not initialized");
    if state.owner != sdk::env::caller() {
        sdk::env::revert("Only owner can set daily limit");
    }
    state.daily_limit = new_limit;
    sdk::storage::write(STATE_KEY, &state);
}

pub fn withdraw(amount: u64, proof: WithdrawalProof) {
    verify_merkle_proof(&proof);

    let caller_address = sdk::env::caller();
    let caller_fr = Fr::from_be_bytes_mod_order(&caller_address);
    if proof.leaf_data[0] != caller_fr {
        sdk::env::revert("Caller does not match the owner in the withdrawal proof");
    }

    let mut state: BridgeState = sdk::storage::read(STATE_KEY).expect("Contract not initialized");

    if state.processed_l2_roots.contains(&proof.l2_state_root) {
        sdk::env::revert("Withdrawal proof already used");
    }

    let current_day = sdk::bridge::host::block_timestamp() / (1000 * 60 * 60 * 24);
    if current_day > state.last_withdrawal_day {
        state.withdrawn_today = 0;
        state.last_withdrawal_day = current_day;
    }
    if state.withdrawn_today + amount > state.daily_limit {
        sdk::env::revert("Exceeds daily withdrawal limit");
    }

    sdk::bridge::host::native_transfer(&caller_address, amount);

    state.withdrawn_today += amount;
    state.processed_l2_roots.push(proof.l2_state_root);
    sdk::storage::write(STATE_KEY, &state);

    let log_msg = format!(
        "Withdrawal of {} to {:?} successful",
        amount, caller_address
    );
    sdk::env::log_message(&log_msg);
}
