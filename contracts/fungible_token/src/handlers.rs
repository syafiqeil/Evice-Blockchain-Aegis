// contracts/fungible_token/src/handlers.rs

use crate::state::{allowance_key, balance_key, Event};
use evice_contract_sdk::{env, storage, Address};

fn emit_event(event: Event) {
    let serialized_event = serde_json::to_string(&event).unwrap_or_default();
    env::log_message(&serialized_event);
}

// --- FUNGSI TULIS ---
pub fn transfer(to: Address, amount: u128) {
    let from = env::caller();
    if from == to {
        env::revert("Cannot transfer to self");
    }

    let mut from_balance: u128 = storage::read(&balance_key(&from)).unwrap_or(0);
    if from_balance < amount {
        env::revert("Insufficient balance");
    }

    let mut to_balance: u128 = storage::read(&balance_key(&to)).unwrap_or(0);

    from_balance -= amount;
    to_balance += amount;

    storage::write(&balance_key(&from), &from_balance);
    storage::write(&balance_key(&to), &to_balance);

    emit_event(Event::Transfer {
        from,
        to,
        value: amount,
    });
}

pub fn approve(spender: Address, amount: u128) {
    let owner = env::caller();
    storage::write(&allowance_key(&owner, &spender), &amount);
    emit_event(Event::Approval {
        owner,
        spender,
        value: amount,
    });
}

pub fn transfer_from(from: Address, to: Address, amount: u128) {
    let caller = env::caller();

    let mut allowance: u128 = storage::read(&allowance_key(&from, &caller)).unwrap_or(0);
    if allowance < amount {
        env::revert("Insufficient allowance");
    }

    let mut from_balance: u128 = storage::read(&balance_key(&from)).unwrap_or(0);
    if from_balance < amount {
        env::revert("Insufficient balance");
    }

    let mut to_balance: u128 = storage::read(&balance_key(&to)).unwrap_or(0);

    allowance -= amount;
    from_balance -= amount;
    to_balance += amount;

    storage::write(&allowance_key(&from, &caller), &allowance);
    storage::write(&balance_key(&from), &from_balance);
    storage::write(&balance_key(&to), &to_balance);

    emit_event(Event::Transfer {
        from,
        to,
        value: amount,
    });
}

// --- FUNGSI BACA ---
pub fn balance_of(owner: Address) {
    let balance: u128 = storage::read(&balance_key(&owner)).unwrap_or(0);
    env::return_data(&balance.to_be_bytes());
}

pub fn allowance(owner: Address, spender: Address) {
    let allowance_amount: u128 = storage::read(&allowance_key(&owner, &spender)).unwrap_or(0);
    env::return_data(&allowance_amount.to_be_bytes());
}
