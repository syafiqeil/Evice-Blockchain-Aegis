// contracts/erc721/src/handlers.rs

use crate::state::{
    approval_key, balance_key, operator_approval_key, owner_key, uri_key, Event, TokenId,
};
use alloc::string::String;
use evice_contract_sdk::{env, storage, Address};

fn emit_event(event: Event) {
    let serialized_event = serde_json::to_string(&event).unwrap_or_default();
    env::log_message(&serialized_event);
}

pub fn mint(to: Address, token_id: TokenId, token_uri: String) {
    // (Di dunia nyata, tambahkan pemeriksaan `env::caller()` untuk memastikan hanya admin yang bisa mint)
    if storage::read::<Address>(&owner_key(token_id)).is_some() {
        panic!("Token ID already exists");
    }
    storage::write(&owner_key(token_id), &to);
    storage::write(&uri_key(token_id), &token_uri);
    let mut balance: u128 = storage::read(&balance_key(&to)).unwrap_or(0);
    balance += 1;
    storage::write(&balance_key(&to), &balance);
    emit_event(Event::Transfer {
        from: Address::default(),
        to,
        token_id,
    });
}

pub fn transfer_from(from: Address, to: Address, token_id: TokenId) {
    let caller = env::caller();
    let owner: Address = storage::read(&owner_key(token_id)).expect("Token does not exist");
    if from != owner {
        panic!("'from' address is not the owner");
    }

    let approved_operator: Option<Address> = storage::read(&approval_key(token_id));
    let is_operator: bool = storage::read(&operator_approval_key(&owner, &caller)).unwrap_or(false);

    if caller != owner && approved_operator != Some(caller) && !is_operator {
        panic!("Caller is not the owner or approved for this token or operator");
    }

    storage::write(&owner_key(token_id), &to);
    storage::write(&approval_key(token_id), &Address::default());

    let mut from_balance: u128 = storage::read(&balance_key(&from)).unwrap_or(1);
    from_balance -= 1;
    storage::write(&balance_key(&from), &from_balance);

    let mut to_balance: u128 = storage::read(&balance_key(&to)).unwrap_or(0);
    to_balance += 1;
    storage::write(&balance_key(&to), &to_balance);

    emit_event(Event::Transfer { from, to, token_id });
}

pub fn approve(to: Address, token_id: TokenId) {
    let caller = env::caller();
    let owner: Address = storage::read(&owner_key(token_id)).expect("Token does not exist");
    if caller != owner {
        panic!("Only the owner can approve a transfer");
    }

    storage::write(&approval_key(token_id), &to);
    emit_event(Event::Approval {
        owner,
        approved: to,
        token_id,
    });
}

pub fn set_approval_for_all(operator: Address, approved: bool) {
    let owner = env::caller();
    storage::write(&operator_approval_key(&owner, &operator), &approved);
    emit_event(Event::ApprovalForAll {
        owner,
        operator,
        approved,
    });
}

pub fn balance_of(owner: Address) {
    let balance: u128 = storage::read(&balance_key(&owner)).unwrap_or(0);
    env::return_data(&balance.to_be_bytes());
}

pub fn owner_of(token_id: TokenId) {
    let owner: Address = storage::read(&owner_key(token_id)).expect("Token does not exist");
    env::return_data(owner.as_ref());
}

pub fn token_uri(token_id: TokenId) {
    let uri: String = storage::read(&uri_key(token_id)).expect("Token URI does not exist");
    env::return_data(uri.as_bytes());
}

pub fn get_approved(token_id: TokenId) {
    let approved: Address = storage::read(&approval_key(token_id)).unwrap_or_default();
    env::return_data(approved.as_ref());
}

pub fn is_approved_for_all(owner: Address, operator: Address) {
    let is_approved: bool =
        storage::read(&operator_approval_key(&owner, &operator)).unwrap_or(false);
    env::return_data(&[is_approved as u8]);
}
