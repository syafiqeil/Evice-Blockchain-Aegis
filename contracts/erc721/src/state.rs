// contracts/erc721/src/state.rs

use alloc::string::String;
use alloc::vec::Vec;
use evice_contract_sdk::Address;
use serde::{Deserialize, Serialize};

pub type TokenId = u128;

pub fn owner_key(token_id: TokenId) -> Vec<u8> {
    [b"owners/", &token_id.to_be_bytes()[..]].concat()
}
pub fn balance_key(owner: &Address) -> Vec<u8> {
    [b"balances/", owner.as_ref()].concat()
}

pub fn approval_key(token_id: TokenId) -> Vec<u8> {
    [b"approvals/", &token_id.to_be_bytes()[..]].concat()
}

pub fn uri_key(token_id: TokenId) -> Vec<u8> {
    [b"uri/", &token_id.to_be_bytes()[..]].concat()
}
pub fn operator_approval_key(owner: &Address, operator: &Address) -> Vec<u8> {
    [b"operators/", owner.as_ref(), operator.as_ref()].concat()
}

#[derive(Serialize, Deserialize)]
pub enum CallAction {
    // Fungsi Tulis (Write Functions)
    Mint {
        to: Address,
        token_id: TokenId,
        token_uri: String,
    },
    TransferFrom {
        from: Address,
        to: Address,
        token_id: TokenId,
    },
    Approve {
        to: Address,
        token_id: TokenId,
    },
    SetApprovalForAll {
        operator: Address,
        approved: bool,
    },

    // Fungsi Baca (Read-Only Functions)
    BalanceOf {
        owner: Address,
    },
    OwnerOf {
        token_id: TokenId,
    },
    TokenURI {
        token_id: TokenId,
    },
    GetApproved {
        token_id: TokenId,
    },
    IsApprovedForAll {
        owner: Address,
        operator: Address,
    },
}

#[derive(Serialize)]
pub enum Event {
    Transfer {
        from: Address,
        to: Address,
        token_id: TokenId,
    },
    Approval {
        owner: Address,
        approved: Address,
        token_id: TokenId,
    },
    ApprovalForAll {
        owner: Address,
        operator: Address,
        approved: bool,
    },
}
