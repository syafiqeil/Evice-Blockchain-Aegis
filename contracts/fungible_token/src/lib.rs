// contracts/fungible_token/src/lib.rs

#![no_std]
extern crate alloc;

use alloc::vec::Vec;

mod handlers;
mod state;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[no_mangle]
pub extern "C" fn main(call_data_ptr: *const u8, call_data_len: u32) {
    let call_data: Vec<u8> = unsafe {
        Vec::from_raw_parts(
            call_data_ptr as *mut u8,
            call_data_len as usize,
            call_data_len as usize,
        )
    };

    core::mem::forget(call_data.clone());

    if let Ok(action) = borsh::BorshDeserialize::try_from_slice(&call_data) {
        match action {
            state::CallAction::Transfer { to, amount } => handlers::transfer(to, amount),
            state::CallAction::Approve { spender, amount } => handlers::approve(spender, amount),
            state::CallAction::TransferFrom { from, to, amount } => {
                handlers::transfer_from(from, to, amount)
            }

            state::CallAction::BalanceOf { owner } => handlers::balance_of(owner),
            state::CallAction::Allowance { owner, spender } => handlers::allowance(owner, spender),
        }
    } else {
        evice_contract_sdk::env::revert("Invalid call data format");
    }
}
