// contracts/bridge_contract/src/lib.rs

#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use borsh::BorshDeserialize;
use evice_contract_sdk as sdk;

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

    if let Ok(action) = BorshDeserialize::try_from_slice(&call_data) {
        match action {
            state::CallAction::Initialize { daily_limit, owner } => {
                handlers::initialize(daily_limit, owner)
            }
            state::CallAction::Withdraw { amount, proof } => handlers::withdraw(amount, proof),
            state::CallAction::SetDailyLimit { new_limit } => handlers::set_daily_limit(new_limit),
        }
    } else {
        sdk::env::revert("Invalid call data format");
    }
}
