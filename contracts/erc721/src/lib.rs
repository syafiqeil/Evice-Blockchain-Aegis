// contracts/erc721/src/lib.rs

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

    if let Ok(action) = serde_json::from_slice::<state::CallAction>(&call_data) {
        match action {
            state::CallAction::Mint {
                to,
                token_id,
                token_uri,
            } => handlers::mint(to, token_id, token_uri),
            state::CallAction::TransferFrom { from, to, token_id } => {
                handlers::transfer_from(from, to, token_id)
            }
            state::CallAction::Approve { to, token_id } => handlers::approve(to, token_id),
            state::CallAction::SetApprovalForAll { operator, approved } => {
                handlers::set_approval_for_all(operator, approved)
            }

            state::CallAction::BalanceOf { owner } => handlers::balance_of(owner),
            state::CallAction::OwnerOf { token_id } => handlers::owner_of(token_id),
            state::CallAction::TokenURI { token_id } => handlers::token_uri(token_id),
            state::CallAction::GetApproved { token_id } => handlers::get_approved(token_id),
            state::CallAction::IsApprovedForAll { owner, operator } => {
                handlers::is_approved_for_all(owner, operator)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn allocate(size: u32) -> *mut u8 {
    let mut buffer = Vec::with_capacity(size as usize);
    let ptr = buffer.as_mut_ptr();
    core::mem::forget(buffer);
    ptr
}
