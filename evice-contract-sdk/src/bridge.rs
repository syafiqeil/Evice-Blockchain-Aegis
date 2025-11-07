// evice-contract-sdk/src/bridge.rs

use crate::Address;
use alloc::vec;
use alloc::vec::Vec;

#[link(wasm_import_module = "env")]
extern "C" {
    pub fn read_storage(
        key_ptr: *const u8,
        key_len: u32,
        value_ptr: *mut u8,
        value_len: u32,
    ) -> u32;
    pub fn write_storage(key_ptr: *const u8, key_len: u32, value_ptr: *const u8, value_len: u32);
    pub fn get_caller(caller_ptr: *mut u8);
    pub fn ret(data_ptr: *const u8, data_len: u32);
    pub fn log(message_ptr: *const u8, message_len: u32);
    pub fn revert(message_ptr: *const u8, message_len: u32);
    pub fn get_block_timestamp() -> u64;
    pub fn transfer_native_token(recipient_ptr: *const u8, recipient_len: u32, amount: u64);
    pub fn poseidon_two_to_one(
        left_input_ptr: *const u8,
        right_input_ptr: *const u8,
        output_ptr: *mut u8,
    );
    pub fn get_l2_state_root(output_ptr: *mut u8);
}

pub mod host {
    use super::*;

    pub fn get_storage(key: &[u8]) -> Option<Vec<u8>> {
        let mut output = vec![0u8; 1024];
        let bytes_read = unsafe {
            read_storage(
                key.as_ptr(),
                key.len() as u32,
                output.as_mut_ptr(),
                output.len() as u32,
            )
        };
        if bytes_read > 0 {
            Some(output[..bytes_read as usize].to_vec())
        } else {
            None
        }
    }

    pub fn set_storage(key: &[u8], value: &[u8]) {
        unsafe {
            write_storage(
                key.as_ptr(),
                key.len() as u32,
                value.as_ptr(),
                value.len() as u32,
            );
        }
    }

    pub fn caller() -> Address {
        let mut caller_bytes: Address = [0; 20];
        unsafe {
            get_caller(caller_bytes.as_mut_ptr());
        }
        caller_bytes
    }

    pub fn return_data(data: &[u8]) {
        unsafe {
            ret(data.as_ptr(), data.len() as u32);
        }
    }

    pub fn log_message(message: &str) {
        unsafe {
            log(message.as_ptr(), message.len() as u32);
        }
    }

    pub fn block_timestamp() -> u64 {
        unsafe { get_block_timestamp() }
    }

    pub fn native_transfer(recipient: &Address, amount: u64) {
        unsafe {
            transfer_native_token(recipient.as_ptr(), recipient.len() as u32, amount);
        }
    }

    pub fn poseidon_two_to_one(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut output = [0u8; 32];
        unsafe {
            super::poseidon_two_to_one(left.as_ptr(), right.as_ptr(), output.as_mut_ptr());
        }
        output
    }

    pub fn l2_state_root() -> [u8; 32] {
        let mut output = [0u8; 32];
        unsafe {
            get_l2_state_root(output.as_mut_ptr());
        }
        output
    }

    pub fn revert(message: &str) {
        unsafe {
            super::revert(message.as_ptr(), message.len() as u32);
        }
    }
}
