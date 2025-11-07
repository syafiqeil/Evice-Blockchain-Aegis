// evice-contract-sdk/src/env.rs

use crate::{bridge, Address};

pub fn caller() -> Address {
    bridge::host::caller()
}

pub fn return_data(data: &[u8]) {
    bridge::host::return_data(data);
}

pub fn log_message(message: &str) {
    bridge::host::log_message(message);
}

#[inline]
pub fn revert(message: &str) {
    bridge::host::revert(message);
}
