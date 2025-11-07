// evice-contract-sdk/src/lib.rs

#![no_std]
extern crate alloc;

pub mod bridge;
pub mod env;
pub mod storage;

pub type Address = [u8; 20];
pub type Balance = u128;
