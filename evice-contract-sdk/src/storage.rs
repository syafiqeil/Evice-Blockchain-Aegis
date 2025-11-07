// evice-contract-sdk/src/storage.rs

use borsh::{BorshDeserialize, BorshSerialize};

// ==============================================================================
//           IMPLEMENTASI ON-CHAIN (AKTIF DENGAN --features "on-chain")
// ==============================================================================
#[cfg(feature = "on-chain")]
mod implementation {
    use super::{BorshDeserialize, BorshSerialize};
    use crate::bridge::host;

    // Menulis data ke penyimpanan persisten blockchain.
    pub fn write<T: BorshSerialize>(key: &[u8], value: &T) {
        let encoded = borsh::to_vec(value).expect("Borsh encoding failed in on-chain storage");
        host::set_storage(key, &encoded);
    }

    // Membaca data dari penyimpanan persisten blockchain.
    pub fn read<T: BorshDeserialize>(key: &[u8]) -> Option<T> {
        host::get_storage(key).and_then(|encoded| T::try_from_slice(&encoded).ok())
    }
}

// ==============================================================================
//        IMPLEMENTASI IN-MEMORY / MOCK (AKTIF SECARA DEFAULT UNTUK TES)
// ==============================================================================
#[cfg(not(feature = "on-chain"))]
mod implementation {
    extern crate alloc;
    use super::{BorshDeserialize, BorshSerialize};
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use spin::{Once, RwLock};

    #[derive(Default)]
    pub struct MockStorage {
        pub data: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    static GLOBAL_STORAGE: Once<Arc<RwLock<MockStorage>>> = Once::new();

    fn get_storage() -> &'static Arc<RwLock<MockStorage>> {
        GLOBAL_STORAGE.call_once(|| Arc::new(RwLock::new(MockStorage::default())))
    }

    // Menulis data ke penyimpanan mock in-memory.
    pub fn write<T: BorshSerialize>(key: &[u8], value: &T) {
        let encoded = borsh::to_vec(value).expect("Borsh encoding failed in mock storage");
        get_storage().write().data.insert(key.to_vec(), encoded);
    }

    // Membaca data dari penyimpanan mock in-memory.
    pub fn read<T: BorshDeserialize>(key: &[u8]) -> Option<T> {
        get_storage()
            .read()
            .data
            .get(key)
            .and_then(|encoded| T::try_from_slice(encoded).ok())
    }
}

pub use implementation::{read, write};

// Saat Men-deploy Kontrak ke Blockchain
// cargo build --target wasm32-unknown-unknown --release --features "on-chain"
