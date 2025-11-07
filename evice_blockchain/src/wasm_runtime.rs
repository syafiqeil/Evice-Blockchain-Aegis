// src/wasm_runtime.rs 

use crate::{
    state::{StateMachine, TrieSession, COL_CONTRACT_STORAGE},
    blockchain::BlockchainError,
    Address,
};
use hash_db::Hasher;
use keccak_hasher::KeccakHasher;
use std::sync::{Arc, Mutex};
use wasmer::{
    imports, Function, FunctionEnv, FunctionEnvMut, Instance, 
    Memory, Module, Store, TypedFunction, Engine,
    sys::{CompilerConfig, Cranelift},
};
use wasmer_middlewares::metering::{self, MeteringPoints};
use wasmer::wasmparser::Operator;
use std::string::String;
use std::vec::Vec;
use std::fmt;

const GAS_COST_READ_STORAGE: u64 = 200;
const GAS_COST_WRITE_STORAGE: u64 = 5000;
const GAS_COST_GET_CALLER: u64 = 50;
const GAS_COST_GET_TIMESTAMP: u64 = 40;
const GAS_COST_NATIVE_TRANSFER: u64 = 3000;

pub struct HostState {
    pub storage_session: TrieSession,
    pub caller: Address,
    pub remaining_gas: u64,
    pub memory: Option<Memory>,
    pub return_data: Option<Vec<u8>>,
    pub logs: Vec<String>,
    pub block_timestamp: u64,
    pub pending_transfers: Vec<(Address, u64)>,
}

impl fmt::Debug for HostState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostState")
         .field("caller", &self.caller)
         .field("remaining_gas", &self.remaining_gas)
         .field("memory", &self.memory.is_some()) 
         .field("return_data", &self.return_data)
         .field("logs", &self.logs)
         .finish_non_exhaustive() 
    }
}

#[derive(Debug)]
pub struct ExecutionResult {
    pub new_storage_root: Vec<u8>,
    pub gas_used: u64,
    pub return_data: Option<Vec<u8>>,
    pub logs: Vec<String>,
    pub reverted: bool,
    pub revert_message: String,
    pub requested_transfers: Vec<(Address, u64)>,
}

fn read_storage(
    env: FunctionEnvMut<Arc<Mutex<HostState>>>,
    key_ptr: u32,
    key_len: u32,
    value_ptr: u32,
    value_len: u32,
) -> u32 {
    let mut host_state = env.data().lock().unwrap();
    if host_state.remaining_gas < GAS_COST_READ_STORAGE { panic!("Out of gas for reading storage"); }
    host_state.remaining_gas -= GAS_COST_READ_STORAGE;

    let memory = host_state.memory.as_ref().expect("Memory should be present");
    let view = memory.view(&env);
    
    let mut key_bytes = vec![0u8; key_len as usize];
    view.read(key_ptr as u64, &mut key_bytes).expect("Failed to read key from WASM memory");
    
    let hashed_key = KeccakHasher::hash(&key_bytes);
    let mut bytes_to_write: u32 = 0;

    if let Ok(Some(value_vec)) = host_state.storage_session.get(hashed_key.as_ref()) {
        let write_len = std::cmp::min(value_vec.len(), value_len as usize);
        let value_slice = &value_vec[..write_len];
        view.write(value_ptr as u64, value_slice).expect("Failed to write to WASM memory");
        bytes_to_write = write_len as u32;
    }
    
    bytes_to_write
}

fn write_storage(env: FunctionEnvMut<Arc<Mutex<HostState>>>, key_ptr: u32, key_len: u32, value_ptr: u32, value_len: u32) {
    let mut host_state = env.data().lock().unwrap();
    if host_state.remaining_gas < GAS_COST_WRITE_STORAGE { panic!("Out of gas"); }
    host_state.remaining_gas -= GAS_COST_WRITE_STORAGE;
    let memory = host_state.memory.as_ref().expect("Memory not set");
    let view = memory.view(&env);
    
    let mut key_bytes = vec![0u8; key_len as usize];
    view.read(key_ptr as u64, &mut key_bytes).expect("Failed to read key from WASM memory");
    
    let mut value_bytes = vec![0u8; value_len as usize];
    view.read(value_ptr as u64, &mut value_bytes).expect("Failed to read value from WASM memory");

    let hashed_key = KeccakHasher::hash(&key_bytes);
    host_state.storage_session.insert(hashed_key.as_ref(), &value_bytes).unwrap();
}

fn get_caller(env: FunctionEnvMut<Arc<Mutex<HostState>>>, caller_ptr: u32) {
    let host_state = env.data().lock().unwrap();
    if host_state.remaining_gas < GAS_COST_GET_CALLER { panic!("Out of gas"); }
    let memory = host_state.memory.as_ref().expect("Memory not set");
    let view = memory.view(&env);
    view.write(caller_ptr as u64, host_state.caller.as_ref()).unwrap();
}

fn ret(env: FunctionEnvMut<Arc<Mutex<HostState>>>, data_ptr: u32, data_len: u32) {
    let mut host_state = env.data().lock().unwrap();
    let memory = host_state.memory.as_ref().expect("Memory not set");
    let view = memory.view(&env);
    
    let mut data = vec![0u8; data_len as usize];
    view.read(data_ptr as u64, &mut data).expect("Failed to read return data");
    
    host_state.return_data = Some(data);
}

fn log(env: FunctionEnvMut<Arc<Mutex<HostState>>>, message_ptr: u32, message_len: u32) {
    let mut host_state = env.data().lock().unwrap();
    let memory = host_state.memory.as_ref().expect("Memory not set");
    let view = memory.view(&env);

    let mut message_bytes = vec![0u8; message_len as usize];
    view.read(message_ptr as u64, &mut message_bytes).expect("Failed to read log message bytes");
    let message = String::from_utf8(message_bytes).unwrap_or_else(|_| "Invalid UTF-8 in log".to_string());
    
    host_state.logs.push(message);
}

fn revert(env: FunctionEnvMut<Arc<Mutex<HostState>>>, message_ptr: u32, message_len: u32) {
    let host_state = env.data().lock().unwrap();
    let memory = host_state.memory.as_ref().expect("Memory not set");
    let view = memory.view(&env);
    
    let mut message_bytes = vec![0u8; message_len as usize];
    view.read(message_ptr as u64, &mut message_bytes).expect("Failed to read revert message bytes");
    let message = String::from_utf8(message_bytes).unwrap_or_else(|_| "Invalid UTF-8 in revert message".to_string());

    panic!("Contract reverted: {}", message);
}

/// Mengembalikan timestamp dari blok saat ini.
fn get_block_timestamp(env: FunctionEnvMut<Arc<Mutex<HostState>>>) -> u64 {
    let mut host_state = env.data().lock().unwrap();
    if host_state.remaining_gas < GAS_COST_GET_TIMESTAMP { panic!("Out of gas"); }
    host_state.remaining_gas -= GAS_COST_GET_TIMESTAMP;
    
    host_state.block_timestamp
}

/// Mencatat permintaan transfer token native dari kontrak ke sebuah alamat.
/// Transfer aktual akan dieksekusi oleh runtime L1 setelah eksekusi WASM selesai.
fn transfer_native_token(
    env: FunctionEnvMut<Arc<Mutex<HostState>>>,
    recipient_ptr: u32,
    recipient_len: u32,
    amount: u64,
) {
    let mut host_state = env.data().lock().unwrap();
    if host_state.remaining_gas < GAS_COST_NATIVE_TRANSFER { panic!("Out of gas"); }
    host_state.remaining_gas -= GAS_COST_NATIVE_TRANSFER;

    let memory = host_state.memory.as_ref().expect("Memory not set");
    let view = memory.view(&env);

    let mut recipient_bytes = vec![0u8; recipient_len as usize];
    view.read(recipient_ptr as u64, &mut recipient_bytes).expect("Failed to read recipient address");
    let recipient_address = Address(recipient_bytes.try_into().expect("Invalid recipient address length"));

    host_state.pending_transfers.push((recipient_address, amount));
}

pub fn execute_contract(
    state_machine: &StateMachine,
    code: &[u8],
    storage_root: Option<Vec<u8>>,
    caller: Address,
    call_data: &[u8],
    gas_limit: u64,
    block_timestamp: u64,
) -> Result<ExecutionResult, BlockchainError> {
    let cost_function = |op: &Operator| -> u64 {
        match op {
            // Operasi dasar (sangat cepat)
            Operator::Nop { .. } | Operator::Drop { .. } | Operator::Block { .. } |
            Operator::Loop { .. } | Operator::If { .. } | Operator::Else { .. } |
            Operator::End { .. } | Operator::Br { .. } | Operator::BrIf { .. } |
            Operator::BrTable { .. } | Operator::Return { .. } | Operator::Unreachable { .. } |
            Operator::LocalGet { .. } | Operator::LocalSet { .. } | Operator::LocalTee { .. } |
            Operator::GlobalGet { .. } | Operator::GlobalSet { .. } |
            Operator::I32Const { .. } | Operator::I64Const { .. } => 1,

            // Operasi perbandingan dan aritmatika sederhana (sedikit lebih mahal)
            Operator::I32Eqz { .. } | Operator::I32Eq { .. } | Operator::I32Ne { .. } |
            Operator::I32LtS { .. } | Operator::I32LtU { .. } | Operator::I32GtS { .. } |
            Operator::I32GtU { .. } | Operator::I32LeS { .. } | Operator::I32LeU { .. } |
            Operator::I32GeS { .. } | Operator::I32GeU { .. } |
            Operator::I64Eqz { .. } | Operator::I64Eq { .. } | Operator::I64Ne { .. } |
            Operator::I64LtS { .. } | Operator::I64LtU { .. } | Operator::I64GtS { .. } |
            Operator::I64GtU { .. } | Operator::I64LeS { .. } | Operator::I64LeU { .. } |
            Operator::I64GeS { .. } | Operator::I64GeU { .. } |
            Operator::I32Add { .. } | Operator::I32Sub { .. } | Operator::I64Add { .. } | 
            Operator::I64Sub { .. } => 3,

            // Operasi aritmatika kompleks (lebih mahal)
            Operator::I32Mul { .. } | Operator::I64Mul { .. } => 5,
            Operator::I32DivS { .. } | Operator::I32DivU { .. } | Operator::I32RemS { .. } |
            Operator::I32RemU { .. } => 8,
            Operator::I64DivS { .. } | Operator::I64DivU { .. } | Operator::I64RemS { .. } |
            Operator::I64RemU { .. } => 10,

            // Operasi memori (sangat mahal karena akses di luar register)
            Operator::I32Load { .. } | Operator::I64Load { .. } |
            Operator::I32Store { .. } | Operator::I64Store { .. } => 100,
            
            // Operasi yang dapat menyebabkan state bloat (paling mahal)
            // Mencegah kontrak memperluas memori secara berlebihan dengan biaya murah.
            Operator::MemoryGrow { .. } => 1000, 
            
            // Operasi pemanggilan (mahal karena mengubah stack frame)
            Operator::Call { .. } => 150,
            Operator::CallIndirect { .. } => 250,

            // Default untuk operasi lain yang belum tercakup
            _ => 2,
        }
    };
   
    let metering = Arc::new(metering::Metering::new(gas_limit, cost_function));
    
    let mut cranelift = Cranelift::new();
    cranelift.push_middleware(metering.clone());
    
    let engine = Engine::from(cranelift);
    let mut store = Store::new(engine);
    
    let module = Module::new(&store, code)?;

    let storage_session = state_machine.create_trie_session(
        storage_root.as_ref().map_or_else(Default::default, |r| r.as_slice().try_into().unwrap()),
        COL_CONTRACT_STORAGE,
    );
    
    let host_state = Arc::new(Mutex::new(HostState {
        storage_session,
        caller,
        remaining_gas: gas_limit,
        memory: None,
        return_data: None,
        logs: Vec::new(),
        block_timestamp,
        pending_transfers: Vec::new(),
    }));
    
    let env = FunctionEnv::new(&mut store, host_state.clone());

    let import_object = imports! {
        "env" => {
            "read_storage" => Function::new_typed_with_env(&mut store, &env, read_storage),
            "write_storage" => Function::new_typed_with_env(&mut store, &env, write_storage),
            "get_caller" => Function::new_typed_with_env(&mut store, &env, get_caller),
            "ret" => Function::new_typed_with_env(&mut store, &env, ret),
            "log" => Function::new_typed_with_env(&mut store, &env, log),
            "revert" => Function::new_typed_with_env(&mut store, &env, revert),
            "get_block_timestamp" => Function::new_typed_with_env(&mut store, &env, get_block_timestamp),
            "transfer_native_token" => Function::new_typed_with_env(&mut store, &env, transfer_native_token),
        }
    };

    let instance = Instance::new(&mut store, &module, &import_object)?;
    
    let memory = instance.exports.get_memory("memory")?.clone();
    env.as_ref(&store).lock().unwrap().memory = Some(memory.clone());

    let malloc: TypedFunction<u32, u32> = instance.exports.get_typed_function(&mut store, "allocate")?;
    let call_data_ptr = malloc.call(&mut store, call_data.len() as u32)?;
    memory.view(&store).write(call_data_ptr as u64, call_data)?;

    let main_fn: TypedFunction<(u32, u32), ()> = instance.exports.get_typed_function(&mut store, "main")?;
    
    let execution_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        main_fn.call(&mut store, call_data_ptr, call_data.len() as u32)
    }));
    
    let remaining_points = match metering::get_remaining_points(&mut store, &instance) {
        MeteringPoints::Remaining(points) => points,
        MeteringPoints::Exhausted => 0,
    };

    let final_host_state = Arc::try_unwrap(host_state)
        .expect("Arc should have only one strong reference")
        .into_inner()
        .expect("Mutex should not be poisoned");

    let final_remaining_gas = std::cmp::min(remaining_points, final_host_state.remaining_gas);
    let gas_used = gas_limit - final_remaining_gas;

    match execution_result {
        Ok(Ok(_)) => { 
            let new_root = final_host_state.storage_session.commit()?;
            Ok(ExecutionResult {
                new_storage_root: new_root.as_ref().to_vec(),
                gas_used,
                return_data: final_host_state.return_data,
                logs: final_host_state.logs,
                reverted: false,
                revert_message: String::new(),
                requested_transfers: final_host_state.pending_transfers,
            })
        },
        Ok(Err(e)) => { 
            Ok(ExecutionResult {
                new_storage_root: storage_root.unwrap_or_default(),
                gas_used: gas_limit,
                return_data: None,
                logs: Vec::new(),
                reverted: true,
                revert_message: e.to_string(), 
                requested_transfers: Vec::new(),
            })
        }
        Err(panic_info) => { 
            let message = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic error".to_string()
            };

            Ok(ExecutionResult {
                new_storage_root: storage_root.unwrap_or_default(),
                gas_used: gas_limit,
                return_data: None,
                logs: Vec::new(),
                reverted: true,
                revert_message: message,
                requested_transfers: Vec::new(),
            })
        }
    }
}