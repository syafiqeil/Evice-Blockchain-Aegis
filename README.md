# Evice Blockchain: A PQC & ZK-Rollup L1/L2 Reference Implementation

> **NOTICE (W3F Grant Context):**
>
> This repository serves as the full-stack **Reference Implementation** and Proof-of-Concept for an advanced L1/L2 blockchain.
>
> The core technologies demonstrated here specifically the **Post-Quantum Cryptography (PQC)** module and the **ZK-Proof Aggregation** circuit are currently being proposed to the **Web3 Foundation Grants Program**.
>
> The goal of this grant is to **extract, adapt, and deliver** these battle-tested components as modular **Substrate Pallets** (`pallet-pqc` and `pallet-zk-aggregation`) for use as *public goods* by the entire Polkadot ecosystem.
>
> This repository stands as the primary **evidence of our team's experience** and technical capability to deliver on this grant, as requested in our application feedback.

---

## Project Overview

Evice is a high-performance Layer 1 blockchain platform designed from the ground up to advance the **WASM (WebAssembly) ecosystem**. It addresses two critical, long-term problems facing the Web3 space: **scalability** and **quantum security**.

Our architecture, demonstrated in this repository, is a natively integrated L1/L2 hybrid:

1.  **L1 (Aegis Consensus):** A novel hybrid PoS consensus (Velocity layer for fast confirmations, Gravity layer for absolute finality) serving as a purpose-built settlement layer.
2.  **L2 (Native ZK-Rollup):** A native ZK-Rollup solution featuring an **AggregationCircuit**, allowing multiple L2 batch proofs to be combined into one single, cheap proof for L1 verification.
3.  **WASM Runtime:** We explicitly use a WASM runtime (via `wasmer`) to empower Rust, C++, and Go developers.
4.  **Post-Quantum Security:** We are natively quantum-resistant by using **Dilithium** (a NIST-standardized PQC algorithm) for all L1 transaction and block signatures.

## Core Technologies

This repository demonstrates a complete, full-stack implementation written in Rust:

* **L1 Full Node:** `evice_blockchain/src/main.rs` (Consensus, P2P, RPC, State Machine)
* **L2 Sequencer Node:** `evice_blockchain/src/bin/sequencer.rs` (Batching, Prover Coordination)
* **P2P Networking:** `evice_blockchain/src/p2p.rs` (Built with `libp2p`)
* **State Machine:** `evice_blockchain/src/state.rs` (ParityDB + Keccak Merkle Patricia Trie)
* **ZK Circuits:** `evice_blockchain/src/l2_circuit.rs`, `evice_blockchain/src/l2_aggregation.rs` (Built with `arkworks`)
* **PQC Crypto:** `evice_blockchain/src/crypto.rs` (PQC Dilithium, BLS, VRF)
* **RPC API:** `evice_blockchain/src/rpc.rs`, `evice_blockchain/rpc.proto` (gRPC/Tonic)
* **Developer Tooling:** `evice_blockchain/src/bin/*` (Faucet, Prover, Aggregator, CLI Wallet, etc.)

## Building and Running

(This section assumes you have Rust, cargo, and other dependencies installed.)

### 1. Build the Binaries

This project is a Rust workspace. Build all binaries:

```bash
cargo build --release

### 2. Generate ZK & Crypto Parameters

(These are one-time setup steps.)

# 1. Generate Poseidon params used in ZK circuits
cargo run --release --bin create_poseidon_params

# 2. Generate L2 Batch ZK proving & verifying key
cargo run --release --bin generate_zk_params

# 3. Generate L2 Aggregation ZK proving & verifying key
cargo run --release --bin aggregator -- generate-keys --leaf-vk-path ./verifying_key.bin --agg-pk-path ./agg_proving_key.bin --agg-vk-path ./agg_verifying_key.bin

### 3. Running a Local Testnet

A local testnet script and configuration are provided in /local_testnet (this folder is not committed to git). You must first generate validator keys using the validator-tool:
# Generate assets for 7 local validators
cargo run --release --bin validator_tool -- generate-batch --num-nodes 7

### License


This project is licensed under the Apache License 2.0. Please see the LICENSE and NOTICE files for details.
