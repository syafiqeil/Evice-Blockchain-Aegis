# Evice Blockchain: A PQC & ZK-Rollup L1/L2 Reference Implementation

## Project Overview

Evice is a high-performance Layer 1 blockchain platform, achieving 600ms average block times, designed from the ground up to advance the **WASM (WebAssembly) ecosystem**. It addresses two critical, long-term problems facing the Web3 space: **scalability** and **quantum security**.

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

## License

This project is licensed under the Apache License 2.0. 



