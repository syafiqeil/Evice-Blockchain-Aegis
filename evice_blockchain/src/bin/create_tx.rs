// evice_blockchain/src/bin/create_tx.rs

use borsh::BorshSerialize;
use clap::{Parser, Subcommand};
use evice_blockchain::{
    blockchain::{BlockHeader, DoubleSignEvidence},
    crypto::{KeyPair, ADDRESS_SIZE, SIGNATURE_SIZE},
    genesis::Genesis,
    governance::{Proposal, ProposalAction},
    keystore::Keystore,
    rpc_client::RpcClient,
    FullPublicKey, Transaction, TransactionData,
};
use evice_core::{Address, WithdrawalProof};
use rpassword::read_password;
use serde_json::json;
use sha2::Digest;
use std::fs;

#[derive(BorshSerialize)]
pub enum BridgeCallAction {
    Initialize { daily_limit: u64, owner: Address },
    Withdraw { amount: u64, proof: WithdrawalProof },
    SetDailyLimit { new_limit: u64 },
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(long, default_value = "https://127.0.0.1:8080")]
    l1_rpc_url: String,
    #[clap(long, default_value = "https://127.0.0.1:8081")]
    l2_rpc_url: String,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Transfer {
        #[clap(long)]
        keystore_path: String,
        #[clap(long)]
        recipient: String,
        #[clap(long)]
        amount: u64,
        #[clap(long)]
        nonce: u64,
        #[clap(long, default_value_t = 20)]
        max_fee_per_gas: u64,
        #[clap(long, default_value_t = 1)]
        max_priority_fee_per_gas: u64,
    },
    Stake {
        #[clap(long)]
        keystore_path: String,
        #[clap(long)]
        amount: u64,
        #[clap(long)]
        nonce: u64,
        #[clap(long, default_value_t = 20)]
        max_fee_per_gas: u64,
        #[clap(long, default_value_t = 1)]
        max_priority_fee_per_gas: u64,
    },
    SubmitProposal {
        #[clap(long)]
        keystore_path: String,
        #[clap(long)]
        nonce: u64,
        #[clap(long)]
        title: String,
        #[clap(long)]
        description: String,
        #[clap(long, default_value_t = 20)]
        max_fee_per_gas: u64,
        #[clap(long, default_value_t = 1)]
        max_priority_fee_per_gas: u64,
        #[clap(subcommand)]
        action: Option<ProposalActionCommand>,
    },
    CastVote {
        #[clap(long)]
        keystore_path: String,
        #[clap(long)]
        nonce: u64,
        #[clap(long)]
        proposal_id: u64,
        #[clap(long)]
        vote_yes: bool,
        #[clap(long, default_value_t = 20)]
        max_fee_per_gas: u64,
        #[clap(long, default_value_t = 1)]
        max_priority_fee_per_gas: u64,
    },
    ReportDoubleSign {
        #[clap(long)]
        keystore_path: String,
        #[clap(long)]
        header1: String,
        #[clap(long)]
        header2: String,
        #[clap(long)]
        nonce: u64,
        #[clap(long, default_value_t = 20)]
        max_fee_per_gas: u64,
        #[clap(long, default_value_t = 1)]
        max_priority_fee_per_gas: u64,
    },
    Deposit {
        #[clap(long)]
        keystore_path: String,
        #[clap(long)]
        nonce: u64,
        #[clap(long)]
        amount: u64,
        #[clap(long, default_value_t = 20)]
        max_fee_per_gas: u64,
        #[clap(long, default_value_t = 1)]
        max_priority_fee_per_gas: u64,
    },
    CreateRollupBatch {
        #[clap(long)]
        keystore_path: String,
        #[clap(long)]
        nonce: u64,
        #[clap(long)]
        old_state_root_hex: String,
        #[clap(long, default_value_t = 20)]
        max_fee_per_gas: u64,
        #[clap(long, default_value_t = 1)]
        max_priority_fee_per_gas: u64,
        #[clap(
            long,
            help = "Daftar tanda tangan dari komite DAC (dalam format hex), dipisahkan koma.",
            use_value_delimiter = true,
            default_value = ""
        )]
        dac_signatures: Vec<String>,
    },
    SubmitAggregateRollupBatch {
        #[clap(long)]
        keystore_path: String,
        #[clap(long)]
        nonce: u64,
        #[clap(long)]
        initial_state_root_hex: String,
        #[clap(long)]
        final_state_root_hex: String,
        #[clap(long)]
        aggregated_proof_path: String,
        #[clap(long, default_value_t = 2)]
        num_batches: u32,
        #[clap(long, default_value_t = 30)]
        max_fee_per_gas: u64,
        #[clap(long, default_value_t = 2)]
        max_priority_fee_per_gas: u64,
    },
    L2Transfer {
        #[clap(long)]
        keystore_path: String,
        #[clap(long)]
        to_address_hex: String,
        #[clap(long)]
        amount: u64,
        #[clap(long)]
        nonce: u64,
        #[clap(long, default_value_t = 20)]
        max_fee_per_gas: u64,
        #[clap(long, default_value_t = 2)]
        max_priority_fee_per_gas: u64,
    },
    L2Withdraw {
        #[clap(long)]
        keystore_path: String,
        #[clap(long)]
        nonce: u64,
        #[clap(long)]
        amount: u64,
        #[clap(long, default_value_t = 20)]
        max_fee_per_gas: u64,
        #[clap(long, default_value_t = 1)]
        max_priority_fee_per_gas: u64,
    },
    UpdateVrfKey {
        #[clap(long)]
        keystore_path: String,
        #[clap(long)]
        nonce: u64,
        #[clap(long)]
        new_vrf_public_key: String,
        #[clap(long, default_value_t = 20)]
        max_fee_per_gas: u64,
        #[clap(long, default_value_t = 1)]
        max_priority_fee_per_gas: u64,
    },
    // WithdrawTreasury {
    //     #[clap(long, help = "Path ke keystore pembuat transaksi (inisiator).")]
    //     keystore_path: String,
    //     #[clap(long)]
    //     nonce: u64,
    //     #[clap(long, help = "Alamat penerima dana.")]
    //     recipient: String,
    //     #[clap(long)]
    //     amount: u64,
    //     #[clap(
    //         long,
    //         help = "Daftar tanda tangan persetujuan dari anggota komite (dalam format hex), dipisahkan koma.",
    //         use_value_delimiter = true
    //     )]
    //     approvals: Vec<String>,
    //     #[clap(long, default_value_t = 30)]
    //     max_fee_per_gas: u64,
    //     #[clap(long, default_value_t = 2)]
    //     max_priority_fee_per_gas: u64,
    // },
}

#[derive(Subcommand, Debug)]
enum ProposalActionCommand {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut rpc_client = RpcClient::new(cli.l1_rpc_url, cli.l2_rpc_url).await?;

    match cli.command {
        Commands::L2Transfer {
            keystore_path,
            to_address_hex,
            amount,
            nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => {
            println!("🚀 Mengirim transaksi L2 ke sequencer...");

            let keystore = Keystore::from_path(&keystore_path)?;
            println!("🔒 Masukkan kata sandi untuk keystore '{}':", keystore_path);
            let password = read_password()?;
            let private_key_bytes = keystore.decrypt(&password)?;

            let mut pub_key_bytes = [0u8; ADDRESS_SIZE];
            hex::decode_to_slice(&keystore.address, &mut pub_key_bytes)?;
            let keypair = KeyPair::from_key_bytes(&pub_key_bytes, &private_key_bytes)?;

            let from_address_hex = keystore.address;

            let mut l2_tx_map = serde_json::Map::new();
            l2_tx_map.insert("from".to_string(), json!(from_address_hex));
            l2_tx_map.insert("to".to_string(), json!(to_address_hex));
            l2_tx_map.insert("amount".to_string(), json!(amount));
            l2_tx_map.insert("nonce".to_string(), json!(nonce));
            l2_tx_map.insert("max_fee_per_gas".to_string(), json!(max_fee_per_gas));
            l2_tx_map.insert(
                "max_priority_fee_per_gas".to_string(),
                json!(max_priority_fee_per_gas),
            );

            let mut data_to_sign = Vec::new();
            data_to_sign.extend_from_slice(l2_tx_map["from"].as_str().unwrap().as_bytes());
            data_to_sign.extend_from_slice(l2_tx_map["to"].as_str().unwrap().as_bytes());
            data_to_sign.extend_from_slice(&amount.to_be_bytes());
            data_to_sign.extend_from_slice(&nonce.to_be_bytes());
            data_to_sign.extend_from_slice(&max_fee_per_gas.to_be_bytes());
            data_to_sign.extend_from_slice(&max_priority_fee_per_gas.to_be_bytes());
            let message_hash = sha2::Sha256::digest(&data_to_sign);

            let signature = keypair.sign(&message_hash);
            l2_tx_map.insert("signature".to_string(), json!(hex::encode(signature)));

            match rpc_client.submit_l2_transaction(json!(l2_tx_map)).await {
                Ok(response) => println!("✅ Transaksi L2 berhasil dikirim. Respons: {}", response),
                Err(e) => eprintln!("❌ Gagal mengirim transaksi L2: {}", e),
            }
        }
        Commands::L2Withdraw {
            keystore_path,
            nonce,
            amount,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => {
            println!("🚀 Memulai proses penarikan L2 -> L1 via Bridge Contract...");

            let keystore = Keystore::from_path(&keystore_path)?;
            let sender_address_bytes = hex::decode(&keystore.address)?;
            let sender_address_array: [u8; ADDRESS_SIZE] = sender_address_bytes
                .try_into()
                .map_err(|_| "Alamat keystore memiliki panjang yang salah")?;
            let sender_address = Address(sender_address_array);

            let l2_root_hex = rpc_client.get_l2_state_root().await?;
            println!("  - State root L2 saat ini di L1: {}", l2_root_hex);
            println!("  - Meminta bukti Merkle dari sequencer...");
            let merkle_proof = rpc_client
                .get_l2_merkle_proof(sender_address, &l2_root_hex)
                .await?;
            println!("  - Bukti Merkle berhasil didapatkan.");

            let withdrawal_proof = WithdrawalProof {
                l2_state_root: hex::decode(l2_root_hex)?,
                leaf_data: merkle_proof.leaf_data,
                merkle_path: merkle_proof.merkle_path,
            };

            let action = BridgeCallAction::Withdraw {
                amount,
                proof: withdrawal_proof,
            };
            let call_data = borsh::to_vec(&action)?;

            let data = TransactionData::CallContract {
                contract_address: evice_blockchain::state::L2_BRIDGE_ADDRESS,
                call_data,
            };

            let tx = create_and_sign_l1_tx(
                keystore,
                nonce,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                data,
            )?;

            println!("  - Mengirim transaksi `CallContract` ke L1...");
            match rpc_client.submit_l1_transaction(&tx).await {
                Ok(tx_hash) => {
                    println!("✅ Transaksi penarikan berhasil dikirim. Hash: {}", tx_hash)
                }
                Err(e) => eprintln!("❌ Gagal mengirim transaksi penarikan: {}", e),
            }
        }
        Commands::CreateRollupBatch {
            keystore_path,
            nonce,
            old_state_root_hex,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            dac_signatures,
        } => {
            println!("🚀 Membuat template transaksi Rollup Batch...");
            let old_state_root = hex::decode(old_state_root_hex)?;

            let final_dac_signatures = dac_signatures
                .into_iter()
                .filter(|s| !s.is_empty())
                .map(|s| hex::decode(s).map(|v| v.try_into().unwrap_or([0; SIGNATURE_SIZE])))
                .collect::<Result<Vec<_>, _>>()?;

            let data = TransactionData::SubmitRollupBatch {
                old_state_root,
                new_state_root: vec![0; 32],
                compressed_batch: vec![],
                zk_proof: vec![],
                vrf_output: vec![0; 32],
                vrf_proof: vec![0; 64],
                is_test_tx: false,
                dac_signatures: final_dac_signatures,
            };

            let keystore = Keystore::from_path(&keystore_path)?;
            let tx = create_and_sign_l1_tx(
                keystore,
                nonce,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                data,
            )?;

            let json_output = serde_json::to_string_pretty(&tx)?;
            println!("{}", json_output);
        }
        _ => {
            let (keystore_path, nonce_opt, max_fee, max_priority, tx_data) =
                parse_l1_commands(cli.command)?;

            let keystore = Keystore::from_path(&keystore_path)?;
            let sender_address = Address(hex::decode(&keystore.address)?.try_into().unwrap());

            let nonce = match nonce_opt {
                Some(n) => n,
                None => rpc_client.get_l1_account_info(sender_address).await?.nonce,
            };

            let tx = create_and_sign_l1_tx(keystore, nonce, max_fee, max_priority, tx_data)?;

            println!("Mengirim transaksi L1 ke node...");
            match rpc_client.submit_l1_transaction(&tx).await {
                Ok(tx_hash) => println!("✅ Transaksi L1 berhasil dikirim. Hash: {}", tx_hash),
                Err(e) => eprintln!("❌ Gagal mengirim transaksi L1: {}", e),
            }
        }
    }
    Ok(())
}

fn parse_l1_commands(
    command: Commands,
) -> Result<(String, Option<u64>, u64, u64, TransactionData), Box<dyn std::error::Error>> {
    match command {
        Commands::Transfer {
            keystore_path,
            recipient,
            amount,
            nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => {
            let mut recipient_bytes = [0u8; ADDRESS_SIZE];
            hex::decode_to_slice(recipient.trim_start_matches("0x"), &mut recipient_bytes)?;
            let data = TransactionData::Transfer {
                recipient: Address(recipient_bytes),
                amount,
            };
            Ok((
                keystore_path,
                Some(nonce),
                max_fee_per_gas,
                max_priority_fee_per_gas,
                data,
            ))
        }
        Commands::Stake {
            keystore_path,
            amount,
            nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => {
            let data = TransactionData::Stake { amount };
            Ok((
                keystore_path,
                Some(nonce),
                max_fee_per_gas,
                max_priority_fee_per_gas,
                data,
            ))
        }
        Commands::SubmitProposal {
            keystore_path,
            nonce,
            title,
            description,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            action,
        } => {
            let proposal_action = match action {
                // Some(ProposalActionCommand::FundTransfer { recipient, amount }) => {
                //     let mut recipient_bytes = [0u8; ADDRESS_SIZE];
                //     hex::decode_to_slice(&recipient, &mut recipient_bytes)?;
                //     ProposalAction::FundTransfer { recipient: Address(recipient_bytes), amount }
                // }
                None => ProposalAction::Text,
            };

            let proposal = Proposal {
                title,
                description,
                action: proposal_action,
            };
            let data = TransactionData::SubmitProposal { proposal };
            Ok((
                keystore_path,
                Some(nonce),
                max_fee_per_gas,
                max_priority_fee_per_gas,
                data,
            ))
        }
        Commands::CastVote {
            keystore_path,
            nonce,
            proposal_id,
            vote_yes,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => {
            let data = TransactionData::CastVote {
                proposal_id,
                vote: vote_yes,
            };
            Ok((
                keystore_path,
                Some(nonce),
                max_fee_per_gas,
                max_priority_fee_per_gas,
                data,
            ))
        }
        Commands::ReportDoubleSign {
            keystore_path,
            header1,
            header2,
            nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => {
            let h1: BlockHeader = serde_json::from_str(&header1)?;
            let h2: BlockHeader = serde_json::from_str(&header2)?;
            let evidence = DoubleSignEvidence {
                header1: h1,
                header2: h2,
            };
            let data = TransactionData::ReportDoubleSigning { evidence };
            Ok((
                keystore_path,
                Some(nonce),
                max_fee_per_gas,
                max_priority_fee_per_gas,
                data,
            ))
        }
        Commands::Deposit {
            keystore_path,
            nonce,
            amount,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => {
            let data = TransactionData::DepositToL2 { amount };
            Ok((
                keystore_path,
                Some(nonce),
                max_fee_per_gas,
                max_priority_fee_per_gas,
                data,
            ))
        }
        Commands::UpdateVrfKey {
            keystore_path,
            nonce,
            new_vrf_public_key,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => {
            let mut vrf_key_bytes = [0u8; 32];
            hex::decode_to_slice(
                new_vrf_public_key.trim_start_matches("0x"),
                &mut vrf_key_bytes,
            )?;
            let data = TransactionData::UpdateVrfKey {
                new_vrf_public_key: vrf_key_bytes,
            };
            Ok((
                keystore_path,
                Some(nonce),
                max_fee_per_gas,
                max_priority_fee_per_gas,
                data,
            ))
        }
        // Commands::WithdrawTreasury {
        //     keystore_path,
        //     nonce,
        //     recipient,
        //     amount,
        //     approvals,
        //     max_fee_per_gas,
        //     max_priority_fee_per_gas,
        // } => {
        //     let mut recipient_bytes = [0u8; ADDRESS_SIZE];
        //     hex::decode_to_slice(recipient.trim_start_matches("0x"), &mut recipient_bytes)?;

        //     let approval_signatures = approvals
        //         .into_iter()
        //         .map(|s| {
        //             hex::decode(s.trim_start_matches("0x")).map(|v| {
        //                 v.try_into()
        //                     .unwrap_or([0; evice_blockchain::crypto::SIGNATURE_SIZE])
        //             })
        //         })
        //         .collect::<Result<Vec<_>, _>>()?;

        //     let data = TransactionData::WithdrawFromTreasury {
        //         recipient: Address(recipient_bytes),
        //         amount,
        //         approvals: approval_signatures,
        //     };
        //     Ok((
        //         keystore_path,
        //         Some(nonce),
        //         max_fee_per_gas,
        //         max_priority_fee_per_gas,
        //         data,
        //     ))
        // }
        Commands::SubmitAggregateRollupBatch {
            keystore_path,
            nonce,
            initial_state_root_hex,
            final_state_root_hex,
            aggregated_proof_path,
            num_batches,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => {
            let data = TransactionData::SubmitAggregateRollupBatch {
                initial_state_root: hex::decode(initial_state_root_hex.trim_start_matches("0x"))?,
                final_state_root: hex::decode(final_state_root_hex.trim_start_matches("0x"))?,
                aggregated_proof: fs::read(aggregated_proof_path)?,
                num_batches,
            };
            Ok((
                keystore_path,
                Some(nonce),
                max_fee_per_gas,
                max_priority_fee_per_gas,
                data,
            ))
        }
        _ => unreachable!(),
    }
}

fn create_and_sign_l1_tx(
    keystore: Keystore,
    nonce: u64,
    max_fee: u64,
    max_priority: u64,
    tx_data: TransactionData,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    println!("🔒 Masukkan kata sandi untuk keystore:");
    let password = read_password()?;
    let private_key_bytes_vec = keystore.decrypt(&password)?;

    let public_key_bytes = hex::decode(&keystore.public_key)?;
    let keypair = KeyPair::from_key_bytes(&public_key_bytes, &private_key_bytes_vec)?;

    let sender_public_key = FullPublicKey(
        public_key_bytes
            .try_into()
            .expect("Public key length is wrong from keystore"),
    );

    let genesis = Genesis::from_file("genesis.json")?;
    let chain_id = genesis.chain_id;

    let mut tx = Transaction {
        sender_public_key,
        data: tx_data,
        nonce,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: max_priority,
        signature: [0u8; SIGNATURE_SIZE],
        chain_id,
    };

    let data_to_sign_hash = tx.message_hash();
    tx.signature = keypair.sign(&data_to_sign_hash);

    Ok(tx)
}
