// evice_blockchain/src/sequencer_selection.rs

use crate::rpc_client::RpcChainSnapshot;
use crate::Address;
use merlin::Transcript;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

pub trait SequencerSelector {
    fn select_leader(
        &self,
        snapshot: &RpcChainSnapshot,
        selection_material: &[u8],
    ) -> Option<Address>;
}

pub struct StakeWeightedVrfSelector;

impl SequencerSelector for StakeWeightedVrfSelector {
    fn select_leader(
        &self,
        snapshot: &RpcChainSnapshot,
        selection_material: &[u8],
    ) -> Option<Address> {
        let mut lowest_scaled_output: Option<(BigUint, Address)> = None;

        for sequencer_addr in &snapshot.active_sequencers {
            let stake = match snapshot.accounts.get(sequencer_addr) {
                Some((_, staked_amount)) => *staked_amount,
                None => continue,
            };

            let mut transcript = Transcript::new(b"EVICE_L2_SEQUENCER_ELECTION_STAKE_WEIGHTED");
            transcript.append_message(b"selection_material", selection_material);
            transcript.append_message(b"candidate_addr", sequencer_addr.as_ref());

            let mut vrf_input = [0u8; 64];
            transcript.challenge_bytes(b"vrf-input", &mut vrf_input);

            let vrf_hash = Sha256::digest(&vrf_input);
            let vrf_as_uint = BigUint::from_bytes_be(&vrf_hash);

            let scaled_output = &vrf_as_uint / BigUint::from(stake.max(1));

            if lowest_scaled_output.is_none()
                || scaled_output < lowest_scaled_output.as_ref().unwrap().0
            {
                lowest_scaled_output = Some((scaled_output, *sequencer_addr));
            }
        }

        lowest_scaled_output.map(|(_, addr)| addr)
    }
}