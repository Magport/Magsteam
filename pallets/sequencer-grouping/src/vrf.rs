//! VRF logic
use crate::{Config, LocalVrfOutput, RandomnessResults};
use codec::{Decode, Encode};
pub use primitives_vrf::{make_vrf_transcript, PreDigest, VRF_ENGINE_ID, AUTHOR_PUBKEY, VRF_INOUT_CONTEXT};
use sp_core::crypto::ByteArray;
use sp_core::sr25519::Public;

/// VRF output
pub const RANDOMNESS_LENGTH: usize = 32;

/// Gets VRF output from system digests and verifies it using the block author's VrfId
/// Transforms VRF output into randomness value and puts it into `LocalVrfOutput`
/// Fills the `RandomnessResult` associated with the current block if any requests exist
pub(crate) fn verify_and_set_output<T: Config>() {
	let randomness = get_and_verify_randomness::<T>(true);

	LocalVrfOutput::<T>::put(Some(randomness));
	let local_vrf_this_block = frame_system::Pallet::<T>::block_number();
	RandomnessResults::<T>::insert(local_vrf_this_block, Some(randomness));
}

pub(crate) fn get_and_verify_randomness<T: Config>(need_verify: bool) -> T::Hash {
	let mut block_author_vrf_id: Option<Public> = None;
	let PreDigest {
		vrf_output,
		vrf_proof,
	} = <frame_system::Pallet<T>>::digest()
		.logs
		.iter()
		.filter_map(|s| s.as_pre_runtime())
		.filter_map(|(id, mut data)| {
			if id == VRF_ENGINE_ID {
				if let Ok(vrf_digest) = PreDigest::decode(&mut data) {
					let encoded = vrf_digest.encode();
					let hex_string = hex::encode(&encoded);
					Some(vrf_digest)
				} else {
					panic!("VRF digest encoded in pre-runtime digest must be valid");
				}
			} else {
				if id == AUTHOR_PUBKEY {
					block_author_vrf_id = Some(Public::decode(&mut data)
						.expect("author public key encoded in pre-runtime digest must be valid"));
				}
				None
			}
		})
		.next()
		.expect("VRF PreDigest was not included in the digests (check rand key is in keystore)");

	// Verify VRF output + proof using input transcript + block author's VrfId
	if need_verify {
		let block_author_vrf_id =
			block_author_vrf_id.expect("VrfId encoded in pre-runtime digest must be valid");
		let block_author_vrf_id = schnorrkel::PublicKey::from_bytes(block_author_vrf_id.as_slice())
			.expect("Expect VrfId to be valid schnorrkel public key");
		// VRF input is last block's VRF output
		let vrf_input_transcript =
			make_vrf_transcript::<T::Hash>(LocalVrfOutput::<T>::get().unwrap_or_default());
		assert!(
			block_author_vrf_id
				.vrf_verify(vrf_input_transcript.0.clone(), &vrf_output.0, &vrf_proof.0)
				.is_ok(),
			"VRF signature verification failed"
		);
	}

	let randomness = vrf_output.encode();
	T::Hash::decode(&mut &randomness[..])
		.ok()
		.expect("Bytes can be decoded into T::Hash")
}
