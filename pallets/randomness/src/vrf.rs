//! VRF logic
use codec::Decode;
use frame_system::pallet_prelude::BlockNumberFor;
use primitives_vrf::{make_vrf_transcript, VRF_INOUT_CONTEXT, VrfDigest, VrfId};
use sp_application_crypto::ByteArray;
use crate::{Config, LatestRandomness, RandomnessResults};

pub const RANDOMNESS_LENGTH: usize = 32;

/// Randomness type required by BABE operations.
pub type Randomness = [u8; RANDOMNESS_LENGTH];

pub(crate) fn verify_and_set_output<T: Config>(block_author_vrf_id: VrfId, vrf_digest: VrfDigest, block: BlockNumberFor<T>) {
	let randomness = get_and_verify_randomness::<T>(block_author_vrf_id, vrf_digest);

	LatestRandomness::<T>::put(randomness);
	RandomnessResults::<T>::insert(block, randomness);
}

fn get_and_verify_randomness<T: Config>(block_author_vrf_id: VrfId, vrf_digest: VrfDigest) -> T::Hash {
	let block_author_vrf_id = schnorrkel::PublicKey::from_bytes(block_author_vrf_id.as_slice())
		.expect("Expect VrfId to be valid schnorrkel public key");
	// VRF input is last block's VRF output
	let vrf_input_transcript =
		make_vrf_transcript::<T::Hash>(LatestRandomness::<T>::get().expect("VRF output not set"));
	// Verify VRF output + proof using input transcript + block author's VrfId
	assert!(
		block_author_vrf_id
			.vrf_verify(vrf_input_transcript.0.clone(), &vrf_digest.vrf_output.0, &vrf_digest.vrf_proof.0)
			.is_ok(),
		"VRF signature verification failed"
	);
	// Transform VrfOutput into randomness bytes stored on-chain
	let randomness: Randomness = vrf_digest.vrf_output
		.0
		.attach_input_hash(&block_author_vrf_id, vrf_input_transcript.0.clone())
		.ok()
		.map(|inout| inout.make_bytes(&VRF_INOUT_CONTEXT))
		.expect("Transforming VrfOutput into randomness bytes failed");
	T::Hash::decode(&mut &randomness[..])
		.ok()
		.expect("Bytes can be decoded into T::Hash")
}
