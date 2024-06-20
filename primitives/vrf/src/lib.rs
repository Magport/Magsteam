#![cfg_attr(not(feature = "std"), no_std)]

//! VRF Key type
use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_application_crypto::{KeyTypeId, RuntimeDebug};
use sp_core::sr25519::vrf::{VrfInput, VrfPreOutput, VrfProof, VrfSignData};
//#[cfg(feature = "std")] <- TODO: Check if this is still needed
use sp_runtime::{BoundToRuntimeAppPublic, ConsensusEngineId};

/// Raw VRF digest.
#[derive(Clone, RuntimeDebug, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub struct VrfDigest {
	/// VRF output
	pub vrf_output: VrfPreOutput,
	/// VRF proof
	pub vrf_proof: VrfProof,
}

impl PartialEq for VrfDigest {
	fn eq(&self, other: &Self) -> bool {
		self.vrf_output == other.vrf_output && self.vrf_proof == other.vrf_proof
	}
}

/// Make VRF transcript from the VrfInput
pub fn make_vrf_transcript<Hash: AsRef<[u8]>>(last_vrf_output: Hash) -> VrfInput {
	VrfInput::new(
		&VRF_ENGINE_ID,
		&[(b"last vrf output", last_vrf_output.as_ref())],
	)
}

pub fn make_vrf_sign_data<Hash: AsRef<[u8]>>(last_vrf_output: Hash) -> VrfSignData {
	make_vrf_transcript(last_vrf_output).into()
}

/// Struct to implement `BoundToRuntimeAppPublic` by assigning Public = VrfId
pub struct VrfSessionKey;

impl BoundToRuntimeAppPublic for VrfSessionKey {
	type Public = VrfId;
}

/// The ConsensusEngineId for VRF keys
pub const VRF_ENGINE_ID: ConsensusEngineId = *b"rand";

/// The KeyTypeId used for VRF keys
pub const VRF_KEY_ID: KeyTypeId = KeyTypeId(VRF_ENGINE_ID);

/// VRFInOut context.
pub static VRF_INOUT_CONTEXT: &[u8] = b"VRFInOutContext";

// The strongly-typed crypto wrappers to be used by VRF in the keystore
mod vrf_crypto {
	use sp_application_crypto::{app_crypto, sr25519};
	app_crypto!(sr25519, crate::VRF_KEY_ID);
}

/// A vrf public key.
pub type VrfId = vrf_crypto::Public;

/// A vrf signature.
pub type VrfSignature = vrf_crypto::Signature;

sp_application_crypto::with_pair! {
	/// A vrf key pair
	pub type VrfPair = vrf_crypto::Pair;
}

sp_api::decl_runtime_apis! {
	pub trait VrfApi {
		fn get_last_vrf_output() -> Option<Block::Hash>;
		fn set_vrf_digest(vrf_digest: VrfDigest, vrf_author_pubkey: VrfId);
	}
}