#![cfg_attr(not(feature = "std"), no_std)]

//! VRF pre vrf object and conversion to DigestItem
use codec::{Decode, Encode};
use sp_core::sr25519::vrf::{VrfPreOutput, VrfProof, VrfInput, VrfSignData};
use sp_runtime::{generic::DigestItem, RuntimeDebug, BoundToRuntimeAppPublic, ConsensusEngineId};
use sp_application_crypto::KeyTypeId;

/// Raw VRF pre-vrf.
#[derive(Clone, RuntimeDebug, Encode, Decode)]
pub struct PreDigest {
	/// VRF output
	pub vrf_output: VrfPreOutput,
	/// VRF proof
	pub vrf_proof: VrfProof,
}

/// A vrf item which is usable with moonbeam VRF.
pub trait CompatibleDigestItem: Sized {
	/// Construct a vrf item which contains a VRF pre-vrf.
	fn vrf_pre_digest(seal: PreDigest) -> Self;

	/// If this item is an VRF pre-vrf, return it.
	fn as_vrf_pre_digest(&self) -> Option<PreDigest>;

	/// Construct a vrf item which contains a VRF seal.
	fn vrf_seal(signature: VrfSignature) -> Self;

	/// If this item is a VRF signature, return the signature.
	fn as_vrf_seal(&self) -> Option<VrfSignature>;
}

impl CompatibleDigestItem for DigestItem {
	fn vrf_pre_digest(digest: PreDigest) -> Self {
		DigestItem::PreRuntime(VRF_ENGINE_ID, digest.encode())
	}

	fn as_vrf_pre_digest(&self) -> Option<PreDigest> {
		self.pre_runtime_try_to(&VRF_ENGINE_ID)
	}

	fn vrf_seal(signature: VrfSignature) -> Self {
		DigestItem::Seal(VRF_ENGINE_ID, signature.encode())
	}

	fn as_vrf_seal(&self) -> Option<VrfSignature> {
		self.seal_try_to(&VRF_ENGINE_ID)
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
	}
}
