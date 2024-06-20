#![cfg_attr(not(feature = "std"), no_std)]

use std::sync::Arc;
use codec::{Decode, Encode};
use sp_inherents::{Error, InherentData, InherentIdentifier, IsFatalError};
use sp_runtime::RuntimeString;
use sp_keystore::KeystorePtr;
use primitives_vrf::VrfApi;

#[derive(Encode)]
#[cfg_attr(feature = "std", derive(Debug, Decode))]
pub enum InherentError {
	Other(RuntimeString),
}

impl IsFatalError for InherentError {
	fn is_fatal_error(&self) -> bool {
		match *self {
			InherentError::Other(_) => true,
		}
	}
}

impl InherentError {
	/// Try to create an instance ouf of the given identifier and data.
	#[cfg(feature = "std")]
	pub fn try_from(id: &InherentIdentifier, data: &[u8]) -> Option<Self> {
		if id == &INHERENT_IDENTIFIER {
			<InherentError as codec::Decode>::decode(&mut &*data).ok()
		} else {
			None
		}
	}
}

/// The InherentIdentifier to set the babe randomness results
pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"vrf-rand";

pub struct InherentDataProvider<B, C> {
	pub client: Arc<C>,
	pub keystore: KeystorePtr,
	pub key: primitives_vrf::VrfId,
	pub parent: sp_core::H256,
	_marker: std::marker::PhantomData<B>,
}

impl<B, C> InherentDataProvider<B, C> {
	pub fn new(client: Arc<C>, keystore: KeystorePtr, key: Public, parent: sp_core::H256) -> Self {
		Self {
			client,
			keystore,
			key,
			parent,
			_marker: Default::default(),
		}
	}
}

#[cfg(feature = "std")]
#[async_trait::async_trait]
impl<B, C> sp_inherents::InherentDataProvider for InherentDataProvider<B, C>
where
	B: sp_runtime::traits::Block<Hash = sp_core::H256>,
	C: sp_api::ProvideRuntimeApi<B> + Sync + Send,
	C::Api: VrfApi<B>,
{
	async fn provide_inherent_data(&self, inherent_data: &mut InherentData) -> Result<(), Error> {
		let vrf_digest = popsicle_vrf::vrf_digest::<B, C>(
			&self.client,
			&self.keystore,
			self.key.clone(),
			self.parent.clone(),
		);

		// let result = C::Api::set_vrf_digest(inherent_data.origin.clone(), vrf_digest.clone(), self.key.clone());
		inherent_data.put_data(INHERENT_IDENTIFIER, &())
	}

	async fn try_handle_error(
		&self,
		identifier: &InherentIdentifier,
		_error: &[u8],
	) -> Option<Result<(), sp_inherents::Error>> {
		// Don't process modules from other inherents
		if *identifier != INHERENT_IDENTIFIER {
			return None;
		}

		// All errors with the randomness inherent are fatal
		Some(Err(Error::Application(Box::from(String::from(
			"Error processing dummy inherent inherent",
		)))))
	}
}
