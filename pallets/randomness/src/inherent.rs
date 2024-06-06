//! Inherents used for randomness
use codec::{Decode, Encode};
use sp_inherents::{Error, InherentData, InherentIdentifier, IsFatalError};
use sp_runtime::RuntimeString;
use sc_service::TFullClient;
use sc_executor::NativeElseWasmExecutor;
use sp_runtime::{generic, OpaqueExtrinsic};
use sp_runtime::traits::BlakeTwo256;
use std::sync::Arc;
use sp_keystore::{Keystore, KeystorePtr};

pub type BlockNumber = u32;
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type Block = generic::Block<Header, OpaqueExtrinsic>;
type FullClient<RuntimeApi, Executor> =
TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<Executor>>;

#[derive(Encode)]
#[cfg_attr(feature = "std", derive(Debug, Decode))]
/// Error type for missing mandatory inherent of pallet_randomness
pub enum InherentError {
    /// Takes an error explanation as string
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

pub struct InherentDataProvider<RuntimeApi, Executor>
where
    RuntimeApi: Send + Sync,
    Executor: sc_executor::NativeExecutionDispatch + 'static,
{
    pub client: Arc<FullClient<RuntimeApi, Executor>>,
    pub keystore: Arc<dyn Keystore>,
}

#[cfg(feature = "std")]
#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for InherentDataProvider {
    async fn provide_inherent_data(&self, inherent_data: &mut InherentData) -> Result<(), Error> {

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
            "Error processing dummy randomness inherent",
        )))))
    }
}
