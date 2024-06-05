use frame_support::pallet_prelude::*;

#[derive(PartialEq, Eq, Copy, Clone, Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
/// Shared request info, a subset of `RequestInfo`
pub enum RequestType {
    /// Babe one epoch ago
    BabeEpoch(u64),
}

#[derive(PartialEq, Eq, Copy, Clone, Encode, Decode, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(T))]
/// Type of request
/// Represents a request for the most recent randomness at or after the inner first field
/// Expiration is second inner field
pub enum RequestInfo {
    /// Babe one epoch ago
    BabeEpoch(u64, u64),
}

#[derive(PartialEq, Eq, Clone, Default, Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
/// Raw randomness snapshot, the unique value for a `RequestType` in `RandomnessResults` map
pub struct RandomnessResult<Hash> {
    /// Randomness once available
    pub randomness: Option<Hash>,
    /// Number of randomness requests for the type
    pub request_count: u64,
}

impl<Hash: Clone> RandomnessResult<Hash> {
    pub fn new() -> RandomnessResult<Hash> {
        RandomnessResult {
            randomness: None,
            request_count: 1u64,
        }
    }
}
