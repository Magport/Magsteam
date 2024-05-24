#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use core::marker::PhantomData;

/// Weight functions needed for pallet_randomness.
pub trait WeightInfo {
	fn set_babe_randomness_results() -> Weight;
}

/// Weights for pallet_randomness using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	/// Storage: Randomness RelayEpoch (r:1 w:1)
	/// Proof Skipped: Randomness RelayEpoch (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: ParachainSystem ValidationData (r:1 w:0)
	/// Proof Skipped: ParachainSystem ValidationData (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: ParachainSystem RelayStateProof (r:1 w:0)
	/// Proof Skipped: ParachainSystem RelayStateProof (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Randomness RandomnessResults (r:0 w:1)
	/// Proof Skipped: Randomness RandomnessResults (max_values: None, max_size: None, mode: Measured)
	/// Storage: Randomness InherentIncluded (r:0 w:1)
	/// Proof Skipped: Randomness InherentIncluded (max_values: Some(1), max_size: None, mode: Measured)
	fn set_babe_randomness_results() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `216`
		//  Estimated: `1701`
		// Minimum execution time: 6_713_000 picoseconds.
		Weight::from_parts(6_963_000, 1701)
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().writes(3_u64))
	}
}

// For backwards compatibility and tests
impl WeightInfo for () {
	/// Storage: Randomness RelayEpoch (r:1 w:1)
	/// Proof Skipped: Randomness RelayEpoch (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: ParachainSystem ValidationData (r:1 w:0)
	/// Proof Skipped: ParachainSystem ValidationData (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: ParachainSystem RelayStateProof (r:1 w:0)
	/// Proof Skipped: ParachainSystem RelayStateProof (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Randomness RandomnessResults (r:0 w:1)
	/// Proof Skipped: Randomness RandomnessResults (max_values: None, max_size: None, mode: Measured)
	/// Storage: Randomness InherentIncluded (r:0 w:1)
	/// Proof Skipped: Randomness InherentIncluded (max_values: Some(1), max_size: None, mode: Measured)
	fn set_babe_randomness_results() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `216`
		//  Estimated: `1701`
		// Minimum execution time: 6_713_000 picoseconds.
		Weight::from_parts(6_963_000, 1701)
			.saturating_add(RocksDbWeight::get().reads(3_u64))
			.saturating_add(RocksDbWeight::get().writes(3_u64))
	}
}
