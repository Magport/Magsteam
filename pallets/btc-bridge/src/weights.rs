
//! Autogenerated weights for pallet_template
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-04-06, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `Alexs-MacBook-Pro-2.local`, CPU: `<UNKNOWN>`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("dev"), DB CACHE: 1024

// Executed Command:
// ../../target/release/node-template
// benchmark
// pallet
// --chain
// dev
// --pallet
// pallet_template
// --extrinsic
// *
// --steps=50
// --repeat=20
// --wasm-execution=compiled
// --output
// pallets/template/src/weights.rs
// --template
// ../../.maintain/frame-weight-template.hbs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use core::marker::PhantomData;

/// Weight functions needed for pallet_template.
pub trait WeightInfo {
	fn deposit_for_pbtc() -> Weight;
	fn redeem_btc() -> Weight;
	fn redeem_process() -> Weight;
}

/// Weights for pallet_template using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	fn deposit_for_pbtc() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_767_000 picoseconds.
		Weight::from_parts(3_947_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(T::DbWeight::get().writes(1))
	}

	fn redeem_btc() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `42`
		//  Estimated: `1587`
		// Minimum execution time: 14_487_000 picoseconds.
		Weight::from_parts(14_969_000, 0)
			.saturating_add(Weight::from_parts(0, 1587))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(3))
	}

	fn redeem_process() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `42`
		//  Estimated: `1587`
		// Minimum execution time: 14_487_000 picoseconds.
		Weight::from_parts(14_969_000, 0)
			.saturating_add(Weight::from_parts(0, 1587))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(3))
	}	
}

// For backwards compatibility and tests
impl WeightInfo for () {
	/// Storage: `ContainerPallet::DefaultUrl` (r:0 w:1)
	/// Proof: `ContainerPallet::DefaultUrl` (`max_values`: Some(1), `max_size`: Some(302), added: 797, mode: `MaxEncodedLen`)
	fn deposit_for_pbtc() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_767_000 picoseconds.
		Weight::from_parts(3_947_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(RocksDbWeight::get().writes(1))
	}

	fn redeem_btc() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `42`
		//  Estimated: `1587`
		// Minimum execution time: 14_487_000 picoseconds.
		Weight::from_parts(14_969_000, 0)
			.saturating_add(Weight::from_parts(0, 1587))
			.saturating_add(RocksDbWeight::get().reads(2))
			.saturating_add(RocksDbWeight::get().writes(3))
	}

	fn redeem_process() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `42`
		//  Estimated: `1587`
		// Minimum execution time: 14_487_000 picoseconds.
		Weight::from_parts(14_969_000, 0)
			.saturating_add(Weight::from_parts(0, 1587))
			.saturating_add(RocksDbWeight::get().reads(2))
			.saturating_add(RocksDbWeight::get().writes(3))
	}	
}
