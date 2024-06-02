
//! Autogenerated weights for `pallet_container`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 35.0.1
//! DATE: 2024-05-23, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: ``, CPU: `AMD Ryzen 7 5800U with Radeon Graphics`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("popsicle-dev")`, DB CACHE: 1024

// Executed Command:
// ./Popsicle/target/release/popsicle-node
// benchmark
// pallet
// --chain
// popsicle-dev
// --execution=wasm
// --wasm-execution=compiled
// --pallet
// pallet_container
// --extrinsic
// *
// --steps
// 50
// --repeat
// 20
// --output
// weights.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use core::marker::PhantomData;

/// Weight functions needed for pallet.
pub trait WeightInfo {
	fn set_default_url() -> Weight;
	fn register_app() -> Weight;
}

/// Weights for pallet using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	/// Storage: `ContainerPallet::DefaultUrl` (r:0 w:1)
	/// Proof: `ContainerPallet::DefaultUrl` (`max_values`: Some(1), `max_size`: Some(302), added: 797, mode: `MaxEncodedLen`)
	fn set_default_url() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 6_329_000 picoseconds.
		Weight::from_parts(6_540_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `ContainerPallet::NextApplicationID` (r:1 w:1)
	/// Proof: `ContainerPallet::NextApplicationID` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `ContainerPallet::InuseMap` (r:1 w:1)
	/// Proof: `ContainerPallet::InuseMap` (`max_values`: Some(1), `max_size`: Some(102), added: 597, mode: `MaxEncodedLen`)
	/// Storage: `ContainerPallet::APPInfoMap` (r:0 w:1)
	/// Proof: `ContainerPallet::APPInfoMap` (`max_values`: None, `max_size`: Some(2136), added: 4611, mode: `MaxEncodedLen`)
	fn register_app() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `42`
		//  Estimated: `1587`
		// Minimum execution time: 18_244_000 picoseconds.
		Weight::from_parts(18_766_000, 0)
			.saturating_add(Weight::from_parts(0, 1587))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(3))
	}
}

// For backwards compatibility and tests
impl WeightInfo for () {
	/// Storage: `ContainerPallet::DefaultUrl` (r:0 w:1)
	/// Proof: `ContainerPallet::DefaultUrl` (`max_values`: Some(1), `max_size`: Some(302), added: 797, mode: `MaxEncodedLen`)
	fn set_default_url() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 6_329_000 picoseconds.
		Weight::from_parts(6_540_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	/// Storage: `ContainerPallet::NextApplicationID` (r:1 w:1)
	/// Proof: `ContainerPallet::NextApplicationID` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `ContainerPallet::InuseMap` (r:1 w:1)
	/// Proof: `ContainerPallet::InuseMap` (`max_values`: Some(1), `max_size`: Some(102), added: 597, mode: `MaxEncodedLen`)
	/// Storage: `ContainerPallet::APPInfoMap` (r:0 w:1)
	/// Proof: `ContainerPallet::APPInfoMap` (`max_values`: None, `max_size`: Some(2136), added: 4611, mode: `MaxEncodedLen`)
	fn register_app() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `42`
		//  Estimated: `1587`
		// Minimum execution time: 18_244_000 picoseconds.
		Weight::from_parts(18_766_000, 0)
			.saturating_add(Weight::from_parts(0, 1587))
			.saturating_add(RocksDbWeight::get().reads(2))
			.saturating_add(RocksDbWeight::get().writes(3))
	}
}
