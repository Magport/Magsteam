//! Benchmarking setup for pallet-sequencer-grouping

#![cfg(feature = "runtime-benchmarks")]

use super::*;

#[allow(unused)]
use crate::Pallet as SequencerGrouping;
use frame_benchmarking::{account, benchmarks, impl_benchmark_test_suite};
use frame_support::{pallet_prelude::Get, traits::OnInitialize, BoundedVec};
use frame_system::RawOrigin;
use sp_std::{vec, mem::size_of};
use sp_std::vec::Vec;
use sp_core::{
	crypto::UncheckedFrom,
	sr25519::Public,
};
use sp_runtime::DigestItem;
use primitives_vrf::{PreDigest, make_vrf_transcript, AUTHOR_PUBKEY, CompatibleDigestItem};
use codec::{Decode, Encode, alloc::string::ToString};
use scale_info::prelude::string::String;



benchmarks! {
	set_group_metric {
		let group_size: u32 = 3;
		let group_number: u32 = 5;
	}: _(RawOrigin::Root, group_size, group_number)

	verify {
		assert_eq!(GroupSize::<T>::get(), group_size);
		assert_eq!(GroupNumber::<T>::get(), group_number);
	}

	benchmark_trigger_group {
		let s in 1 .. T::MaxGroupSize::get() as u32;
		let n in 1 .. T::MaxGroupNumber::get() as u32;

		let mut candidates: Vec<T::AccountId> = Vec::new();
		for i in 0..(s * n) {
			let candidate: T::AccountId = account("candidate", i, 0);
			candidates.push(candidate);
		}
		let starting_block = frame_system::Pallet::<T>::block_number();
		let round_index = 1u32;

	}: _(RawOrigin::Root, candidates, starting_block, round_index)

	register_processor {
		let ip_address: BoundedVec<u8, T::MaxLengthIP> = BoundedVec::from(BoundedVec::try_from(vec![1u8; 15]).unwrap());
	}: _(RawOrigin::Signed(account("processor", 0, 0)), ip_address)

	// Benchmark for VRF verification and everything else in `set_output`, in `on_initialize`
	on_initialize {
		fn decode_32_bytes(input: String) -> [u8; 32] {
			let output = hex::decode(input).expect("expect to decode input");
			let mut ret: [u8; 32] = Default::default();
			ret.copy_from_slice(&output[0..32]);
			ret
		}
		fn decode_key(input: String) -> Public {
			Public::unchecked_from(decode_32_bytes(input))
		}
		fn decode_pre_digest(input: String) -> PreDigest {
			let output = hex::decode(input).expect("expect to decode input");
			const PRE_DIGEST_BYTE_LEN: usize = size_of::<PreDigest>() as usize;
			let mut ret: [u8; PRE_DIGEST_BYTE_LEN] = [0u8; PRE_DIGEST_BYTE_LEN];
			ret.copy_from_slice(&output[0..PRE_DIGEST_BYTE_LEN]);
			Decode::decode(&mut ret.as_slice()).expect("expect to decode predigest")
		}

		let raw_author_public = "a66aa1e9fcb06e64daa01bf50a5e0881ef544df028c4e401aef97054e3746708"
			.to_string();
		// let raw_vrf_id = "e01d4eb5b3c482df465513ecf17f74154005ed7466166e7d2f049e0fa371ef66"
		// 	.to_string();
		let raw_vrf_input = "24583ca3ba768736eeaad921c2479367679a03f1ed453d101075c30f862ed260"
			.to_string();
		let raw_vrf_pre_digest = "941f5b8cc921ab893485c5055322321a3894334b3ff4cbf605d0fa6d5ce14025dec3917a9fb8a821617885e433fd4e90f11a9e576186e87e7374cfe1c725be0f3bfe14d47597ffb911fd11afdecfc44c3c930fb8827146752fff427ac7e8e30e".to_string();
		let author_pubkey: Public = decode_key(raw_author_public).into();
		// let vrf_id: VrfId = decode_key(raw_vrf_id).into();
		let vrf_input: [u8; 32] = decode_32_bytes(raw_vrf_input);
		let vrf_pre_digest = decode_pre_digest(raw_vrf_pre_digest);
		let last_vrf_output: T::Hash = Decode::decode(&mut vrf_input.as_slice()).ok()
			.expect("decode into same type");
		LocalVrfOutput::<T>::put(Some(last_vrf_output));
		NotFirstBlock::<T>::put(());
		let block_num = frame_system::Pallet::<T>::block_number() + 100u32.into();
		RandomnessResults::<T>::insert(
			&block_num,
			Some(last_vrf_output),
		);
		let transcript = make_vrf_transcript::<T::Hash>(LocalVrfOutput::<T>::get().unwrap_or_default());
		let auth_digest_item = DigestItem::PreRuntime(AUTHOR_PUBKEY, author_pubkey.encode());
		let vrf_digest_item = CompatibleDigestItem::vrf_pre_digest(vrf_pre_digest.clone());
		let digest =  sp_runtime::generic::Digest {
			logs: vec![auth_digest_item, vrf_digest_item]
		};
		// insert digest into frame_system storage
		frame_system::Pallet::<T>::initialize(
			&block_num,
			&T::Hash::default(),
			&digest
		);
	}: {
		Pallet::<T>::on_initialize(block_num);
	}
}

impl_benchmark_test_suite!(SequencerGrouping, crate::mock::new_test_ext(), crate::mock::Test,);
