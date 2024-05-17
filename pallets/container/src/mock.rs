use core::marker::PhantomData;
use frame_system::pallet_prelude::BlockNumberFor;
use crate::Config;

use frame_support::{derive_impl, parameter_types, traits::Everything};
use frame_system as system;
use sp_core::{ConstU32, H256};
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup, Hash},
	BuildStorage,
};
type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system::{Pallet, Call, Config<T>, Storage, Event<T>},
		SequencerGroupingModule: pallet_sequencer_grouping::{Pallet, Call, Storage, Event<T>},
		ContainerModule: crate::{Pallet, Call, Storage, Event<T>},
	}
);

parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const SS58Prefix: u8 = 42;
}
#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type BaseCallFilter = Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Nonce = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Block = Block;
	type BlockHashCount = BlockHashCount;
	type DbWeight = ();
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = ();
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = SS58Prefix;
	type OnSetCode = ();
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}

// Randomness trait
pub struct TestRandomness<T> {
	_marker: PhantomData<T>,
}
impl<T: Config> frame_support::traits::Randomness<T::Hash, BlockNumberFor<T>>
for TestRandomness<T>
{
	fn random(subject: &[u8]) -> (T::Hash, BlockNumberFor<T>) {
		use rand::{rngs::OsRng, RngCore};
		let mut digest: Vec<_> = [0u8; 32].into();
		OsRng.fill_bytes(&mut digest);
		digest.extend_from_slice(subject);
		let randomness = T::Hashing::hash(&digest);
		// NOTE: Test randomness is always "fresh" assuming block_number is > DrawingFreezeout
		let block_number = 0u32.into();
		(randomness, block_number)
	}
}

impl pallet_sequencer_grouping::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type MaxGroupSize = ConstU32<100>;
	type MaxGroupNumber = ConstU32<100>;
	type RandomnessSource = TestRandomness<Test>;
}

parameter_types! {
	pub const MaxLengthFileName: u32 = 256;
	pub const MaxRuningAPP: u32 = 100;
	pub const MaxUrlLength: u32 = 300;
	pub const MaxArgCount: u32 = 10;
	pub const MaxArgLength: u32 = 100;
}
impl crate::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	// type AuthorityId = AuraId;
	type MaxLengthFileName = MaxLengthFileName;
	type MaxRuningAPP = MaxRuningAPP;
	type MaxUrlLength = MaxUrlLength;
	type MaxArgCount = MaxArgCount;
	type MaxArgLength = MaxArgLength;
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	system::GenesisConfig::<Test>::default().build_storage().unwrap().into()
}
