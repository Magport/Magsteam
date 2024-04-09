use crate as pallet_sequencer_grouping;
use frame_support::{derive_impl, parameter_types, traits::Everything};
use frame_support::__private::RuntimeDebug;
use frame_support::pallet_prelude::{Decode, Encode, MaxEncodedLen};
use frame_support::traits::{ConstU64, Contains, InstanceFilter};
use sp_core::{ConstU32, H256};
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	BuildStorage,
};

type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system::{Pallet, Call, Config<T>, Storage, Event<T>},
		SequencerGrouping: pallet_sequencer_grouping,
		Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
		Multisig: pallet_multisig::{Pallet, Call, Storage, Event<T>},
		Proxy: pallet_proxy::{Pallet, Call, Storage, Event<T>},
		Utility: pallet_utility::{Pallet, Call, Event},
	}
);

#[derive(
Copy,
Clone,
Eq,
PartialEq,
Ord,
PartialOrd,
Encode,
Decode,
RuntimeDebug,
MaxEncodedLen,
scale_info::TypeInfo,
)]
pub enum ProxyType {
	Any,
	JustTransfer,
	JustUtility,
}
impl Default for ProxyType {
	fn default() -> Self {
		Self::Any
	}
}
impl InstanceFilter<RuntimeCall> for ProxyType {
	fn filter(&self, c: &RuntimeCall) -> bool {
		match self {
			ProxyType::Any => true,
			ProxyType::JustTransfer => {
				matches!(
					c,
					RuntimeCall::Balances(pallet_balances::Call::transfer_allow_death { .. })
				)
			},
			ProxyType::JustUtility => matches!(c, RuntimeCall::Utility { .. }),
		}
	}
	fn is_superset(&self, o: &Self) -> bool {
		self == &ProxyType::Any || self == o
	}
}
pub struct BaseFilter;
impl Contains<RuntimeCall> for BaseFilter {
	fn contains(c: &RuntimeCall) -> bool {
		match *c {
			// Remark is used as a no-op call in the benchmarking
			RuntimeCall::System(frame_system::Call::remark { .. }) => true,
			RuntimeCall::System(_) => false,
			_ => true,
		}
	}
}

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
	type AccountData = pallet_balances::AccountData<u64>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = SS58Prefix;
	type OnSetCode = ();
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}

// impl pallet_insecure_randomness_collective_flip::Config for Test {}

impl pallet_sequencer_grouping::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type Randomness = pallet_sequencer_grouping::SimpleRandomness<Self>;
	type MaxGroupSize = ConstU32<5u32>;
	type MaxGroupNumber = ConstU32<10u32>;
}

impl pallet_multisig::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type DepositBase = ConstU64<1>;
	type DepositFactor = ConstU64<1>;
	type MaxSignatories = ConstU32<3>;
	type WeightInfo = ();
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig as pallet_balances::DefaultConfig)]
impl pallet_balances::Config for Test {
	type ReserveIdentifier = [u8; 8];
	type AccountStore = System;
}

impl pallet_utility::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type PalletsOrigin = OriginCaller;
	type WeightInfo = ();
}

impl pallet_proxy::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type ProxyType = ProxyType;
	type ProxyDepositBase = ConstU64<1>;
	type ProxyDepositFactor = ConstU64<1>;
	type MaxProxies = ConstU32<4>;
	type WeightInfo = ();
	type CallHasher = BlakeTwo256;
	type MaxPending = ConstU32<2>;
	type AnnouncementDepositBase = ConstU64<1>;
	type AnnouncementDepositFactor = ConstU64<1>;
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	pallet_balances::GenesisConfig::<Test> {
		balances: vec![(1, 10), (2, 10), (3, 10), (4, 10), (5, 2)],
	}
		.assimilate_storage(&mut t)
		.unwrap();
	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| System::set_block_number(1));
	ext
}
