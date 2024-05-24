//! A minimal runtime including the pallet-randomness pallet
use super::*;
use crate as pallet_randomness;
use frame_support::{
    construct_runtime, derive_impl, parameter_types, traits::Everything, weights::Weight,
};
use sp_core::{H160, H256};
use sp_runtime::{
    traits::{BlakeTwo256, IdentityLookup},
    BuildStorage, Perbill,
};
use sp_std::convert::{TryFrom, TryInto};

pub type AccountId = H160;
pub type Balance = u128;

type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
construct_runtime!(
    pub enum Test
    {
        System: frame_system,
        Balances: pallet_balances,
        Randomness: pallet_randomness,
    }
);

parameter_types! {
    pub const BlockHashCount: u32 = 250;
    pub const MaximumBlockWeight: Weight = Weight::from_parts(1024, 0);
    pub const MaximumBlockLength: u32 = 2 * 1024;
    pub const AvailableBlockRatio: Perbill = Perbill::one();
    pub const SS58Prefix: u8 = 42;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Test {
    type BaseCallFilter = Everything;
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type Nonce = u64;
    type Block = Block;
    type RuntimeCall = RuntimeCall;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = BlockHashCount;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type BlockWeights = ();
    type BlockLength = ();
    type SS58Prefix = SS58Prefix;
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<16>;
}

parameter_types! {
    pub const ExistentialDeposit: u128 = 1;
}
impl pallet_balances::Config for Test {
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 4];
    type MaxLocks = ();
    type Balance = Balance;
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type FreezeIdentifier = ();
    type MaxFreezes = frame_support::traits::ConstU32<1>;
}

pub struct BabeDataGetter;
impl crate::GetBabeData<u64, Option<H256>> for BabeDataGetter {
    fn get_epoch_index() -> u64 {
        10u64
    }
    fn get_epoch_randomness() -> Option<H256> {
        Some(H256::default())
    }
}

parameter_types! {
    pub const Deposit: u128 = 10;
    pub const MaxRandomWords: u8 = 1;
    pub const MinBlockDelay: u32 = 2;
    pub const MaxBlockDelay: u32 = 20;
}
impl Config for Test {
    type BabeDataGetter = BabeDataGetter;
    type WeightInfo = ();
}

/// Externality builder for pallet randomness mock runtime
#[derive(Default)]
pub(crate) struct ExtBuilder {
    /// Balance amounts per AccountId
    balances: Vec<(AccountId, Balance)>,
}

impl ExtBuilder {
    #[allow(dead_code)]
    pub(crate) fn with_balances(mut self, balances: Vec<(AccountId, Balance)>) -> Self {
        self.balances = balances;
        self
    }

    #[allow(dead_code)]
    pub(crate) fn build(self) -> sp_io::TestExternalities {
        let mut t = frame_system::GenesisConfig::<Test>::default()
            .build_storage()
            .expect("Frame system builds valid default genesis config");

        pallet_balances::GenesisConfig::<Test> {
            balances: self.balances,
        }
        .assimilate_storage(&mut t)
        .expect("Pallet balances storage can be assimilated");

        let mut ext = sp_io::TestExternalities::new(t);
        ext.execute_with(|| System::set_block_number(1));
        ext
    }
}
