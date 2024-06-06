#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

pub mod weights;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
	pallet_prelude::*,
	traits::{ConstU32, OriginTrait},
};
use frame_system::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::{traits::StaticLookup, BoundedVec};
pub use weights::*;

pub type BtcAddress = BoundedVec<u8, ConstU32<60>>;
type AccountIdLookupOf<T> = <<T as frame_system::Config>::Lookup as StaticLookup>::Source;
#[derive(Encode, Decode, Default, Clone, TypeInfo, MaxEncodedLen, Debug)]
#[scale_info(skip_type_params(T))]
pub struct DepositInfo<T: Config> {
	block_height: u128,
	txid: H256,
	amount: T::Balance,
	benifit: T::AccountId,
}
#[derive(Encode, Decode, Default, Clone, TypeInfo, MaxEncodedLen, Debug)]
#[scale_info(skip_type_params(T))]
pub struct RedeemInfo<T: Config> {
	redeem_id: u128,
	amount: T::Balance,
	who: T::AccountId,
	btc_address: BtcAddress,
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_assets::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// Type representing the weight of this pallet
		type WeightInfo: WeightInfo;
		/// pBTC assetid
		type BtcAssetId: Get<Self::AssetId>;
	}

	#[pallet::storage]
	#[pallet::getter(fn last_btc_height)]
	pub type LastBtcHeight<T: Config> = StorageValue<_, u128, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn bridge_account_map)]
	pub type BridgeAccountMap<T: Config> =
		StorageMap<_, Twox64Concat, T::AccountId, u32, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn depositinfo_map)]
	pub type DepositInfoMap<T: Config> =
		StorageMap<_, Twox64Concat, H256, DepositInfo<T>, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn redeeminfo_pointer)]
	pub type RedeemInfoPointer<T: Config> = StorageValue<_, (u128, u128), ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn redeeminfo_map)]
	pub type RedeemInfoMap<T: Config> =
		StorageMap<_, Twox64Concat, u128, RedeemInfo<T>, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn redeemtx_map)]
	pub type RedeemTxMap<T: Config> = StorageMap<_, Twox64Concat, H256, u128, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn redeeminfohistory_map)]
	pub type RedeemInfoHistoryMap<T: Config> =
		StorageMap<_, Twox64Concat, u128, RedeemInfo<T>, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		Deposit4pBTC {
			block_height: u128,
			txid: H256,
			amount: T::Balance,
			benifit: T::AccountId,
		},
		RedeemBTC {
			redeem_id: u128,
			amount: T::Balance,
			who: T::AccountId,
			btc_address: BtcAddress,
		},
		RedeemProcess {
			redeem_id: u128,
			fun: u32,
			txid: H256,
		},
		SetBtcHeight {
			btc_block_height: u128,
		},
		SetBridgeAccount {
			bridge_account: AccountIdLookupOf<T>,
			set_flag: bool,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		BlockProcced,
		TxProcced,
		RedeemNotExist,
		RedeemProcced,
		RedeemInternalError,
		NotBridgeAccount,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::deposit_for_pbtc())]
		pub fn deposit_for_pbtc(
			origin: OriginFor<T>,
			btc_block_height: u128,
			btc_txid: H256,
			#[pallet::compact] amount: T::Balance,
			benifit_lookup: AccountIdLookupOf<T>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			_ = BridgeAccountMap::<T>::get(who).ok_or(Error::<T>::NotBridgeAccount)?;

			let benifit = T::Lookup::lookup(benifit_lookup.clone())?;

			let btc_block = LastBtcHeight::<T>::get();
			if btc_block_height < btc_block {
				return Err(Error::<T>::BlockProcced.into());
			}

			if DepositInfoMap::<T>::contains_key(btc_txid) {
				return Err(Error::<T>::TxProcced.into());
			}

			let _ = <pallet_assets::Pallet<T>>::mint(
				T::RuntimeOrigin::root(),
				T::BtcAssetId::get().into(),
				benifit_lookup,
				amount,
			)?;

			DepositInfoMap::<T>::insert(
				btc_txid,
				DepositInfo {
					block_height: btc_block_height,
					txid: btc_txid,
					amount,
					benifit: benifit.clone(),
				},
			);

			Pallet::<T>::deposit_event(Event::<T>::Deposit4pBTC {
				block_height: btc_block_height,
				txid: btc_txid,
				amount,
				benifit,
			});

			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::redeem_btc())]
		pub fn redeem_btc(
			origin: OriginFor<T>,
			#[pallet::compact] amount: T::Balance,
			btc_address: BtcAddress,
		) -> DispatchResult {
			let who = ensure_signed(origin.clone())?;

			let (redeem_start, mut redeem_end) = Self::redeeminfo_pointer();
			redeem_end = redeem_end + 1;

			let who_lookup = <T::Lookup as sp_runtime::traits::StaticLookup>::unlookup(who.clone());
			let _ = <pallet_assets::Pallet<T>>::burn(
				origin,
				T::BtcAssetId::get().into(),
				who_lookup,
				amount,
			)?;

			RedeemInfoPointer::<T>::set((redeem_start, redeem_end));
			RedeemInfoMap::<T>::insert(
				redeem_end,
				RedeemInfo {
					redeem_id: redeem_end,
					amount,
					who: who.clone(),
					btc_address: btc_address.clone(),
				},
			);

			Pallet::<T>::deposit_event(Event::<T>::RedeemBTC {
				redeem_id: redeem_end,
				amount,
				who,
				btc_address,
			});

			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::redeem_process())]
		pub fn redeem_process(
			origin: OriginFor<T>,
			fun: u32,
			txid: H256,
			redeem_id_p: u128,
			btc_block_height: u128,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			_ = BridgeAccountMap::<T>::get(who).ok_or(Error::<T>::NotBridgeAccount)?;

			let (mut redeem_start, redeem_end) = Self::redeeminfo_pointer();
			let mut redeem_id = redeem_id_p;

			if fun == 0 {
				redeem_start = redeem_start + 1;
				if redeem_id != redeem_start {
					return Err(Error::<T>::RedeemInternalError.into());
				}
				let _redeem_info =
					RedeemInfoMap::<T>::get(redeem_start).ok_or(Error::<T>::RedeemNotExist)?;
				RedeemInfoPointer::<T>::set((redeem_start, redeem_end));
				RedeemTxMap::<T>::insert(txid, redeem_id);
			} else {
				redeem_id = RedeemTxMap::<T>::get(txid).ok_or(Error::<T>::RedeemNotExist)?;
				if RedeemInfoHistoryMap::<T>::contains_key(redeem_id) {
					return Err(Error::<T>::RedeemProcced.into());
				}
				let redeem_info =
					RedeemInfoMap::<T>::get(redeem_id).ok_or(Error::<T>::RedeemNotExist)?;
				RedeemInfoMap::<T>::remove(redeem_id);
				RedeemInfoHistoryMap::<T>::insert(redeem_id, redeem_info);
			}

			Pallet::<T>::deposit_event(Event::<T>::RedeemProcess { redeem_id, fun, txid });
			Ok(())
		}

		#[pallet::call_index(3)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::set_btc_height())]
		pub fn set_btc_height(origin: OriginFor<T>, btc_block_height: u128) -> DispatchResult {
			let who = ensure_signed(origin)?;
			_ = BridgeAccountMap::<T>::get(who).ok_or(Error::<T>::NotBridgeAccount)?;

			LastBtcHeight::<T>::set(btc_block_height);
			Pallet::<T>::deposit_event(Event::<T>::SetBtcHeight { btc_block_height });
			Ok(())
		}

		#[pallet::call_index(4)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::set_bridge_account())]
		pub fn set_bridge_account(
			origin: OriginFor<T>,
			bridge_account: AccountIdLookupOf<T>,
			set_flag: bool,
		) -> DispatchResult {
			ensure_root(origin)?;

			let who = T::Lookup::lookup(bridge_account.clone())?;
			if set_flag {
				BridgeAccountMap::<T>::insert(who, 1u32);
			} else {
				BridgeAccountMap::<T>::remove(who);
			}
			Pallet::<T>::deposit_event(Event::<T>::SetBridgeAccount { bridge_account, set_flag });
			Ok(())
		}
	}
}
