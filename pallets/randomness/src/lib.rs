#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;
pub mod weights;
pub mod vrf;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::{dispatch::DispatchResultWithPostInfo, pallet_prelude::*};
    use frame_system::pallet_prelude::*;
    use primitives_vrf::{VrfDigest, VrfId};
    use crate::vrf;
    use crate::weights::WeightInfo;

    /// Configure the pallet by specifying the parameters and types on which it depends.
    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Because this pallet emits events, it depends on the runtime's definition of an event.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// A type representing the weights required by the dispatchables of this pallet.
        type WeightInfo: crate::weights::WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn local_vrf_digest)]
    pub type LocalVrfDigest<T: Config> = StorageValue<_, VrfDigest>;

    #[pallet::storage]
    #[pallet::getter(fn vrf_author_pubkey)]
    pub type VrfAuthorPubkey<T: Config> = StorageValue<_, VrfId>;

    #[pallet::storage]
    #[pallet::getter(fn randomness_results)]
    pub type RandomnessResults<T: Config> =
        StorageMap<_, Twox64Concat, BlockNumberFor<T>, T::Hash>;

    #[pallet::storage]
    #[pallet::getter(fn latest_randomness)]
    pub type LatestRandomness<T: Config> = StorageValue<_, T::Hash>;

    #[pallet::storage]
    #[pallet::getter(fn not_first_block)]
    pub type NotFirstBlock<T: Config> = StorageValue<_, ()>;


    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        VrfDigestGenerated(VrfId),
    }

    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        /// Error names should be descriptive.
        NoneValue,
        /// Errors should have helpful documentation associated with them.
        StorageOverflow,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            // Do not set the output in the first block (genesis or runtime upgrade)
            // because we do not have any input for author to sign
            if NotFirstBlock::<T>::get().is_none() {
                NotFirstBlock::<T>::put(());
                LatestRandomness::<T>::put(T::Hash::default());
                return T::DbWeight::get().reads_writes(1, 2);
            }
            // Verify VRF output included by block author and set it in storage
            let block_author_vrf_id = VrfAuthorPubkey::<T>::get().expect("VRF public key not set");
            let vrf_digest = LocalVrfDigest::<T>::get().expect("VRF digest not set");
            vrf::verify_and_set_output::<T>(block_author_vrf_id, vrf_digest, n);
            T::WeightInfo::on_initialize()
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000, 0) + T::DbWeight::get().writes(1))]
        pub fn set_vrf_digest(origin: OriginFor<T>, vrf_digest: VrfDigest, vrf_author_pubkey: VrfId) -> DispatchResultWithPostInfo {
            ensure_signed(origin)?;

            <LocalVrfDigest<T>>::put(vrf_digest.clone());
            <VrfAuthorPubkey<T>>::put(vrf_author_pubkey.clone());

            // Emit an event.
            Self::deposit_event(Event::VrfDigestGenerated(vrf_author_pubkey));
            Ok(().into())
        }

        /// An example dispatchable that may throw a custom error.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000, 0) + T::DbWeight::get().reads_writes(1,1))]
        pub fn cause_error(origin: OriginFor<T>) -> DispatchResultWithPostInfo {
            let _who = ensure_signed(origin)?;
            Ok(().into())

            // Read a value from storage.
            // match <Something<T>>::get() {
            //     // Return an error if the value has not been set.
            //     None => Err(Error::<T>::NoneValue)?,
            //     Some(old) => {
            //         // Increment the value read from storage; will error in the event of overflow.
            //         let new = old.checked_add(1).ok_or(Error::<T>::StorageOverflow)?;
            //         // Update the value in storage with the incremented result.
            //         <Something<T>>::put(new);
            //         Ok(().into())
            //     },
            // }
        }
    }
}