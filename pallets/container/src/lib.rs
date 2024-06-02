//! # Container Pallet
//!
//! This pallet is named container, hoping to be a container for various clients.
//! The function it expects to achieve is to register various layer2 clients and start these clients
//! when appropriate conditions are met.
//!
//! The roles that complete this work are called sequencer and processor.
//! The sequencer is responsible for starting the consensus client,
//! and the processor is responsible for starting the batcher client.
//!
//! In order to achieve the goal of being compatible with all layer2, the layer2 client is
//! abstracted into a consensus client and a batcher client. The client can be started and run as a
//! process or a docker container. The operation of the consensus client is based on the time
//! sequence, and there are two steps: synchronization of blocks and consensus.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod weights;
use codec::{Decode, Encode, MaxEncodedLen};
use cumulus_primitives_core::relay_chain::Hash;
use derivative::Derivative;
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
use pallet_sequencer_grouping::SequencerGroup;
use primitives_container::{DownloadInfo, ProcessorDownloadInfo};
use scale_info::{prelude::vec::Vec, TypeInfo};
use sp_runtime::BoundedVec;
use sp_std::{boxed::Box, vec};
pub use weights::*;

/// Client basic information structure, including consensus client and batcher client.
#[derive(Derivative, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[derivative(
	Clone(bound = ""),
	Eq(bound = ""),
	PartialEq(bound = ""),
	Debug(bound = ""),
	Default(bound = "")
)]
#[codec(encode_bound())]
#[codec(decode_bound())]
#[scale_info(bounds(), skip_type_params(T))]
pub struct AppClient<T: Config> {
	/// Client hash(sha256), if client is run as docker container, this is digest.
	pub app_hash: Hash,
	/// Client file name.
	pub file_name: BoundedVec<u8, T::MaxLengthFileName>,
	/// Client file size, bytes.
	pub size: u32,
	/// Client startup common parameters.
	pub args: Option<BoundedVec<u8, T::MaxArgLength>>,
	/// Client operation log file.
	pub log: Option<BoundedVec<u8, T::MaxLengthFileName>>,
	/// Is started as a Docker container.
	pub is_docker_image: Option<bool>,
	/// Docker image name
	pub docker_image: Option<BoundedVec<u8, T::MaxLengthFileName>>,
}

/// Registered application information structure.
#[derive(Encode, Decode, Default, Clone, TypeInfo, MaxEncodedLen, Debug)]
#[scale_info(skip_type_params(T))]
pub struct APPInfo<T: Config> {
	/// Account of register an application.
	creator: T::AccountId,
	/// Project name,uniquely identifies.
	project_name: BoundedVec<u8, T::MaxLengthFileName>,
	/// Consensus client.
	consensus_client: AppClient<T>,
	/// Batcher client.
	batch_client: AppClient<T>,
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_sequencer_grouping::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// Type representing the weight of this pallet
		type WeightInfo: WeightInfo;
		/// Max length of file name
		#[pallet::constant]
		type MaxLengthFileName: Get<u32>;
		/// Max number of registered app.
		#[pallet::constant]
		type MaxRuningAPP: Get<u32>;
		/// Max length of url,for download client binary file.
		#[pallet::constant]
		type MaxUrlLength: Get<u32>;
		/// Max count of arguments.
		#[pallet::constant]
		type MaxArgCount: Get<u32>;
		/// Max length of arguments.
		#[pallet::constant]
		type MaxArgLength: Get<u32>;
	}

	/// By default, the application number starts from 1.
	#[pallet::type_value]
	pub fn ApplicationIDOnEmpty<T: Config>() -> u32 {
		1
	}

	/// The next available application id.
	#[pallet::storage]
	#[pallet::getter(fn next_application_id)]
	pub type NextApplicationID<T> = StorageValue<_, u32, ValueQuery, ApplicationIDOnEmpty<T>>;

	/// Url storage.
	#[pallet::storage]
	#[pallet::getter(fn default_url)]
	pub type DefaultUrl<T: Config> = StorageValue<_, BoundedVec<u8, T::MaxUrlLength>, OptionQuery>;

	/// Registered application information, map of app_id:app_info.
	#[pallet::storage]
	#[pallet::getter(fn appinfo_map)]
	pub type APPInfoMap<T: Config> = StorageMap<_, Twox64Concat, u32, APPInfo<T>, OptionQuery>;

	// app_id,inuse
	#[pallet::storage]
	#[pallet::getter(fn inuse_map)]
	pub type InuseMap<T: Config> = StorageValue<_, BoundedVec<bool, T::MaxRuningAPP>, ValueQuery>;

	// groupid,app_id
	#[pallet::storage]
	#[pallet::getter(fn group_app_map)]
	pub type GroupAPPMap<T: Config> = StorageMap<_, Twox64Concat, u32, u32, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		ReisterApp {
			/// Account of register client.
			creator: T::AccountId,
			/// Assigned app id.
			appid: u32,
			/// Project name.
			project_name: BoundedVec<u8, T::MaxLengthFileName>,
			/// File name of consensus client.
			consensus_client: BoundedVec<u8, T::MaxLengthFileName>,
			/// Hash of consensus client.
			consensus_hash: Hash,
			/// File size of consensus client.
			consensus_size: u32,
			/// File name of batcher client.
			batch_client: BoundedVec<u8, T::MaxLengthFileName>,
			/// Hash of batcher client.
			batch_hash: Hash,
			/// File size of batcher client.
			batch_size: u32,
		},
		SetDownloadURL {
			url: BoundedVec<u8, T::MaxUrlLength>,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		AppNotExist,
		AccountInconsistent,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		/// The logic executed by each parachain block queries how many groups there are and binds
		/// the registered applications to the groups. One application is bound to one group.
		fn on_initialize(_n: BlockNumberFor<T>) -> Weight
		where
			BlockNumberFor<T>: From<u32>,
		{
			let groups = Self::get_groups();
			log::info!("groups:{:?}", groups);

			let mut inuse_apps = InuseMap::<T>::get();
			log::info!("inuse_apps:{:?}", inuse_apps);
			let mut read_count = 2;
			let mut write_count = 0;
			for group in groups.iter() {
				let app = GroupAPPMap::<T>::get(group);
				read_count += 1;
				match app {
					Some(_app_id) => {
						// TODO:alloced app to group,do nothing??
						// GroupAPPMap::<T>::mutate(group, |id| *id=Some((index + 1) as u64));
					},
					None => {
						// alloc app to group
						let alloc_apps = inuse_apps.len();

						let mut index = 0;

						while index < alloc_apps {
							if !inuse_apps[index] {
								inuse_apps[index] = true;

								InuseMap::<T>::mutate(|inuses| inuses[index] = true);

								GroupAPPMap::<T>::insert(group, (index + 1) as u32);
								write_count += 2;
								break;
							}
							index += 1;
						}
						if index == alloc_apps {
							// all is inuse, can not alloc,do nothing,just wait
						}
					},
				}
			}
			log::info!("inuse_apps:{:?}", inuse_apps);
			T::DbWeight::get().reads_writes(read_count, write_count)
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Register layer2 application client.
		///
		/// Parameters:
		/// - `project_name`: The project name.
		/// - `consensus_client`: Consensus client.
		/// - `batch_client`: Batcher client.
		#[pallet::call_index(0)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::register_app())]
		pub fn register_app(
			origin: OriginFor<T>,
			project_name: BoundedVec<u8, T::MaxLengthFileName>,
			consensus_client: Box<AppClient<T>>,
			batch_client: Box<AppClient<T>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let old_application_id = NextApplicationID::<T>::get();

			let consensus_app = *consensus_client;

			let batch_app = *batch_client;

			// we can allow same app when register app.
			// for app_id in 1..old_application_id {
			// 	let p_app_info = APPInfoMap::<T>::get(app_id);
			// 	if let Some(app_info) = p_app_info {
			// 		assert!(
			// 			(app_info.consensus_client.app_hash != consensus_app.app_hash) &&
			// 				(app_info.batch_client.app_hash != batch_app.app_hash),
			// 			"Client with the same hash exist!",
			// 		);
			// 	}
			// }
			APPInfoMap::<T>::insert(
				old_application_id,
				APPInfo {
					creator: who.clone(),
					project_name: project_name.clone(),
					consensus_client: consensus_app.clone(),
					batch_client: batch_app.clone(),
				},
			);

			NextApplicationID::<T>::set(old_application_id + 1);

			let mut inuse_apps = InuseMap::<T>::get();
			inuse_apps.try_push(false).map_err(|_| Error::<T>::AppNotExist)?;

			InuseMap::<T>::put(inuse_apps);

			Pallet::<T>::deposit_event(Event::<T>::ReisterApp {
				creator: who,
				appid: old_application_id,
				project_name,
				consensus_client: consensus_app.file_name,
				consensus_hash: consensus_app.app_hash,
				consensus_size: consensus_app.size,
				batch_client: batch_app.file_name,
				batch_hash: batch_app.app_hash,
				batch_size: batch_app.size,
			});

			Ok(())
		}

		/// Set url for download client binary file.
		///
		/// Parameters:
		/// - `url`: Url.
		#[pallet::call_index(1)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::set_default_url())]
		pub fn set_default_url(
			origin: OriginFor<T>,
			url: BoundedVec<u8, T::MaxUrlLength>,
		) -> DispatchResult {
			ensure_root(origin)?;

			DefaultUrl::<T>::put(url.clone());

			Pallet::<T>::deposit_event(Event::<T>::SetDownloadURL { url });
			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	// Obtain application information corresponding to the group.
	// If no group has been assigned or there are no available apps in the group, return None
	pub fn shuld_load(author: T::AccountId) -> Option<DownloadInfo> {
		// log::info!("============author:{:?}", author.encode());
		//Get the group ID of the sequencer, error when got 0xFFFFFFFF
		let group_id = Self::get_group_id(author);

		let app_id = GroupAPPMap::<T>::get(group_id)?;

		let app_info = APPInfoMap::<T>::get(app_id).ok_or(Error::<T>::AppNotExist).ok()?;

		let url = DefaultUrl::<T>::get()?;

		let consensus_client = app_info.consensus_client;

		let args = consensus_client.args.and_then(|log| Some(log.as_slice().to_vec()));

		let log = consensus_client.log.and_then(|log| Some(log.as_slice().to_vec()));

		let is_docker_image =
			if let Some(is_docker) = consensus_client.is_docker_image { is_docker } else { false };

		let docker_image = consensus_client
			.docker_image
			.and_then(|docker_image| Some(docker_image.as_slice().to_vec()));

		Some(DownloadInfo {
			app_id,
			app_hash: consensus_client.app_hash,
			file_name: consensus_client.file_name.into(),
			size: consensus_client.size,
			group: group_id,
			url: url.into(),
			args,
			log,
			is_docker_image,
			docker_image,
		})
	}

	// Consensus client startup at which block number.
	pub fn should_run() -> bool {
		let next_round = <pallet_sequencer_grouping::Pallet<T>>::next_round();

		let block_number = <frame_system::Pallet<T>>::block_number();

		if next_round.starting_block == block_number {
			true
		} else {
			false
		}
	}

	// Get sequencer group id.
	pub fn get_group_id(author: T::AccountId) -> u32 {
		let group_id_result = <pallet_sequencer_grouping::Pallet<T>>::account_in_group(author);
		if let Ok(group_id) = group_id_result {
			log::info!("new groupID:{:?}", group_id);
			group_id
		} else {
			0xFFFFFFFF
		}
	}

	// Get the assigned group id.
	pub fn get_groups() -> Vec<u32> {
		<pallet_sequencer_grouping::Pallet<T>>::all_group_ids()
	}

	// Whether the account running the current node has been assigned a group, whether it is a
	// processor, and whether the IP meets the requirements.
	pub fn processor_run(author: T::AccountId, ip_address: Vec<u8>) -> Vec<ProcessorDownloadInfo> {
		// let processors = <pallet_sequencer_grouping::Pallet<T>>::get_group_ids(author);
		let mut download_infos: Vec<ProcessorDownloadInfo> = Vec::new();
		if Self::get_groups().len() == 0 {
			return download_infos;
		}
		let url = DefaultUrl::<T>::get().expect("Need set url");

		let processor_info = <pallet_sequencer_grouping::Pallet<T>>::processor_info();
		let processors = if let Some((_, _, group_ids)) = processor_info
			.iter()
			.find(|(acc, ip, _)| (*acc == author) && (ip.to_vec() == ip_address))
		{
			group_ids.clone().into_inner()
		} else {
			Vec::new()
		};
		for group_id in processors {
			if let Some(app_id) = GroupAPPMap::<T>::get(group_id) {
				let p_app_info = APPInfoMap::<T>::get(app_id);

				if let Some(app_info) = p_app_info {
					let batch_client = app_info.batch_client;

					let args = batch_client.args.and_then(|log| Some(log.as_slice().to_vec()));

					let log = batch_client.log.and_then(|log| Some(log.as_slice().to_vec()));

					let is_docker_image = if let Some(is_docker) = batch_client.is_docker_image {
						is_docker
					} else {
						false
					};

					let docker_image = batch_client
						.docker_image
						.and_then(|docker_image| Some(docker_image.as_slice().to_vec()));
					download_infos.push(ProcessorDownloadInfo {
						app_id,
						app_hash: batch_client.app_hash,
						file_name: batch_client.file_name.into(),
						size: batch_client.size,
						url: url.clone().into(),
						args,
						log,
						is_docker_image,
						docker_image,
					});
				}
			}
		}
		download_infos
	}
}
