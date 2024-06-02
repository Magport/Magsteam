#![cfg_attr(not(feature = "std"), no_std)]
use codec::{Codec, Decode, Encode};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_std::vec::Vec;

/// Client info of sequencer.
#[derive(Debug, Clone, TypeInfo, Encode, Decode, Default)]
pub struct DownloadInfo {
	/// App id.
	pub app_id: u32,
	/// App hash.
	pub app_hash: H256,
	/// File name of app.
	pub file_name: Vec<u8>,
	/// File size of app.
	pub size: u32,
	/// Group id of app.
	pub group: u32,
	/// Url of download binary client file.
	pub url: Vec<u8>,
	/// Arguments of startup client.
	pub args: Option<Vec<u8>>,
	/// Log file of startup client.
	pub log: Option<Vec<u8>>,
	/// Is starup of docker container.
	pub is_docker_image: bool,
	/// Docker image
	pub docker_image: Option<Vec<u8>>,
}

/// Client info of processor.
#[derive(Debug, Clone, TypeInfo, Encode, Decode, Default)]
pub struct ProcessorDownloadInfo {
	/// App id.
	pub app_id: u32,
	/// App hash.
	pub app_hash: H256,
	/// File name of app.
	pub file_name: Vec<u8>,
	/// File size of app.
	pub size: u32,
	/// Url of download binary client file.
	pub url: Vec<u8>,
	/// Arguments of startup client.
	pub args: Option<Vec<u8>>,
	/// Log file of startup client.
	pub log: Option<Vec<u8>>,
	/// Is starup of docker container.
	pub is_docker_image: bool,
	/// Docker image
	pub docker_image: Option<Vec<u8>>,
}

sp_api::decl_runtime_apis! {
	#[api_version(2)]
	pub trait ContainerRuntimeApi<AuthorityId> where
	AuthorityId:Codec
	{
		fn shuld_load(author:AuthorityId)->Option<DownloadInfo>;
		fn should_run()-> bool;
		fn get_group_id(author:AuthorityId) ->u32;
		fn get_groups()->Vec<u32>;
		fn processor_run(author:AuthorityId, ip_address:Vec<u8>)->Vec<ProcessorDownloadInfo>;
	}
}
