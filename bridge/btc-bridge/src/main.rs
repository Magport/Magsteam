use hex_literal::hex;
use light_bitcoin::{
	crypto::dhash160,
	//chain::TransactionOutput,
	keys::Network as LightNetwork,
	keys::Public,
	mast::key::KeyAgg,
	//script::Opcode,
	//merkle::PartialMerkleTree,
	//serialization::{self, Reader},
	mast::Mast,
};
use rand::rngs::OsRng;
use std::str::FromStr;

use bitcoincore_rpc::{Auth, Client, RpcApi};

use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::key::{Keypair, Parity};
use bitcoin::script::Instruction;
use bitcoin::transaction::Version;
//use bitcoin::key::{Keypair, TapTweak, TweakedKeypair, UntweakedPublicKey};
use bitcoin::locktime::absolute;
//use bitcoin::secp256k1::{rand, Signing, Verification};
use bitcoin::secp256k1::{
	schnorr::Signature, All, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
//use bitcoin::crypto::taproot::Signature;
use bitcoin::{
	Address as BtcAddress,
	Amount,
	Network,
	OutPoint,
	ScriptBuf,
	Sequence,
	Transaction,
	TxIn,
	TxOut,
	Witness, //Script,
};

use codec::Decode;
use subxt::{
	utils::{AccountId32, MultiAddress},
	OnlineClient, PolkadotConfig,
};
use subxt_signer::sr25519::dev::{self};
//use subxt::{Client, Error, RuntimeApi};
use std::convert::TryInto;
//use secp256k1_zkp::{All, Message, Secp256k1, SecretKey, XOnlyPublicKey, schnorr::Signature};
use tokio::sync::mpsc::channel; //Receiver, Sender
use tokio::task;

#[subxt::subxt(runtime_metadata_path = "statemint_metadata.scale")]
pub mod statemint {}

type StatemintConfig = PolkadotConfig;

#[tokio::main]
pub async fn main() {
	if let Err(err) = run().await {
		eprintln!("{err}");
	}
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
	println!("Btc bridge POC!");

	let light_network = LightNetwork::Testnet;
	let network = Network::Testnet;

	println!(" a 2/3 threshold signature merkel tree:");
	println!("    root(AB-AC(ABh,ACh), BCh)");

	let hash_preimage_bytes = hex!("0102f1f232313233381a67b0b1b2b31c");

	let prvkey1_bytes = hex!("4820b374e77f61bde6b386f78f1fa6c1926289cdfa4332bc55152d9930ab0091");
	let prvkey2_bytes = hex!("2d0d38419397aeddd0ff475e1d5c5460c70119b9cbe8f2a3c4cb44ff0dc304ad");
	let prvkey3_bytes = hex!("a4def4b20f84bcb8241b96d72a45c36d6778e6456283ec16e1c0a7613b6f4cc9");

	let pubkey1_bytes = hex!("0329cf83dcaf59a8aad6bb6edd884b05a9c4a999b02030f91373a088d7962eb8d6");
	let pubkey2_bytes = hex!("028bf9d1198c2881f10422aac3a61bb1a2bddf44400c421c4afaf6efd935b589da");
	let pubkey3_bytes = hex!("03144b84bce3f073ea31ebd8d6ffe4de514070bc46ec7a43d91a9fd4b569d37992");

	let prvkey1 = SecretKey::from_slice(&prvkey1_bytes).unwrap();
	let prvkey2 = SecretKey::from_slice(&prvkey2_bytes).unwrap();
	let _prvkey2 = SecretKey::from_slice(&prvkey3_bytes).unwrap();
	//generate_taproot_address and can deposit btc to it

	let mut pubkeys = Vec::new();
	pubkeys.push(Public::from_slice(&pubkey1_bytes).unwrap());
	pubkeys.push(Public::from_slice(&pubkey2_bytes).unwrap());
	pubkeys.push(Public::from_slice(&pubkey3_bytes).unwrap());

	let pks = pubkeys.into_iter().map(|k| k.try_into().unwrap()).collect::<Vec<_>>();

	let hashlock = dhash160(&hash_preimage_bytes);
	let mast = Mast::new(pks, 2u32, hashlock).unwrap();
	let taproot_addr_unchecked: BtcAddress<NetworkUnchecked> =
		mast.generate_address(&light_network.to_string()).unwrap().parse()?;
	let taproot_addr = taproot_addr_unchecked.require_network(network)?;

	println!("Taproot address: {}", taproot_addr.to_string());

	let alice: MultiAddress<AccountId32, ()> = dev::alice().public_key().into();
	let alice_pair_signer = dev::alice();

	println!("Popsicle address: {:?}", alice);

	// Loop:  check the taproot address new transactions: for output mint pBTC to
	//      the address(Return Data reference),  for input complete proposal and
	//      burn pending.
	//      check the Popsicle new PBTC burn transactions, create and send the withdraw
	//      transaction to BTC chain and set the proposal statu
	let client =
		Client::new("http://localhost:8332", Auth::UserPass("".to_string(), "".to_string()))
			.unwrap();

	let api = OnlineClient::<StatemintConfig>::from_url("ws://127.0.0.1:42069").await?;
	println!("Connection with parachain established.");

	let confirm_blocks = 6;
	let check_blocks = 10;
	loop {
		// Get bitcoin newwork the latest n blocks
		let latest_block_height = client.get_block_count()? as u128;
		println!("Loop, latest block height: {}", latest_block_height);

		let storage_query = statemint::storage().btc_bridge().last_btc_height();
		let last_btc_height = api.storage().at_latest().await?.fetch(&storage_query).await?;

		let mut checked_block_height = last_btc_height.unwrap_or(0);
		if checked_block_height < 1000 {
			checked_block_height = latest_block_height;

			let start_set_height_tx =
				statemint::tx().btc_bridge().set_btc_height(checked_block_height.into());
			let _start_set_height_events =
				api.tx()
					.sign_and_submit_then_watch_default(&start_set_height_tx, &alice_pair_signer)
					.await
					.map(|e| {
						println!("start set height tx submitted, waiting for transaction to be finalized...");
						e
					})?
					.wait_for_finalized_success()
					.await?;
			println!("start set checked block height:{}", checked_block_height);
		}

		println!("checked block height: {}", checked_block_height);

		let mut num_blocks_to_check = 0;
		if latest_block_height > checked_block_height + confirm_blocks {
			num_blocks_to_check = latest_block_height - (checked_block_height + confirm_blocks);
		}

		if num_blocks_to_check > check_blocks {
			// Adjustment as required
			num_blocks_to_check = check_blocks;
		} // Adjustment as required
		let block_heights_to_check =
			(checked_block_height..=checked_block_height + num_blocks_to_check).rev();

		// Check the nearest block
		for height in block_heights_to_check {
			//1. get the taproot address new confirmed transactions
			let block_hash = client.get_block_hash(height as u64)?;
			let block = client.get_block(&block_hash)?;

			// Check each transaction in the block, get all locked addresses in the input and
			// output transactions respectively
			let mut new_outs = Vec::new();
			let mut new_ins = Vec::new();
			for tx in block.txdata {
				let txid = tx.compute_txid();
				let raw_transaction = client.get_raw_transaction(&txid, Some(&block_hash))?;
				let decoded_transaction = raw_transaction; //raw_transaction.decode()?;

				let mut address_in_input = false;
				for input in &decoded_transaction.input {
					let inout_point = input.previous_output.clone();
					let inout_tx = client.get_raw_transaction(&inout_point.txid, None)?;
					let inout = &inout_tx.output[inout_point.vout as usize];
					if is_txoutput_address(&taproot_addr, &inout) {
						address_in_input = true;
						break;
					}
				}

				if address_in_input {
					println!("Found a new confirmed transaction involving the Taproot address input in block {}: {}", block_hash, txid);
					new_ins.push(decoded_transaction);
				} else if decoded_transaction
					.output
					.iter()
					.any(|output| is_txoutput_address(&taproot_addr, &output))
				{
					println!("Found a new confirmed transaction involving the Taproot address output in block {}: {}", block_hash, txid);
					new_outs.push(decoded_transaction);
				}
			}

			//2. for taproot address's new transaction outs new_outs， mint pBTC
			if new_outs.len() > 0 {
				for out in new_outs {
					let mut mint_amount: Amount = Amount::ZERO;
					let mut popsicle_address: Option<MultiAddress<AccountId32, ()>> = None;
					for output in &out.output {
						if is_txoutput_address(&taproot_addr, &output) {
							mint_amount =
								mint_amount.checked_add(output.value).ok_or("Amount overflow!")?;
						}
						if output.script_pubkey.as_script().is_op_return() {
							// Extracting data from OP_RETURN scripts
							let mut push_bytes: &[u8] = &[];
							let mut data = output
								.script_pubkey
								.as_script()
								.instructions()
								.find(|inst| match inst {
									Ok(Instruction::Op(_opcode)) => false,
									Ok(Instruction::PushBytes(bytes)) => {
										push_bytes = bytes.as_bytes();
										true
									},
									Err(_) => false,
								})
								.map(|_inst| push_bytes)
								.ok_or("No data found in OP_RETURN")?;

							// Decode the data into a MultiAddress structure
							popsicle_address = MultiAddress::decode(&mut data).ok();
						}
					}
					let pop_address = match popsicle_address {
						Some(address) => address,
						None => alice.clone(),
					};
					println!("Popsicle address: {:?}", pop_address);
					println!("Minting {} pBTC to the Popsicle address", mint_amount.to_sat());

					// mint pBTC
					let mint_tx = statemint::tx().btc_bridge().deposit_for_pbtc(
						height.try_into().unwrap(),
						out.compute_txid().as_byte_array().into(),
						mint_amount.to_sat().into(),
						pop_address.into(),
					);
					let _pBTC_mint_events =
						api.tx()
							.sign_and_submit_then_watch_default(&mint_tx, &alice_pair_signer)
							.await
							.map(|e| {
								println!("pBTC mint submitted, waiting for transaction to be finalized...");
								e
							})?
							.wait_for_finalized_success()
							.await?;
					println!("pBTC minted.");
				}
			}

			//3. for taproot address's new transaction input， finalize proposal
			if new_ins.len() > 0 {
				for input_tx in new_ins {
					let txid = input_tx.compute_txid();
					println!("finalize proposal txid={}.", txid);
					//finish redeem or proposal
					let fin_proposal_tx = statemint::tx().btc_bridge().redeem_process(
						1,
						txid.as_byte_array().into(),
						0u128,
						height.try_into().unwrap(),
					);
					let _fin_proposal_events = api
						.tx()
						.sign_and_submit_then_watch_default(&fin_proposal_tx, &alice_pair_signer)
						.await
						.map(|e| {
							println!("finalize proposal submitted, waiting for transaction to be finalized...");
							e
						})?
						.wait_for_finalized_success()
						.await?;
					println!("finalize proposal txid={}.", txid);
				}
			}

			//4. check pBTC burn transaction, tranfer to a burn_address， withdraw BTC
			let storage_query = statemint::storage().btc_bridge().redeem_info_pointer();
			let redeem_info_pointer =
				api.storage().at_latest().await?.fetch(&storage_query).await?;

			let result = redeem_info_pointer.unwrap_or((0, 0));
			// get unspend list
			let unspents =
				client.list_unspent(None, None, Some(&[&taproot_addr.clone()]), None, None)?;
			for redeem_id in result.0 + 1..result.1 {
				let storage_query = statemint::storage().btc_bridge().redeem_info_map(redeem_id);
				let redeem_info = api.storage().at_latest().await?.fetch(&storage_query).await?;

				let redeem_info = redeem_info.ok_or("redeem id in redeem info pointer error!")?;
				let sat_fee = Amount::from_sat(1000u64);
				let amount = Amount::from_sat(redeem_info.amount.try_into()?);
				let dest_address_unchecked = BtcAddress::<NetworkUnchecked>::from_str(
					std::str::from_utf8(redeem_info.btc_address.0.as_slice())?,
				)?;
				let dest_address = dest_address_unchecked.require_network(network)?;
				let amount_and_fee =
					amount.checked_add(sat_fee).ok_or("Amount pluse sat_fee overflow!")?;

				//create withdraw btc tx
				let spend = TxOut { value: amount, script_pubkey: dest_address.script_pubkey() };
				let mut unsigned_tx = Transaction {
					version: Version::TWO,               // Post BIP-68.
					lock_time: absolute::LockTime::ZERO, // Ignore the locktime.
					input: Vec::new(),                   // Input goes into index 0.
					output: vec![spend],                 // Outputs, order does not matter.
				};

				let mut prevouts: Vec<TxOut> = Vec::new();
				let amount_sum = Amount::from_sat(0u64);
				for unspent in unspents {
					let unspent_outpoint = OutPoint::new(unspent.txid, unspent.vout);
					let input = TxIn {
						previous_output: unspent_outpoint, // The dummy output we are spending.
						script_sig: ScriptBuf::default(),  // For a p2tr script_sig is empty.
						sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
						witness: Witness::default(), // Filled in after signing.
					};
					unsigned_tx.input.push(input);

					let prevout_tx = client.get_raw_transaction(&unspent.txid, None)?;
					let pre_txout = &prevout_tx.output[usize::try_from(unspent.vout)?];
					prevouts.push(pre_txout.clone());

					if amount_sum >= amount_and_fee {
						if amount_sum > amount_and_fee {
							let change_amount = amount_sum
								.checked_sub(amount_and_fee)
								.ok_or("Change amount overflow!")?;
							let change = TxOut {
								value: change_amount,
								script_pubkey: taproot_addr.clone().script_pubkey(),
							};

							unsigned_tx.output.push(change);
						}
						break;
					}
				}

				//Use m private keys agg to signature and hash preimage to withdraw bt
				let sighash_type = TapSighashType::Default;
				let prevouts_all = Prevouts::All(&prevouts);
				let mut input_index = 0;
				let mut unsigned_tx_sign = unsigned_tx.clone();
				let mut sighasher = SighashCache::new(&mut unsigned_tx_sign);
				for _input in &unsigned_tx.input {
					// threshold aggregated signature using mu_sig_sign
					let sighash = sighasher
						.taproot_key_spend_signature_hash(input_index, &prevouts_all, sighash_type)
						.expect("failed to construct sighash");

					let msg = Message::from(sighash);
					let signature = mu_sig_sign(&msg, &prvkey1, &prvkey2).await?;
					// put preimage and signature into witness
					let taproot_signature = bitcoin::taproot::Signature { signature, sighash_type };
					let mut witness = Witness::p2tr_key_spend(&taproot_signature);
					/*
					let preimage_script: Bytes = Builder::default()
							.push_bytes(&hash_preimage_bytes.to_vec())
							.into_script()
							.into();
					*/

					let control_block_result = mast.generate_merkle_proof(&mast.pubkeys[0]);
					if let Ok(control_block) = control_block_result {
						witness.push(hash_preimage_bytes);
						witness.push(control_block);
						*sighasher.witness_mut(input_index).unwrap() = witness;
						input_index = input_index + 1;
					} else {
						return Err("Generate merkle proof error!".into());
					}
				}

				let tx = sighasher.into_transaction();

				let mut buf = [0u8; 10240];
				let size = tx.consensus_encode(&mut &mut buf[..]).unwrap();
				//send proposal start popsicle tx
				let start_proposal_tx = statemint::tx().btc_bridge().redeem_process(
					0,
					tx.compute_txid().as_byte_array().into(),
					redeem_id,
					0u128,
				);
				let _start_proposal_events =
					api.tx()
						.sign_and_submit_then_watch_default(&start_proposal_tx, &alice_pair_signer)
						.await
						.map(|e| {
							println!("start proposal submitted, waiting for transaction to be finalized...");
							e
						})?
						.wait_for_finalized_success()
						.await?;
				println!("start proposal .");
				//send proposal btc tx
				client.send_raw_transaction(&buf[..size]);
				break;
			}

			let set_height_tx = statemint::tx().btc_bridge().set_btc_height(height.into());
			let _set_height_events = api
				.tx()
				.sign_and_submit_then_watch_default(&set_height_tx, &alice_pair_signer)
				.await
				.map(|e| {
					println!("set height tx submitted, waiting for transaction to be finalized...");
					e
				})?
				.wait_for_finalized_success()
				.await?;
			println!("set checked block height:{}", height);
		}
	}
}

// check the address being btc tx output address
fn is_txoutput_address(addr: &BtcAddress<NetworkChecked>, output: &TxOut) -> bool {
	let script = light_bitcoin::script::Script::from(output.script_pubkey.into_bytes());
	let script_addresses = script
		.extract_destinations()
		.unwrap_or(Vec::<light_bitcoin::script::ScriptAddress>::new());

	if script_addresses.len() == 1 {
		let address = &script_addresses[0];
		if let Ok(light_address) = addr.to_string().parse::<light_bitcoin::keys::Address>() {
			address.hash == light_address.hash
		} else {
			false
		}
	} else {
		false
	}
}

// funtion for musig
async fn mu_sig_sign(
	message: &Message,
	sk1: &SecretKey,
	sk2: &SecretKey,
) -> Result<Signature, Box<dyn std::error::Error>> {
	let secp = Secp256k1::new();
	//let message_hash = Message::from_slice(message).unwrap();

	// 1. generate Mugsig
	let public_keys: Vec<PublicKey> = Vec::new();
	public_keys.push(sk1.public_key(&secp));
	public_keys.push(sk2.public_key(&secp));

	let musig = Musig::new(secp, message, public_keys)?;

	// 2. Generating nonce commitments
	let (nonce1, nonce_point1, nonce_commitment1) = musig.generate_nonce();
	let (nonce2, nonce_point2, nonce_commitment2) = musig.generate_nonce();

	// 3. Exchange of nonce commitments
	let (nonce_sender, nonce_receiver) = channel(1);
	task::spawn(async move {
		nonce_sender.send(nonce_commitment1).await;
	});
	let received_nonce_commitment1 = nonce_receiver.recv().await;

	task::spawn(async move {
		nonce_sender.send(nonce_commitment2).await;
	});
	let received_nonce_commitment2 = nonce_receiver.recv().await;

	// and then exchange nonces
	task::spawn(async move {
		nonce_sender.send(nonce_point1).await;
	});
	let received_nonce_point1 = nonce_receiver.recv().await;

	task::spawn(async move {
		nonce_sender.send(nonce_point2).await;
	});
	let received_nonce_point2 = nonce_receiver.recv().await;

	// Validating received nonce commitments
	assert_eq!(sha256d::Hash::hash(nonce_point1), received_nonce_commitment1);
	assert_eq!(sha256d::Hash::hash(nonce_point2), received_nonce_commitment2);

	musig.add_nonce_point(nonce_point1);
	musig.add_nonce_point(nonce_point2);
	// 4. Calculation of partial signatures
	let part1 = musig.partial_sign(&sk1, &nonce1);
	let part2 = musig.partial_sign(&sk2, &nonce2);

	// and then exchange partial signature partial
	task::spawn(async move {
		nonce_sender.send(part1).await;
	});
	let received_part1 = nonce_receiver.recv().await;

	task::spawn(async move {
		nonce_sender.send(part2).await;
	});
	let received_part2 = nonce_receiver.recv().await;

	musig.add_signature(received_part1);
	musig.add_signature(received_part2);
	// 5. polymerization of partial signatures
	let final_signature = musig.combine_signatures()?;

	Ok(final_signature)
}

//Musig Type
struct Musig {
	secp: Secp256k1<All>,
	message: Message,
	public_keys: Vec<PublicKey>,
	nonce_points: Vec<PublicKey>,
	partial_signatures: Vec<Signature>,
	agg_nonce_point: Option<XOnlyPublicKey>,
	key_agg: KeyAgg,
}

impl Musig {
	fn new(
		secp: Secp256k1<All>,
		message: &Message,
		pub_keys: Vec<PublicKey>,
	) -> Result<Self, Box<dyn std::error::Error>> {
		Musig {
			secp,
			message,
			public_keys: pub_keys.clone(),
			nonce_point: Vec::new(),
			partial_signatures: Vec::new(),
			agg_nonce_point: None,
			key_agg: Mast::keys::KeyAgg::key_aggregation_n(pub_keys)?,
		}
	}

	// generate shared nonce point
	fn generate_nonce(&mut self) -> (SecretKey, PublicKey, sha256d::Hash) {
		let mut rng = OsRng;
		let nonce = SecretKey::new(&mut rng);
		let nonce_point = PublicKey::from_secret_key(&self.secp, &nonce);
		let nonce_point_commit = sha256d::Hash::hash(nonce_point.serialize());

		(nonce, nonce_point, nonce_point_commit)
	}
	// add nonce point
	fn add_nonce_point(&mut self, nonce_point: PublicKey) {
		self.nonce_points.push(nonce_point);
	}

	// partial sign
	fn partial_sign(&mut self, secret_key: &SecretKey, nonce: &SecretKey) -> Signature {
		if self.nonce_points.len() != self.public_keys.len() {
			return Err("nonce_points is not enough!");
		}

		if let None = self.agg_nonce_point {
			let mut agg_point = self.nonce_points[0].mul_tweak(&self.key_agg.a_coefficients[0])?;
			for i in 0..self.nonce_points.len() - 1 {
				agg_point = agg_point.combine(
					self.nonce_points[i + 1].mul_tweak(&self.key_agg.a_coefficients[i + 1])?,
				)?;
			}
			self.agg_nonce_point = Some(agg_point);
		}

		let message_hash = sha2::Sha256::from_bytes(message.to_bytes())
			.add(self.key_agg.xtidle.to_bytes())
			.add(self.agg_nonce_point.unwrap().to_bytes())
			.finalize();

		let partial_signature = self.secp.sign_schnorr_with_aux_rand(
			&Message::from(message_hash),
			Keypair::from_seckey(secret_key),
			nonce,
		);

		partial_signature
	}
	// add signature
	fn add_signature(&mut self, partial_signature: Signature) {
		self.partial_signatures.push(partial_signature);
	}
	// combine signatures
	fn combine_signatures(&self) -> Result<Signature, Box<dyn std::error::Error>> {
		if self.partial_signatures.len() != self.public_keys.len() {
			return Err("signatures is not enough!");
		}

		let sig_s_combine = SecretKey::from_slice(self.partial_signatures[0].serialize()[32..])
			.mul_tweak(&self.key_agg.a_coefficients[0])?;
		for i in 0..self.partial_signatures.len() - 1 {
			let sig_r_xonly =
				XOnlyPublicKey::from_slice(self.partial_signatures[i + 1].serialize()[0..32]);
			let sig_r = PublicKey::from_x_only_public_key(sig_r_xonly, Parity::Even);
			let sig_s = SecretKey::from_slice(self.partial_signatures[i + 1].serialize()[32..]);

			sig_r_combine =
				sig_r_combine.combine(sig_r.mul_tweak(&self.key_agg.a_coefficients[i + 1])?)?;
			sig_s_combine = sig_s_combine
				.add_tweak(sig_s.mul_tweak(&self.key_agg.a_coefficients[i + 1])?.into())?;
		}

		let mut array64u8 = [0u8; 64];
		let (sig_r_combine_xonly, _) = sig_r_combine.x_only_public_key();
		let sig_r_u8 = sig_r_combine_xonly.serialize();
		let sig_s_u8 = sig_s_combine.serialize();
		for i in 0..32 {
			array64u8[i] = sig_r_u8[i];
			array64u8[i + 32] = sig_s_u8[i];
		}
		let combined_signature = Signature::from_slice(&array64u8);

		Some(combined_signature)
	}
}

/*
$ node gkeys2.js
Private Key: 4820b374e77f61bde6b386f78f1fa6c1926289cdfa4332bc55152d9930ab0091
Compressed Public Key: 0329cf83dcaf59a8aad6bb6edd884b05a9c4a999b02030f91373a088d7962eb8d6
Bitcoin Address: 17qAFepiHdNQrQo21qJvv4JSdXefi2hFgz
[wd@localhost js]$ node gkeys2.js
Private Key: 2d0d38419397aeddd0ff475e1d5c5460c70119b9cbe8f2a3c4cb44ff0dc304ad
Compressed Public Key: 028bf9d1198c2881f10422aac3a61bb1a2bddf44400c421c4afaf6efd935b589da
Bitcoin Address: 1ExSAyvnsMr6VvxKLHQPxdWMre288nxjWa
[wd@localhost js]$ node gkeys2.js
Private Key: a4def4b20f84bcb8241b96d72a45c36d6778e6456283ec16e1c0a7613b6f4cc9
Compressed Public Key: 03144b84bce3f073ea31ebd8d6ffe4de514070bc46ec7a43d91a9fd4b569d37992
Bitcoin Address: 1AKVbFj7LnDz7VM2giR98ddCTdLKNSQezx
*/
