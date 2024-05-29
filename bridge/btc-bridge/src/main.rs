
use hex_literal::hex;

use light_bitcoin::{
    crypto::dhash160,
	chain::BlockHeader as BtcHeader,
    keys::Network as BtcNetwork,
    keys::{Address, AddressTypes, Public, Type},
    mast::Mast,
    script::{Builder, Opcode},
	merkle::PartialMerkleTree,
    serialization::{self, Reader},
};

use bitcoincore_rpc::{Auth, Client, RpcApi};

use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak, TweakedKeypair, UntweakedPublicKey};
use bitcoin::locktime::absolute;
use bitcoin::secp256k1::{rand, Signing, Verification};
//use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    transaction, Address as BtcAddress, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};

use subxt::{
    PolkadotConfig,
    utils::{AccountId32, MultiAddress},
    OnlineClient,
};
use subxt_signer::sr25519::dev::{self};
//use subxt::{Client, Error, RuntimeApi};
use std::convert::TryInto;
use secp256k1_zkp::{All, Message, Secp256k1, SecretKey, XOnlyPublicKey, schnorr::Signature};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task;

#[tokio::main]
pub async fn main() {
    if let Err(err) = run().await {
        eprintln!("{err}");
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("Btc bridge POC!");
	
    let network = BtcNetwork::Testnet;

	println!(" a 2/3 threshold signature merkel tree:");
	println!("    root(AB-AC(ABh,ACh), BCh)");
	
	
	let hash_preimage_bytes = hex!("0102f1f232313233381a67b0b1b2b31c");
	
	let prvkey1_bytes = hex!("4820b374e77f61bde6b386f78f1fa6c1926289cdfa4332bc55152d9930ab0091");
    let prvkey2_bytes = hex!("2d0d38419397aeddd0ff475e1d5c5460c70119b9cbe8f2a3c4cb44ff0dc304ad");
    let prvkey3_bytes = hex!("a4def4b20f84bcb8241b96d72a45c36d6778e6456283ec16e1c0a7613b6f4cc9");
	

    let pubkey1_bytes = hex!("0329cf83dcaf59a8aad6bb6edd884b05a9c4a999b02030f91373a088d7962eb8d6");
    let pubkey2_bytes = hex!("028bf9d1198c2881f10422aac3a61bb1a2bddf44400c421c4afaf6efd935b589da");
    let pubkey3_bytes = hex!("03144b84bce3f073ea31ebd8d6ffe4de514070bc46ec7a43d91a9fd4b569d37992");

    let prvkey1: SecretKey = Public::from_slice(&prvkey1_bytes);
    let prvkey2: SecretKey = Public::from_slice(&prvkey2_bytes);
    let prvkey2: SecretKey = Public::from_slice(&prvkey3_bytes);
	//generate_taproot_address and can deposit btc to it
	
  	let mut pubkeys = Vec::new();
    pubkeys.push(Public::from_slice(&pubkey1_bytes).unwrap());
    pubkeys.push(Public::from_slice(&pubkey2_bytes).unwrap());
    pubkeys.push(Public::from_slice(&pubkey3_bytes).unwrap());
    
	let pks = pubkeys
        .into_iter()
        .map(|k| k.try_into().unwrap())
        .collect::<Vec<_>>();
	
	let hashlock = dhash160(&hash_preimage_bytes);
    let mast = Mast::new(pks, 2u32, hashlock).unwrap();
    let taproot_addr: Address = mast
        .generate_address(&network.to_string())
        .unwrap()
        .parse()
        .unwrap();
		
	println!("Taproot address: {}", taproot_addr.to_string());

	let alice: MultiAddress<AccountId32, ()> = dev::alice().public_key().into();
    let alice_pair_signer = dev::alice();

    println!("Popsicle address: {}", dev::alice().address.to_string());

	// Loop:  check the taproot address new transactions: for output mint pBTC to 
    //      the address(Return Data reference),  for input complete proposal and 
    //      burn pending.
    //      check the Popsicle new PBTC burn transactions, create and send the withdraw
    //      transaction to BTC chain and set the proposal statu

    loop {
        //1. get the taproot address new confirmed transactions         
            // 获取最新的 n 个区块
                    
            // 检查最近的区块
            for height in block_heights_to_check {
                        
                // 检查区块中的每个交易， 获得所有锁定地址分别在input和output交易
                for tx in block.txdata {
                    
                }
            }

        //2. for taproot address's new transaction outs new_outs， mint pBTC
            if new_outs.len() > 0 {
  
                            // 提取 OP_RETURN 脚本中的数据
  
                            // 解码数据为 MultiAddress 结构
                          
 
                    println!("Popsicle address: {}", pop_address);
                    println!("Minting {} pBTC to the Popsicle address", mint_amount);

					// mint pBTC				
 
					println!("pBTC minted.");
       
            }

        //3. for taproot address's new transaction input， finalize proposal
            if new_ins.len() > 0 {
    
						//finish redeem or proposal
						println!("finalize proposal txid={}.", input.txid);	
			}
			
		 //4. check pBTC burn transaction, tranfer to a burn_address， withdraw BTC

                // get unspend list 

                    //create withdraw btc tx
   
                    //Use m private keys agg to signature and hash preimage to withdraw bt
					
						// threshold aggregated signature using mu_sig_sign
  
                        // put preimage and signature into witness
 
                    //send proposal start popsicle tx
	
						println!("start proposal .");	
                    //send proposal btc tx
			
	}		
}
    
async fn mu_sig_sign(message_hash: &H256, sk1: SecretKey, sk2: SecretKey) -> Signature {
     
        // 1. 公钥聚合
     
        // 2. 生成 nonce 承诺
     
        // 3. 交换 nonce 承诺
     
        // 验证收到的 nonce 承诺
     
        // 4. 计算部分签名
     
        // 5. 聚合部分签名
    
        // 6. 生成最终签名
  
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
/* 
   k = nonce, d=privateKey,  s=signature
   Schnorr:   sign(R=k*G, P=d*G, S=s*G): s = k + H(x(R)|x(P)|m) * d  : x(R) |s
             verify: S = R + H(x(R)|x(P)|m) * P
   ECDSA:    sign: s = k^-1 * (h(m) + p * R )    verify: R = s^-1 *H(m)*G + s^-1 *x(R)*P
*/
