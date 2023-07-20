use std::ops::Add;
use std::str::FromStr;

use anyhow::Context;
use bigdecimal::{BigDecimal, FromPrimitive, ToPrimitive};
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::sha256d;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::util::address::Payload;

use bitcoin::util::sighash::SighashCache;
use bitcoin::{
    Address, Network, OutPoint, PackedLockTime, Script, Sequence, TxIn, TxOut, Txid, Witness,
};
use rustmodel::{
    CreateSignTransactionRequest, CreateSignTransactionResult, CreateTransactionRequest,
    CreateTransactionResult, GetAddressRequest, GetAddressResult, KeyScheme, SendRequest,
    SignatureRecidHex, UnspentOutput, VerifyTransactionResult,
};

use crate::blockchain_lib::BlockchainLib;
use crate::utils;

pub struct BitcoinLib {}

impl BlockchainLib for BitcoinLib {
    fn get_address(
        &self,
        address_request: &GetAddressRequest,
    ) -> Result<GetAddressResult, anyhow::Error> {
        let key = bitcoin::secp256k1::PublicKey::from_slice(
            &utils::hex_to_bytes(
                address_request
                    .wallet_config
                    .pubkeys
                    .iter()
                    .find(|x| x.key_scheme == KeyScheme::ECDSA)
                    .context("ECDSA pubkey not found")?
                    .pubkey
                    .as_str(),
            )?[..],
        )?;
        let pubkey = bitcoin::PublicKey::new(key);
        let network = if address_request.wallet_config.is_mainnet {
            Network::Bitcoin
        } else {
            Network::Testnet
        };
        let address = if address_request.wallet_config.is_segwit {
            bitcoin::Address::p2wpkh(&pubkey, network)?.to_string()
        } else {
            bitcoin::Address::p2pkh(&pubkey, network).to_string()
        };
        Ok(GetAddressResult { address })
    }

    fn create_transaction(
        &self,
        transaction_request: &CreateTransactionRequest,
    ) -> Result<CreateTransactionResult, anyhow::Error> {
        let fee = estimate_fee(transaction_request.clone())
            .context("fee is not calculated successfully")?;
        let tx = create_transaction(transaction_request.clone(), fee.clone());
        let raw_transaction = serialize_hex(&tx.context("tx is required")?);
        let params = transaction_request
            .request_params_btc
            .clone()
            .expect("requestParamsBtc is required");
        let script_pubkeys = params
            .unspent_outputs
            .clone()
            .into_iter()
            .map(|x| x.script)
            .collect();
        let is_segwit =
            is_segwit_address(transaction_request.signing_request.from_address.as_str())?;
        if is_segwit {
            Ok(CreateTransactionResult {
                raw_transaction: raw_transaction.clone(),
                fee,
                hashes: get_segwit_signing_hashes(
                    raw_transaction.clone(),
                    transaction_request.signing_request.pubkey.clone(),
                    params.unspent_outputs,
                )?,
            })
        } else {
            Ok(CreateTransactionResult {
                raw_transaction: raw_transaction.clone(),
                fee,
                hashes: get_signing_hashes(raw_transaction.clone(), script_pubkeys),
            })
        }
    }

    fn sign_transaction(
        &self,
        transaction_request: &CreateSignTransactionRequest,
    ) -> Result<CreateSignTransactionResult, anyhow::Error> {
        let signed_tx = sign_transaction(
            transaction_request.raw_transaction.clone(),
            transaction_request.signatures.clone(),
            transaction_request.pubkey.clone(),
        )?;
        Ok(CreateSignTransactionResult {
            signed_transaction: signed_tx.clone(),
            transaction_hash: get_tx_id(signed_tx.clone()),
        })
    }

    fn verify_transaction(
        &self,
        transaction_request: &rustmodel::VerifyTransactionRequest,
    ) -> Result<rustmodel::VerifyTransactionResult, anyhow::Error> {
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
            Vec::from_hex(transaction_request.raw_transaction.as_str())
                .expect("fail to read hex tx data")
                .as_slice(),
        )
        .context("fail to deserialize tx")?;

        // verify address
        let request_address = transaction_request
            .clone()
            .signing_request
            .send_request
            .context("sendRequest is required")?
            .to_address;
        let output_addresses: Vec<String> = tx
            .output
            .iter()
            .map(|x| script_to_address(x.script_pubkey.clone(), false))
            .collect();
        if !output_addresses.contains(&request_address) {
            return Ok(VerifyTransactionResult {
                failed_reason: Some("request address is not in the output".to_string()),
            });
        }

        // verify amount
        let request_send_amount: BigDecimal = btc_to_sat(
            &transaction_request
                .clone()
                .signing_request
                .send_request
                .context("sendRequest is required")?
                .amount,
        );
        let encoded_send_amount: BigDecimal = BigDecimal::from_u64(
            tx.output
                .iter()
                .filter(|x| script_to_address(x.script_pubkey.clone(), false) == request_address)
                .map(|x| x.value)
                .sum(),
        )
        .context("fail to convert u64 to BigDecimal")?;
        if encoded_send_amount != request_send_amount {
            return Ok(VerifyTransactionResult {
                failed_reason: Some(format!(
                    "request amount is not in the output: {} != {}",
                    encoded_send_amount, request_send_amount
                )),
            });
        }

        return Ok(VerifyTransactionResult {
            failed_reason: None,
        });
    }
}

fn estimate_fee(
    transaction_request: CreateTransactionRequest,
) -> Result<BigDecimal, anyhow::Error> {
    let params = transaction_request
        .request_params_btc
        .expect("requestPramsBtc is required");
    let number_of_inputs = params.unspent_outputs.len();
    let number_of_outputs = 2; // change + recipient
    let is_segwit = is_segwit_address(transaction_request.signing_request.from_address.as_str())?;
    let vbytes = if is_segwit {
        number_of_inputs * 68 + number_of_outputs * 31 + 11
    } else {
        number_of_inputs * 148 + number_of_outputs * 34 + 10
    };
    let fee = BigDecimal::from_usize(vbytes).context("fail to convert vbytes to BigDecimal")?
        * params.fee_per_byte;
    Ok(fee)
}
pub fn pubkey_str_to_pubkey(pubkey: String) -> Result<bitcoin::PublicKey, anyhow::Error> {
    let key =
        bitcoin::secp256k1::PublicKey::from_slice(&utils::hex_to_bytes(pubkey.as_str())?[..])?;
    let pubkey = bitcoin::PublicKey::new(key);
    return Ok(pubkey);
}

fn get_tx_id(raw_tx: String) -> String {
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
        Vec::from_hex(raw_tx.as_str())
            .expect("fail to read hex tx data")
            .as_slice(),
    )
    .expect("fail to decode tx");
    return tx.txid().to_hex();
}

fn is_segwit_address(address_str: &str) -> Result<bool, anyhow::Error> {
    let address = Address::from_str(address_str)?;
    match address.payload {
        Payload::WitnessProgram { .. } => Ok(true),
        _ => Ok(false),
    }
}

fn sign_transaction(
    raw_tx: String,
    signatures: Vec<SignatureRecidHex>,
    pubkey: String,
) -> Result<String, anyhow::Error> {
    let mut tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
        Vec::from_hex(raw_tx.as_str())
            .expect("fail to read hex tx data")
            .as_slice(),
    )
    .expect("fail to decode tx");
    for i in 0..signatures.len() {
        if tx.input[i].script_sig.is_p2pkh() {
            // first verify if signature is signed by given pubkey key and msg
            let mut signature_hex = signatures[i].r.clone();
            signature_hex.push_str(signatures[i].s.as_str());
            let sign_bytes = utils::hex_to_bytes(signature_hex.as_str())
                .expect("Signature may not in correct format");
            let sig =
                Signature::from_compact(sign_bytes.as_slice()).expect("fail to read signature");

            // add signature to transaction
            let mut with_hashtype = sig.serialize_der().to_vec();
            with_hashtype.push(bitcoin::EcdsaSighashType::All.to_u32() as u8);
            let scriptsig = Builder::new()
                .push_slice(with_hashtype.as_slice())
                .push_slice(
                    hex::decode(pubkey_str_to_pubkey(pubkey.clone())?.to_string())?
                        .as_slice(),
                )
                .into_script();
            tx.input[i].script_sig = scriptsig;
        } else {
            let mut signature_hex = signatures[i].r.clone();
            signature_hex.push_str(signatures[i].s.as_str());
            let sign_bytes = utils::hex_to_bytes(signature_hex.as_str())
                .expect("Signature may not in correct format");
            let sig =
                Signature::from_compact(sign_bytes.as_slice()).expect("fail to read signature");

            // add signature to transaction
            let mut with_hashtype = sig.serialize_der().to_vec();
            with_hashtype.push(bitcoin::EcdsaSighashType::All.to_u32() as u8);
            let witness = Witness::from_vec(vec![
                with_hashtype,
                pubkey_str_to_pubkey(pubkey.clone())?.to_bytes(),
            ]);
            tx.input[i].witness = witness;
        }
    }
    return Ok(serialize_hex(&tx));
}

fn script_to_address(script: Script, is_mainnet: bool) -> String {
    let address = bitcoin::Address::from_script(
        &script,
        if is_mainnet {
            Network::Bitcoin
        } else {
            Network::Testnet
        },
    )
    .expect("fail to convert script to address");
    return address.to_string();
}

fn get_signing_hashes(raw_tx: String, script_pubkey_str: Vec<String>) -> Vec<String> {
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
        Vec::from_hex(raw_tx.as_str())
            .expect("fail to read hex tx data")
            .as_slice(),
    )
    .expect("fail to decode tx");
    let mut result: Vec<String> = Vec::new();
    for i in 0..tx.input.len() {
        let script_pubkey = Script::from_hex(script_pubkey_str[i].as_str())
            .expect(format!("fail to read input pubkey hash {}", i).as_str());
        let sig_hash =
            tx.signature_hash(i, &script_pubkey, bitcoin::EcdsaSighashType::All.to_u32());
        result.push(sig_hash[..].to_hex());
    }
    return result;
}

fn get_segwit_signing_hashes(
    raw_tx: String,
    pubkey: String,
    utxos: Vec<UnspentOutput>,
) -> Result<Vec<String>, anyhow::Error> {
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
        Vec::from_hex(raw_tx.as_str())
            .expect("fail to read hex tx data")
            .as_slice(),
    )
    .expect("fail to decode tx");
    let mut result: Vec<String> = Vec::new();
    for i in 0..tx.input.len() {
        let public_key = pubkey_str_to_pubkey(pubkey.clone())?;
        let script_pubkey = Address::p2pkh(&public_key, Network::Testnet).script_pubkey();
        let value = btc_to_sat(&utxos[i].amount)
            .to_u64()
            .expect("fail to convert amount to u64");
        let sig_hash = SighashCache::new(&tx)
            .segwit_signature_hash(i, &script_pubkey, value, bitcoin::EcdsaSighashType::All)
            .expect("fail to get segwit signature hash")
            .as_hash();
        result.push(sig_hash[..].to_hex());
    }
    return Ok(result);
}

fn btc_to_sat(input: &BigDecimal) -> BigDecimal {
    return input * BigDecimal::from(100_000_000);
}

fn create_transaction(
    transaction_request: CreateTransactionRequest,
    fee: BigDecimal,
) -> Result<bitcoin::Transaction, anyhow::Error> {
    let params = transaction_request
        .request_params_btc
        .expect("requestParamsBtc is required");
    let send_request: SendRequest = transaction_request
        .signing_request
        .send_request
        .context("sendRequest is required")?;
    let from_address = transaction_request.signing_request.from_address;
    let to_address = send_request.to_address;
    let to_amount = send_request.amount;
    let utxos = params.unspent_outputs.clone();

    let mut inputs = Vec::new();
    let sequence = Sequence::MAX; // 0xffffffff. Use lower value if want to RBF
    let mut version = 1;
    if is_segwit_address(from_address.as_str())? {
        version = 2;
        for i in 0..utxos.len() {
            inputs.push(TxIn {
                previous_output: OutPoint {
                    txid: Txid::from(sha256d::Hash::from_str(
                        &utxos[i].transaction_hash.as_str(),
                    )?),
                    vout: utxos[i].index as u32,
                },
                script_sig: Default::default(),
                sequence,
                witness: Default::default(),
            })
        }
    } else {
        for i in 0..utxos.len() {
            inputs.push(TxIn {
                previous_output: OutPoint {
                    txid: Txid::from(sha256d::Hash::from_str(
                        &utxos[i].transaction_hash.as_str(),
                    )?),
                    vout: utxos[i].index as u32,
                },
                script_sig: Script::from_str(utxos[i].script.as_str())?,
                sequence,
                witness: Default::default(),
            })
        }
    }
    let to_amount = btc_to_sat(&to_amount);
    let mut outputs = Vec::new();
    outputs.push(TxOut {
        value: to_amount
            .to_u64()
            .context("fail to convert BigDecimal to u64")?,
        script_pubkey: Address::from_str(to_address.as_str())?.script_pubkey(),
    });
    let total_in = utxos
        .into_iter()
        .map(|x| x.amount)
        .fold(BigDecimal::from(0), |s, unspent_amount| {
            btc_to_sat(&unspent_amount).add(s)
        });
    let fee_amount = btc_to_sat(&fee);
    let change_amount = total_in - to_amount - fee_amount;
    if change_amount.gt(&BigDecimal::from(0)) {
        outputs.push(TxOut {
            value: change_amount
                .to_u64()
                .context("fail to convert BigDecimal to u64")?,
            script_pubkey: Address::from_str(from_address.as_str())?.script_pubkey(),
        });
    }
    let tx = bitcoin::Transaction {
        version,
        lock_time: PackedLockTime::ZERO,
        input: inputs,
        output: outputs,
    };
    return Ok(tx);
}

#[cfg(test)]
mod segwit_tests {

    use rustmodel::{
        KeyScheme, RequestParamsBtc, SignatureRecidHex, SigningRequest, WalletCreationConfig,
        WalletCreationConfigPubkey,
    };

    use crate::blockchains::bitcoin_lib::*;

    #[test]
    fn should_return_segwit_address_from_pubkey() {
        assert_eq!(
            BitcoinLib {}
                .get_address(&GetAddressRequest {
                    blockchain: rustmodel::Blockchain::BITCOIN,
                    coin: rustmodel::Coin::BTC,
                    wallet_config: WalletCreationConfig {
                        is_segwit: true,
                        pubkeys: vec![WalletCreationConfigPubkey{
                            pubkey: String::from("02c090469fbb29bed9419ace8d4acc50abbc39dedd00b0e3fa861f817fae78d873"),
                            key_scheme: KeyScheme::ECDSA,
                        }],
                        is_mainnet: false,
                    }
                })
                .unwrap()
                .address,
            "tb1qk4ltnulq8rwlzvyxtc3vwn07pcsdhhz4xv372e"
        )
    }

    #[test]
    fn should_generate_segwit_transaction() {
        let result = BitcoinLib {}
            .create_transaction(&CreateTransactionRequest {
                blockchain: rustmodel::Blockchain::BITCOIN,
                coin: rustmodel::Coin::BTC,
                signing_request: SigningRequest {
                    id: String::from(""),
                    wallet_id: "wallet1".to_string(),
                    key_scheme: KeyScheme::ECDSA,
                    blockchain: rustmodel::Blockchain::BITCOIN,
                    coin: rustmodel::Coin::BTC,
                    pubkey: String::from(
                        "02c090469fbb29bed9419ace8d4acc50abbc39dedd00b0e3fa861f817fae78d873",
                    ),
                    from_address: String::from("tb1qk4ltnulq8rwlzvyxtc3vwn07pcsdhhz4xv372e"),
                    threshold: 1,
                    request_transaction_type: rustmodel::RequestTransactionType::SEND,
                    status: rustmodel::SigningStatus::SIGNING_COMPLETED,
                    message: None,
                    signing_result: None,
                    send_request: Some(SendRequest {
                        to_address: String::from("tb1qnurq5w3h8c3n96e23wvhq5jljkkvwnu2axrqcy"),
                        amount: BigDecimal::from_str("0.00001").unwrap(),
                    }),
                    send_token_request: None,
                    eth_smart_contract_request: None,
                    signers: vec![1, 2],
                    version: 0,
                    fee_level: rustmodel::FeeLevel::HIGH,
                    fee: None,
                    created_at: String::from(""),
                },
                request_params_btc: Some(RequestParamsBtc {
                    unspent_outputs: vec![rustmodel::UnspentOutput {
                        transaction_hash: String::from(
                            "a2febf03b2d9e1b1d7fb472805b49b2dfe1ee65b68d2f004684bb4fb243a8bbd",
                        ),
                        index: 0,
                        script: String::from("0014b57eb9f3e038ddf130865e22c74dfe0e20dbdc55"),
                        amount: BigDecimal::from_str("0.00006").unwrap(),
                    }],
                    fee_per_byte: BigDecimal::from_str("0.00000005").unwrap(),
                }),
                request_params_eth_legacy: None,
                request_params_eth_eip1559: None,
                request_params_ada: None,
            })
            .unwrap();
        assert_eq!(result.fee, BigDecimal::from_str("0.00000705").unwrap());
        assert_eq!(result.raw_transaction, "0200000001bd8b3a24fbb44b6804f0d2685be61efe2d9bb4052847fbd7b1e1d9b203bffea20000000000ffffffff02e8030000000000001600149f060a3a373e2332eb2a8b9970525f95acc74f8ac710000000000000160014b57eb9f3e038ddf130865e22c74dfe0e20dbdc5500000000");
        assert_eq!(
            result.hashes,
            vec!["bd82be05afedc3f399efde5cda2e590c69b6478bf888dc38c961b12105485333"]
        );
    }

    #[test]
    fn should_add_signature_to_segwit_tx() {
        let result = BitcoinLib {}.sign_transaction(&CreateSignTransactionRequest {
            blockchain: rustmodel::Blockchain::BITCOIN,
            coin: rustmodel::Coin::BTC,
            pubkey: String::from("02c090469fbb29bed9419ace8d4acc50abbc39dedd00b0e3fa861f817fae78d873"),
            raw_transaction: String::from("0200000001bd8b3a24fbb44b6804f0d2685be61efe2d9bb4052847fbd7b1e1d9b203bffea20000000000ffffffff02e8030000000000001600149f060a3a373e2332eb2a8b9970525f95acc74f8ac710000000000000160014b57eb9f3e038ddf130865e22c74dfe0e20dbdc5500000000"),
            hashes: vec![String::from("bd82be05afedc3f399efde5cda2e590c69b6478bf888dc38c961b12105485333")],
            signatures: vec![SignatureRecidHex { r: String::from("ca94ea1001fb90e4cce44d49bb9da0716091cf38caa5b7f03b3c838f59146829"), s: String::from("0fa207ee408439a2ff8687696cf6bc4ac89035d09bab50b695c47f258e4859c3"), recid: 0 }],
        }).unwrap();

        assert_eq!(
            result.clone().transaction_hash,
            "85450ab47e614ca1ec208c12526a25824033e336ddb1b3fbe1c82f82b49663e0"
        );

        assert_eq!(result.clone().signed_transaction,
                   "02000000000101bd8b3a24fbb44b6804f0d2685be61efe2d9bb4052847fbd7b1e1d9b203bffea20000000000ffffffff02e8030000000000001600149f060a3a373e2332eb2a8b9970525f95acc74f8ac710000000000000160014b57eb9f3e038ddf130865e22c74dfe0e20dbdc5502483045022100ca94ea1001fb90e4cce44d49bb9da0716091cf38caa5b7f03b3c838f5914682902200fa207ee408439a2ff8687696cf6bc4ac89035d09bab50b695c47f258e4859c3012102c090469fbb29bed9419ace8d4acc50abbc39dedd00b0e3fa861f817fae78d87300000000");
    }
}

#[cfg(test)]
mod non_segwit_tests {
    use bitcoin::secp256k1::{Message, Secp256k1};
    use rustmodel::{
        KeyScheme, RequestParamsBtc, SignatureRecidHex, SigningRequest, VerifyTransactionRequest,
        WalletCreationConfig, WalletCreationConfigPubkey,
    };

    use crate::blockchains::bitcoin_lib::*;

    #[test]
    fn should_return_address_from_pubkey() {
        assert_eq!(
            BitcoinLib {}
                .get_address(&GetAddressRequest {
                    blockchain: rustmodel::Blockchain::BITCOIN,
                    coin: rustmodel::Coin::BTC,
                    wallet_config: WalletCreationConfig {
                        pubkeys: vec![WalletCreationConfigPubkey{
                            pubkey: String::from("0273d7e0bdf15f941ebb587357737f825056c1db44300ce880177224f4f037e87d"),
                            key_scheme: KeyScheme::ECDSA,
                        }],
                        is_segwit: false,
                        is_mainnet: false,
                    }
                })
                .unwrap()
                .address,
            "mjuHBBAU2CvAZprRudUregToYWjgxhcnXY"
        )
    }

    #[test]
    fn should_return_address_from_pubkey2() {
        assert_eq!(
            BitcoinLib {}.get_address(&GetAddressRequest {
                blockchain: rustmodel::Blockchain::BITCOIN,
                coin: rustmodel::Coin::BTC,
                wallet_config: WalletCreationConfig{
                    is_segwit: false,
                    pubkeys: vec![WalletCreationConfigPubkey{
                        pubkey: String::from("0473d7e0bdf15f941ebb587357737f825056c1db44300ce880177224f4f037e87d532feedc0cc924bf8a93515d58f129aad44c8ee16de15156f97048c63bec7660"),
                        key_scheme: KeyScheme::ECDSA,
                    }],
                    is_mainnet: false,
                }
            }).unwrap().address,
            "mjuHBBAU2CvAZprRudUregToYWjgxhcnXY"
        )
    }

    #[test]
    fn should_generate_transaction_with_change2() {
        let result = BitcoinLib {}
            .create_transaction(&CreateTransactionRequest {
                blockchain: rustmodel::Blockchain::BITCOIN,
                coin: rustmodel::Coin::BTC,
                signing_request: SigningRequest {
                    id: String::from(""),
                    wallet_id: "wallet1".to_string(),
                    key_scheme: KeyScheme::ECDSA,
                    blockchain: rustmodel::Blockchain::BITCOIN,
                    coin: rustmodel::Coin::BTC,
                    pubkey: String::from(""),
                    from_address: String::from("my7igpePF4FCpDLAmMKtvneYrpWLpXMA4R"),
                    threshold: 1,
                    request_transaction_type: rustmodel::RequestTransactionType::SEND,
                    status: rustmodel::SigningStatus::SIGNING_COMPLETED,
                    message: None,
                    signing_result: None,
                    send_token_request: None,
                    send_request: Some(SendRequest {
                        to_address: String::from("tb1qnurq5w3h8c3n96e23wvhq5jljkkvwnu2axrqcy"),
                        amount: BigDecimal::from_str("0.00003").unwrap(),
                    }),
                    eth_smart_contract_request: None,
                    signers: vec![1, 2],
                    version: 0,
                    fee_level: rustmodel::FeeLevel::HIGH,
                    fee: None,
                    created_at: String::from(""),
                },
                request_params_eth_eip1559: None,
                request_params_eth_legacy: None,
                request_params_ada: None,
                request_params_btc: Some(RequestParamsBtc {
                    unspent_outputs: vec![rustmodel::UnspentOutput {
                        transaction_hash: String::from(
                            "549a8f3a0ec07f593b1cb93dca626eb1e81e7dcb644ce05f6aee0f9775b01f78",
                        ),
                        index: 1,
                        script: String::from("76a914c10d568b687de22049129a2e89d332e4d2569f5088ac"),
                        amount: BigDecimal::from_str("0.00027834").unwrap(),
                    }],
                    fee_per_byte: BigDecimal::from_str("0.00000005").unwrap(),
                }),
            })
            .unwrap();
        assert_eq!(result.fee, BigDecimal::from_str("0.0000113").unwrap());
        assert_eq!(result.raw_transaction, "0100000001781fb075970fee6a5fe04c64cb7d1ee8b16e62ca3db91c3b597fc00e3a8f9a54010000001976a914c10d568b687de22049129a2e89d332e4d2569f5088acffffffff02b80b0000000000001600149f060a3a373e2332eb2a8b9970525f95acc74f8a985c0000000000001976a914c10d568b687de22049129a2e89d332e4d2569f5088ac00000000");
        assert_eq!(
            result.hashes,
            vec!["f90540c525930512ca12ab519c3cc38d41564ec7d71a66ed5f06050be1ffc69e"]
        );
    }

    #[test]
    fn should_verify_valid_tx() {
        let result = BitcoinLib {}.verify_transaction(&VerifyTransactionRequest {
            blockchain: rustmodel::Blockchain::BITCOIN,
            coin: rustmodel::Coin::BTC,
            raw_transaction: "0100000001781fb075970fee6a5fe04c64cb7d1ee8b16e62ca3db91c3b597fc00e3a8f9a54010000001976a914c10d568b687de22049129a2e89d332e4d2569f5088acffffffff02b80b0000000000001600149f060a3a373e2332eb2a8b9970525f95acc74f8a985c0000000000001976a914c10d568b687de22049129a2e89d332e4d2569f5088ac00000000".to_string(),
            signing_request: SigningRequest {
                id: String::from(""),
                wallet_id: "wallet1".to_string(),
                key_scheme: KeyScheme::ECDSA,
                blockchain: rustmodel::Blockchain::BITCOIN,
                coin: rustmodel::Coin::BTC,
                pubkey: String::from(""),
                from_address: String::from("my7igpePF4FCpDLAmMKtvneYrpWLpXMA4R"),
                threshold: 1,
                request_transaction_type: rustmodel::RequestTransactionType::SEND,
                status: rustmodel::SigningStatus::SIGNING_COMPLETED,
                message: None,
                signing_result: None,
                send_token_request: None,
                send_request: Some(SendRequest {
                    to_address: String::from("tb1qnurq5w3h8c3n96e23wvhq5jljkkvwnu2axrqcy"),
                    amount: BigDecimal::from_str("0.00003").unwrap(),
                }),
                eth_smart_contract_request: None,
                version: 0,
                signers: vec![1, 2],
                fee_level: rustmodel::FeeLevel::HIGH,
                fee: Some(BigDecimal::from_str("0.0000113").unwrap()),
                created_at: String::from(""),
            },
        }).unwrap();
        assert_eq!(result.failed_reason, None);
    }

    #[test]
    fn should_verify() {
        let pk = pubkey_str_to_pubkey(
            "02f40320c28eb59aedef3c0c63674a33fa371d422d61230f969f988e3d2f88d743".to_string(),
        )
        .unwrap()
        .inner;
        let sign_bytes = utils::hex_to_bytes("4cd16eba55e18c1f6a29fcfda4771f9ec4bdd1d68c2061fb09d1182527761b006d406c60d273fbca0172c41408607492705420f16575064b42c8d97bb45c1efa").expect("Signature may not in correct format");
        let sig = Signature::from_compact(sign_bytes.as_slice()).expect("fail to read signature");
        let secp = Secp256k1::new();
        let msg = Message::from_slice(
            hex::decode("3c1a02a7c34d95c2dc30fd6ce1c694ec04d126b2e913430f567784dba0ffe7c0")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        secp.verify_ecdsa(&msg, &sig, &pk)
            .expect("signature does not match public key");
    }

    #[test]
    fn should_add_signature_to_tx() {
        // real data in blockchain
        // ecpoint: acd6734b71ea3969b8e9876b87a3cca4c7b88f7a404d752e36a596fcd98b2ac00e6e0face7fe5c6389656d65ddc1fdd3d9ad4e67d3969718c55c110111766bbf
        // unsign: 0100000001781fb075970fee6a5fe04c64cb7d1ee8b16e62ca3db91c3b597fc00e3a8f9a54010000001976a914c10d568b687de22049129a2e89d332e4d2569f5088acffffffff02b80b0000000000001600149f060a3a373e2332eb2a8b9970525f95acc74f8a1a5d0000000000001976a914c10d568b687de22049129a2e89d332e4d2569f5088ac00000000
        // signed: 0100000001781fb075970fee6a5fe04c64cb7d1ee8b16e62ca3db91c3b597fc00e3a8f9a54010000006b483045022100bc0b12a678168c2e84cd3e4a03fb053c76be9c74a94ca8538db75f1da3b616d102203e241533bfb4c9f7ded72a6abbf2c3141873fc7c2a96205739f00ed01fa8539d012103acd6734b71ea3969b8e9876b87a3cca4c7b88f7a404d752e36a596fcd98b2ac0ffffffff02b80b0000000000001600149f060a3a373e2332eb2a8b9970525f95acc74f8a1a5d0000000000001976a914c10d568b687de22049129a2e89d332e4d2569f5088ac00000000
        // to sign: 3c1a02a7c34d95c2dc30fd6ce1c694ec04d126b2e913430f567784dba0ffe7c0
        // signature: vAsSpngWjC6EzT5KA/sFPHa+nHSpTKhTjbdfHaO2FtE+JBUzv7TJ997XKmq78sMUGHP8fCqWIFc58A7QH6hTnQ==
        // tx id: 8183fec769b256f7c3b9b9e665ddfe97bfb762c05f51e401c1316dc336086b49
        // from: my7igpePF4FCpDLAmMKtvneYrpWLpXMA4R
        // to: tb1qnurq5w3h8c3n96e23wvhq5jljkkvwnu2axrqcy
        // amount: 0.00003
        // params: {"fee": "0.00001", "bitcoinUnspentOutput": [{"previousTxId": "549a8f3a0ec07f593b1cb93dca626eb1e81e7dcb644ce05f6aee0f9775b01f78", "scriptPubkey": "76a914c10d568b687de22049129a2e89d332e4d2569f5088ac", "unspentAmount": "0.00027834", "unspentTransactionIndex": 1}]}

        let result = BitcoinLib {}.sign_transaction(&CreateSignTransactionRequest {
            blockchain: rustmodel::Blockchain::BITCOIN,
            coin: rustmodel::Coin::BTC,
            pubkey: String::from("03acd6734b71ea3969b8e9876b87a3cca4c7b88f7a404d752e36a596fcd98b2ac0"),
            raw_transaction: String::from("0100000001781fb075970fee6a5fe04c64cb7d1ee8b16e62ca3db91c3b597fc00e3a8f9a54010000001976a914c10d568b687de22049129a2e89d332e4d2569f5088acffffffff02b80b0000000000001600149f060a3a373e2332eb2a8b9970525f95acc74f8a1a5d0000000000001976a914c10d568b687de22049129a2e89d332e4d2569f5088ac00000000"),
            hashes: vec![String::from("3c1a02a7c34d95c2dc30fd6ce1c694ec04d126b2e913430f567784dba0ffe7c0")],
            signatures: vec![SignatureRecidHex { r: String::from("bc0b12a678168c2e84cd3e4a03fb053c76be9c74a94ca8538db75f1da3b616d1"), s: String::from("3e241533bfb4c9f7ded72a6abbf2c3141873fc7c2a96205739f00ed01fa8539d"), recid: 0 }],
        }).unwrap();

        assert_eq!(
            result.clone().transaction_hash,
            "8183fec769b256f7c3b9b9e665ddfe97bfb762c05f51e401c1316dc336086b49"
        );

        assert_eq!(result.clone().signed_transaction,
                   "0100000001781fb075970fee6a5fe04c64cb7d1ee8b16e62ca3db91c3b597fc00e3a8f9a54010000006b483045022100bc0b12a678168c2e84cd3e4a03fb053c76be9c74a94ca8538db75f1da3b616d102203e241533bfb4c9f7ded72a6abbf2c3141873fc7c2a96205739f00ed01fa8539d012103acd6734b71ea3969b8e9876b87a3cca4c7b88f7a404d752e36a596fcd98b2ac0ffffffff02b80b0000000000001600149f060a3a373e2332eb2a8b9970525f95acc74f8a1a5d0000000000001976a914c10d568b687de22049129a2e89d332e4d2569f5088ac00000000");
    }
}
