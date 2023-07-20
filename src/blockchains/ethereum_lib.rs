use std::ops::{Add, Mul};
use std::str::FromStr;

use anyhow::{anyhow, Context};
use bigdecimal::num_bigint::ToBigInt;

use bigdecimal::{BigDecimal, ToPrimitive};
use bitcoin::hashes::hex::ToHex;
use ethers::prelude::Signature;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, Eip1559TransactionRequest, TransactionRequest, U256};
use ethers::utils::rlp::{self};
use rustmodel::{
    CreateSignTransactionRequest, CreateSignTransactionResult, CreateTransactionRequest,
    CreateTransactionResult, GetAddressResult, KeyScheme, RequestTransactionType,
    SignatureRecidHex, VerifyTransactionResult,
};

use crate::blockchain_lib::BlockchainLib;
use crate::blockchains::bitcoin_lib::pubkey_str_to_pubkey;
use crate::utils::{self, bytes_to_hex, hex_to_bytes};

pub struct EthereumLib {}

impl BlockchainLib for EthereumLib {
    fn get_address(
        &self,
        address_request: &rustmodel::GetAddressRequest,
    ) -> Result<rustmodel::GetAddressResult, anyhow::Error> {
        let pubkey = pubkey_str_to_pubkey(
            address_request
                .wallet_config
                .pubkeys
                .iter()
                .find(|x| x.key_scheme == KeyScheme::ECDSA)
                .context("ECDSA pubkey not found")?
                .pubkey
                .clone(),
        )?
        .inner
        .serialize_uncompressed();
        // remove first byte 04
        let pubkey = &pubkey[1..];
        let result = ethers::core::utils::keccak256(hex_to_bytes(pubkey.to_hex().as_str())?);
        let address = &result[result.len() - 20..];
        let checksum =
            ethers::utils::to_checksum(&Address::from_str(address.to_hex().as_str())?, None);
        Ok(GetAddressResult { address: checksum })
    }

    fn create_transaction(
        &self,
        transaction_request: &CreateTransactionRequest,
    ) -> Result<CreateTransactionResult, anyhow::Error> {
        if transaction_request.request_params_eth_legacy.is_some() {
            create_legacy_transaction(transaction_request)
        } else {
            create_eip1559_transaction(transaction_request)
        }
    }

    fn sign_transaction(
        &self,
        transaction_request: &CreateSignTransactionRequest,
    ) -> Result<CreateSignTransactionResult, anyhow::Error> {
        let eip1559 = is_eip1559(transaction_request.raw_transaction.as_str())?;
        let tx = get_typed_transaction(transaction_request.raw_transaction.as_str())?;
        let v = tx.chain_id().context("chainId is required")?.as_u64() * 2
            + 35
            + transaction_request.signatures[0].recid as u64;
        let signed_tx = if eip1559 {
            sign_eip1559_transaction(
                transaction_request.raw_transaction.clone(),
                transaction_request.signatures[0].clone(),
                v as i64,
            )?
        } else {
            sign_transaction(
                transaction_request.raw_transaction.clone(),
                transaction_request.signatures[0].clone(),
                v as i64,
            )?
        };
        Ok(CreateSignTransactionResult {
            signed_transaction: signed_tx.clone(),
            transaction_hash: get_tx_hash(signed_tx.clone())?,
        })
    }

    fn verify_transaction(
        &self,
        transaction_request: &rustmodel::VerifyTransactionRequest,
    ) -> Result<rustmodel::VerifyTransactionResult, anyhow::Error> {
        let tx = get_typed_transaction(transaction_request.raw_transaction.as_str())?;
        // verify destination address
        let encoded_address = ethers::utils::to_checksum(
            &Address::from_slice(
                tx.to()
                    .context("to address is required")?
                    .as_address()
                    .context("encoded toAddress is invalid")?
                    .as_bytes(),
            ),
            None,
        );
        let encoded_amount = tx.value().context("amount is required")?;
        if transaction_request.signing_request.request_transaction_type
            == RequestTransactionType::SEND
        {
            let request_address = transaction_request
                .signing_request
                .clone()
                .send_request
                .context("send_request is required")?
                .to_address
                .clone();
            if encoded_address.to_lowercase() != request_address.to_lowercase() {
                return Ok(VerifyTransactionResult {
                    failed_reason: Some(
                        format!(
                            "destination address is invalid {} != {}",
                            encoded_address.to_lowercase(),
                            request_address.to_lowercase()
                        )
                        .to_string(),
                    ),
                });
            }

            // verify send amount
            let request_amount = ethers::utils::parse_ether(
                transaction_request
                    .signing_request
                    .clone()
                    .send_request
                    .context("send_request is required")?
                    .amount
                    .clone(),
            )?;
            if request_amount.ne(&encoded_amount) {
                return Ok(VerifyTransactionResult {
                    failed_reason: Some(
                        format!("amount is invalid {} != {}", request_amount, encoded_amount)
                            .to_string(),
                    ),
                });
            }
        } else if transaction_request.signing_request.request_transaction_type
            == RequestTransactionType::ETH_SMART_CONTRACT_CALL
        {
            let request_address = transaction_request
                .signing_request
                .clone()
                .eth_smart_contract_request
                .context("eth_smart_contract_request is required")?
                .to_address
                .clone();
            if encoded_address.to_lowercase() != request_address.to_lowercase() {
                return Ok(VerifyTransactionResult {
                    failed_reason: Some(
                        format!(
                            "destination address is invalid {} != {}",
                            encoded_address.to_lowercase(),
                            request_address.to_lowercase()
                        )
                        .to_string(),
                    ),
                });
            }

            // verify send amount
            let request_amount = ethers::utils::parse_ether(
                transaction_request
                    .signing_request
                    .clone()
                    .eth_smart_contract_request
                    .context("eth_smart_contract_request is required")?
                    .amount
                    .clone(),
            )?;
            if request_amount.ne(&encoded_amount) {
                return Ok(VerifyTransactionResult {
                    failed_reason: Some(format!(
                        "amount is invalid {} != {}",
                        request_amount, encoded_amount
                    )),
                });
            }
        }

        // verify fee amount
        let gas_price = match tx.clone() {
            TypedTransaction::Eip1559(x) => {
                x.max_fee_per_gas.context("fee is required")?
                    + x.max_priority_fee_per_gas
                        .context("priority fee is required")?
            }
            TypedTransaction::Legacy(x) => x.gas_price.context("fee is required")?,
            _ => return Err(anyhow!("invalid transaction type")),
        };
        let encoded_fee = tx.gas().context("fee is required")? * gas_price;
        let requested_fee_in_eth = transaction_request
            .signing_request
            .clone()
            .fee
            .context("fee is required")?;
        let requested_fee_in_wei = ethers::utils::parse_ether(requested_fee_in_eth)?;
        if encoded_fee != requested_fee_in_wei {
            return Ok(VerifyTransactionResult {
                failed_reason: Some(format!(
                    "fee is invalid {} != {}",
                    encoded_fee, requested_fee_in_wei
                )),
            });
        }

        // verify fee amount is less than send amount
        if encoded_amount.lt(&encoded_fee) {
            return Ok(VerifyTransactionResult {
                failed_reason: Some(format!(
                    "fee is invalid {} < {}",
                    encoded_amount, encoded_fee
                )),
            });
        }

        return Ok(VerifyTransactionResult {
            failed_reason: None,
        });
    }
}

fn get_typed_transaction(raw_transaction: &str) -> Result<TypedTransaction, anyhow::Error> {
    let vec = utils::hex_to_bytes(raw_transaction)?;
    let rlp = rlp::Rlp::new(&vec[0..]);
    let eip1559 = is_eip1559(raw_transaction)?;
    let tx: TypedTransaction = if eip1559 {
        Eip1559TransactionRequest::decode_base_rlp(&rlp, &mut 0)
            .context("decode transaction failed")?
            .into()
    } else {
        TransactionRequest::decode_unsigned_rlp(&rlp)
            .context("decode transaction failed")?
            .into()
    };
    Ok(tx)
}

fn is_eip1559(raw_transaction: &str) -> Result<bool, anyhow::Error> {
    let vec = hex_to_bytes(raw_transaction)?;
    let rlp = rlp::Rlp::new(&vec[0..]);
    return Ok(if TransactionRequest::decode_unsigned_rlp(&rlp).is_ok() {
        false
    } else if Eip1559TransactionRequest::decode_base_rlp(&rlp, &mut 0).is_ok() {
        true
    } else {
        false
    });
}

fn get_signing_hash(tx: String, eip1559: bool) -> Result<String, anyhow::Error> {
    let vec = utils::hex_to_bytes(tx.as_str())?;
    let rlp = rlp::Rlp::new(&vec[0..]);
    let tx: TypedTransaction = if eip1559 {
        Eip1559TransactionRequest::decode_base_rlp(&rlp, &mut 0)?.into()
    } else {
        TransactionRequest::decode_unsigned_rlp(&rlp)?.into()
    };
    return Ok(tx.sighash().to_hex());
}

fn get_tx_hash(signed_tx: String) -> Result<String, anyhow::Error> {
    let encoded = ethers::core::utils::keccak256(hex_to_bytes(signed_tx.as_str())?);
    return Ok(bytes_to_hex(encoded.to_vec()));
}

fn create_legacy_transaction(
    transaction_request: &CreateTransactionRequest,
) -> Result<CreateTransactionResult, anyhow::Error> {
    let params = transaction_request
        .clone()
        .request_params_eth_legacy
        .context("requestParamsEthLegacy is required")?;
    let (data, amount, to_address, gas_limit) = if transaction_request
        .clone()
        .signing_request
        .request_transaction_type
        == RequestTransactionType::ETH_SMART_CONTRACT_CALL
    {
        let request_data = transaction_request
            .signing_request
            .eth_smart_contract_request
            .clone()
            .expect("ethSmartContractRequest is required");
        (
            request_data.data,
            request_data.amount,
            request_data.to_address,
            request_data.gas_limit,
        )
    } else if transaction_request
        .clone()
        .signing_request
        .request_transaction_type
        == RequestTransactionType::SEND
    {
        let send_request = transaction_request
            .clone()
            .signing_request
            .send_request
            .context("sendRequest is required")?;

        (
            "".to_string(),
            send_request.amount,
            send_request.to_address,
            BigDecimal::from(21_000),
        )
    } else {
        process_token_send(transaction_request)?
    };

    let fee = gas_limit.clone().mul(params.gas_fee.clone());
    let gas_price = ethers::utils::parse_ether(params.gas_fee.clone().to_string())?;

    let raw_transaction = TransactionRequest::new()
        .gas(U256::from(
            gas_limit.to_u64().context("gas limit is required")?,
        ))
        .to(Address::from_str(to_address.as_str())?)
        .nonce(params.nonce)
        .value(ethers::utils::parse_ether(amount)?)
        .chain_id(
            params
                .chain_id
                .parse::<u64>()
                .context("chainId is required")?,
        )
        .gas_price(gas_price)
        .data(hex_to_bytes(data.as_str())?)
        .rlp()
        .to_hex()
        .replace("0x", "");
    Ok(CreateTransactionResult {
        raw_transaction: raw_transaction.clone(),
        fee,
        hashes: vec![get_signing_hash(raw_transaction.clone(), false)?],
    })
}

fn process_token_send(
    transaction_request: &CreateTransactionRequest,
) -> Result<(String, BigDecimal, String, BigDecimal), anyhow::Error> {
    let send_request = transaction_request
        .clone()
        .signing_request
        .send_token_request
        .context("sendTokenRequest is required")?;

    let _method = String::from("a9059cbb");
    let _to = format!(
        "000000000000000000000000{}",
        send_request.to_address.trim_start_matches("0x")
    );
    let _value = format!(
        "{:064x}",
        send_request
            .amount
            .clone()
            .mul(
                BigDecimal::from_str(format!("1e{}", send_request.decimals).as_str())
                    .expect("decimal is invalid"),
            )
            .to_bigint().context("amount is invalid")?
    );
    let data = format!("{}{}{}", _method, _to, _value).to_lowercase();
    if data.len() != 8 + 64 + 64 {
        return Err(anyhow!("data is invalid"));
    }

    Ok((
        data,
        send_request.amount,
        send_request.token_contract_address,
        BigDecimal::from(120_000),
    ))
}

fn create_eip1559_transaction(
    transaction_request: &CreateTransactionRequest,
) -> Result<CreateTransactionResult, anyhow::Error> {
    let params = transaction_request
        .clone()
        .request_params_eth_eip1559.context("requestParamsEthEip1559 is required")?;
    let (data, amount, to_address, gas_limit) = if transaction_request
        .clone()
        .signing_request
        .request_transaction_type
        == RequestTransactionType::ETH_SMART_CONTRACT_CALL
    {
        let request_data = transaction_request
            .signing_request
            .eth_smart_contract_request
            .clone()
            .expect("ethSmartContractRequest is required");
        (
            request_data.data,
            request_data.amount,
            request_data.to_address,
            request_data.gas_limit,
        )
    } else if transaction_request
        .clone()
        .signing_request
        .request_transaction_type
        == RequestTransactionType::SEND
    {
        let send_request = transaction_request
            .clone()
            .signing_request
            .send_request
            .context("sendRequest is required")?;

        (
            "".to_string(),
            send_request.amount,
            send_request.to_address,
            BigDecimal::from(21_000),
        )
    } else {
        process_token_send(transaction_request)?
    };

    let fee = gas_limit
        .clone()
        .mul(params.base_gas_fee.clone().add(params.priority_fee.clone()));
    let raw_transaction = Eip1559TransactionRequest::new()
        .to(Address::from_str(to_address.as_str())?)
        .nonce(params.nonce)
        .chain_id(
            params
                .chain_id
                .parse::<u64>()
                .context("chain id is required")?,
        )
        .value(ethers::utils::parse_ether(amount)?)
        .gas(U256::from(
            gas_limit.to_u64().context("gas limit is required")?,
        ))
        .max_fee_per_gas(ethers::utils::parse_ether(params.base_gas_fee)?)
        .max_priority_fee_per_gas(ethers::utils::parse_ether(params.priority_fee)?)
        .data(hex_to_bytes(data.as_str())?)
        .rlp()
        .to_hex()
        .replace("0x", "");
    Ok(CreateTransactionResult {
        raw_transaction: raw_transaction.clone(),
        fee,
        hashes: vec![get_signing_hash(raw_transaction.clone(), true)?],
    })
}

fn sign_transaction(
    tx: String,
    signature: SignatureRecidHex,
    v: i64,
) -> Result<String, anyhow::Error> {
    let vec = utils::hex_to_bytes(tx.as_str())?;
    let rlp = rlp::Rlp::new(&vec[0..]);
    let tx: TypedTransaction = TransactionRequest::decode_unsigned_rlp(&rlp)?.into();
    // let tx: TypedTransaction = Eip1559TransactionRequest::decode_base_rlp(&rlp, &mut 0)?.into();
    let mut signature_obj =
        Signature::from_str(&format!("{}{}00", signature.r.clone(), signature.s.clone(),))?;
    signature_obj.v = v as u64;
    return Ok(tx.rlp_signed(&signature_obj).to_hex().replace("0x", ""));
}

fn sign_eip1559_transaction(
    tx: String,
    signature: SignatureRecidHex,
    v: i64,
) -> Result<String, anyhow::Error> {
    let vec = utils::hex_to_bytes(tx.as_str())?;
    let rlp = rlp::Rlp::new(&vec[0..]);
    let tx: TypedTransaction = Eip1559TransactionRequest::decode_base_rlp(&rlp, &mut 0)?.into();
    let mut signature_obj =
        Signature::from_str(&format!("{}{}00", signature.r.clone(), signature.s.clone(),))?;
    signature_obj.v = v as u64;
    return Ok(tx.rlp_signed(&signature_obj).to_hex().replace("0x", ""));
}

#[cfg(test)]
mod eip1559_tests {
    use rustmodel::{
        KeyScheme, RequestParamsEthEip1559, SignatureRecidHex, VerifyTransactionRequest,
    };

    use crate::blockchains::ethereum_lib::*;

    #[test]
    fn should_create_a_transaction() {
        let result = EthereumLib {}
            .create_transaction(&CreateTransactionRequest {
                blockchain: rustmodel::Blockchain::ETHEREUM,
                coin: rustmodel::Coin::ETH,
                signing_request: rustmodel::SigningRequest {
                    id: String::from(""),
                    wallet_id: "wallet1".to_string(),
                    key_scheme: KeyScheme::ECDSA,
                    blockchain: rustmodel::Blockchain::ETHEREUM,
                    coin: rustmodel::Coin::ETH,
                    pubkey: String::from(
                        "02c090469fbb29bed9419ace8d4acc50abbc39dedd00b0e3fa861f817fae78d873",
                    ),
                    from_address: String::from("0x2FFa03c290DdB5d3F0907802c1448258621246CB"),
                    threshold: 1,
                    request_transaction_type: rustmodel::RequestTransactionType::SEND,
                    status: rustmodel::SigningStatus::SIGNING_COMPLETED,
                    message: None,
                    signing_result: None,
                    send_request: Some(rustmodel::SendRequest {
                        to_address: "0x1404DC99E220702365255145EeD9c2a0F7BB7727".to_string(),
                        amount: BigDecimal::from_str("0.001").unwrap(),
                    }),
                    send_token_request: None,
                    eth_smart_contract_request: None,
                    signers: vec![1, 2],
                    version: 0,
                    fee_level: rustmodel::FeeLevel::HIGH,
                    fee: None,
                    created_at: String::from(""),
                },
                request_params_btc: None,
                request_params_ada: None,
                request_params_eth_eip1559: Some(RequestParamsEthEip1559 {
                    base_gas_fee: BigDecimal::from_str("0.00000002").unwrap(),
                    priority_fee: BigDecimal::from_str("0.000000001").unwrap(),
                    chain_id: String::from("11155111"),
                    nonce: 0,
                }),
                request_params_eth_legacy: None,
            })
            .unwrap();
        assert_eq!(result.fee, BigDecimal::from_str("0.000441").unwrap());
        assert_eq!(result.raw_transaction, "f283aa36a780843b9aca008504a817c800825208941404dc99e220702365255145eed9c2a0f7bb772787038d7ea4c6800080c0");
        assert_eq!(
            result.hashes[0],
            "c70dbd68d675f992198a9d14b4c76ddac58955b5e2b5011d22a7b07d22903f91"
        );
    }

    #[test]
    fn should_verify_valid_tx() {
        let result = EthereumLib {}.verify_transaction(&VerifyTransactionRequest {
            blockchain: rustmodel::Blockchain::ETHEREUM,
            coin: rustmodel::Coin::ETH,
            raw_transaction: "f083aa36a780843b9aca00847735940082520894396397247a4e9b9cc6397d103a3aaeb3c524bcda865af3107a400080c0".to_string(),
            signing_request: rustmodel::SigningRequest {
                id: String::from(""),
                wallet_id: "wallet1".to_string(),
                key_scheme: KeyScheme::ECDSA,
                blockchain: rustmodel::Blockchain::ETHEREUM,
                coin: rustmodel::Coin::ETH,
                pubkey: String::from(""),
                from_address: String::from("0xACF4c5eea20B11a48C21808F881Da6618901531A"),
                threshold: 1,
                request_transaction_type: rustmodel::RequestTransactionType::SEND,
                status: rustmodel::SigningStatus::SIGNING_COMPLETED,
                message: None,
                signing_result: None,
                send_token_request: None,
                eth_smart_contract_request: None,
                send_request: Some(rustmodel::SendRequest {
                    to_address: "0x396397247a4E9b9cC6397D103A3AaEB3c524bCda".to_string(),
                    amount: BigDecimal::from_str("0.0001").unwrap(),
                }),
                version: 0,
                signers: vec![1, 2],
                fee_level: rustmodel::FeeLevel::HIGH,
                fee: Some(BigDecimal::from_str("0.000063").unwrap()),
                created_at: String::from(""),
            },
        }).unwrap();
        assert_eq!(result.failed_reason, None);
    }

    #[test]
    fn should_verify_valid_tx_with_lowcase_address() {
        let result = EthereumLib {}.verify_transaction(&VerifyTransactionRequest {
            blockchain: rustmodel::Blockchain::ETHEREUM,
            coin: rustmodel::Coin::ETH,
            raw_transaction: "f083aa36a780843b9aca00847735940082520894396397247a4e9b9cc6397d103a3aaeb3c524bcda865af3107a400080c0".to_string(),
            signing_request: rustmodel::SigningRequest {
                id: String::from(""),
                wallet_id: "wallet1".to_string(),
                key_scheme: KeyScheme::ECDSA,
                blockchain: rustmodel::Blockchain::ETHEREUM,
                coin: rustmodel::Coin::ETH,
                pubkey: String::from(""),
                from_address: String::from("0xacf4c5eea20b11a48c21808f881da6618901531a"),
                threshold: 1,
                request_transaction_type: rustmodel::RequestTransactionType::SEND,
                status: rustmodel::SigningStatus::SIGNING_COMPLETED,
                message: None,
                signing_result: None,
                send_token_request: None,
                eth_smart_contract_request: None,
                send_request: Some(rustmodel::SendRequest {
                    to_address: "0x396397247a4e9b9cc6397d103a3aaeb3c524bcda".to_string(),
                    amount: BigDecimal::from_str("0.0001").unwrap(),
                }),
                version: 0,
                signers: vec![1, 2],
                fee_level: rustmodel::FeeLevel::HIGH,
                fee: Some(BigDecimal::from_str("0.000063").unwrap()),
                created_at: String::from(""),
            },
        }).unwrap();
        assert_eq!(result.failed_reason, None);
    }

    #[test]
    fn should_sign_a_transaction() {
        let result = EthereumLib {}.sign_transaction(&CreateSignTransactionRequest {
            blockchain: rustmodel::Blockchain::ETHEREUM,
            coin: rustmodel::Coin::ETH,
            pubkey: String::from("02c090469fbb29bed9419ace8d4acc50abbc39dedd00b0e3fa861f817fae78d873"),
            raw_transaction: "f283aa36a780843b9aca008504a817c800825208941404dc99e220702365255145eed9c2a0f7bb772787038d7ea4c6800080c0".to_string(),
            hashes: vec![String::from("c70dbd68d675f992198a9d14b4c76ddac58955b5e2b5011d22a7b07d22903f91")],
            signatures: vec![SignatureRecidHex{ r: "ca94ea1001fb90e4cce44d49bb9da0716091cf38caa5b7f03b3c838f59146829".to_string(), s: "0f04642bd3af6a73e81ed0604fec808dbd151a6bfe99d4f2f7d741e775cc3e34".to_string(), recid: 0 }],
        }).unwrap();

        assert_eq!(result.signed_transaction, "02f87583aa36a780843b9aca008504a817c800825208941404dc99e220702365255145eed9c2a0f7bb772787038d7ea4c6800080c080a0ca94ea1001fb90e4cce44d49bb9da0716091cf38caa5b7f03b3c838f59146829a00f04642bd3af6a73e81ed0604fec808dbd151a6bfe99d4f2f7d741e775cc3e34");
        assert_eq!(
            result.transaction_hash,
            "760a4a74191c689493b0619d564084c538102e2b6fbfd4993a204b89ce1aa716"
        );
    }
}

#[cfg(test)]
mod smartcontract_tests {
    use rustmodel::{KeyScheme, RequestParamsEthEip1559, VerifyTransactionRequest};

    use crate::blockchains::ethereum_lib::*;

    #[test]
    fn should_create_a_transaction() {
        let result = EthereumLib {}
            .create_transaction(&CreateTransactionRequest {
                blockchain: rustmodel::Blockchain::ETHEREUM,
                coin: rustmodel::Coin::ETH,
                signing_request: rustmodel::SigningRequest {
                    id: String::from(""),
                    wallet_id: "wallet1".to_string(),
                    key_scheme: KeyScheme::ECDSA,
                    blockchain: rustmodel::Blockchain::ETHEREUM,
                    coin: rustmodel::Coin::ETH,
                    pubkey: String::from(
                        "02c090469fbb29bed9419ace8d4acc50abbc39dedd00b0e3fa861f817fae78d873",
                    ),
                    from_address: String::from("0x2FFa03c290DdB5d3F0907802c1448258621246CB"),
                    threshold: 1,
                    request_transaction_type:
                        rustmodel::RequestTransactionType::ETH_SMART_CONTRACT_CALL,
                    status: rustmodel::SigningStatus::SIGNING_COMPLETED,
                    message: None,
                    signing_result: None,
                    send_request: None,
                    send_token_request: None,
                    eth_smart_contract_request: Some(rustmodel::EthContractRequest {
                        amount: BigDecimal::from_str("0.0001").unwrap(),
                        data: String::from("0xa9059cbb"),
                        gas_limit: BigDecimal::from_str("21000").unwrap(),
                        to_address: String::from("0x396397247a4E9b9cC6397D103A3AaEB3c524bCda"),
                    }),
                    signers: vec![1, 2],
                    version: 0,
                    fee_level: rustmodel::FeeLevel::HIGH,
                    fee: None,
                    created_at: String::from(""),
                },
                request_params_btc: None,
                request_params_eth_legacy: None,
                request_params_ada: None,
                request_params_eth_eip1559: Some(RequestParamsEthEip1559 {
                    base_gas_fee: BigDecimal::from_str("0.00000002").unwrap(),
                    priority_fee: BigDecimal::from_str("0.000000001").unwrap(),
                    chain_id: String::from("11155111"),
                    nonce: 0,
                }),
            })
            .unwrap();
        assert_eq!(result.fee, BigDecimal::from_str("0.000441").unwrap());
        assert_eq!(result.raw_transaction, "f583aa36a780843b9aca008504a817c80082520894396397247a4e9b9cc6397d103a3aaeb3c524bcda865af3107a400084a9059cbbc0");
        assert_eq!(
            result.hashes[0],
            "bf9f8c4f3c4f27c9e1ff93ecd501a2a8f2b6f5868d96523acfbfefe4608d0a27"
        );
    }

    #[test]
    fn should_verify_valid_tx() {
        let result = EthereumLib {}.verify_transaction(&VerifyTransactionRequest {
            blockchain: rustmodel::Blockchain::ETHEREUM,
            coin: rustmodel::Coin::ETH,
            raw_transaction: "f083aa36a780843b9aca00847735940082520894396397247a4e9b9cc6397d103a3aaeb3c524bcda865af3107a400080c0".to_string(),
            signing_request: rustmodel::SigningRequest {
                id: String::from(""),
                wallet_id: "wallet1".to_string(),
                key_scheme: KeyScheme::ECDSA,
                blockchain: rustmodel::Blockchain::ETHEREUM,
                coin: rustmodel::Coin::ETH,
                pubkey: String::from(""),
                from_address: String::from("0xACF4c5eea20B11a48C21808F881Da6618901531A"),
                threshold: 1,
                request_transaction_type:
                rustmodel::RequestTransactionType::ETH_SMART_CONTRACT_CALL,
                status: rustmodel::SigningStatus::SIGNING_COMPLETED,
                message: None,
                signing_result: None,
                send_token_request: None,
                eth_smart_contract_request: Some(rustmodel::EthContractRequest {
                    amount: BigDecimal::from_str("0.0001").unwrap(),
                    data: String::from("0xa9059cbb"),
                    gas_limit: BigDecimal::from_str("21000").unwrap(),
                    to_address: String::from("0x396397247a4E9b9cC6397D103A3AaEB3c524bCda"),
                }),
                send_request: None,
                version: 0,
                signers: vec![1, 2],
                fee_level: rustmodel::FeeLevel::HIGH,
                fee: Some(BigDecimal::from_str("0.000063").unwrap()),
                created_at: String::from(""),
            },
        }).unwrap();
        assert_eq!(result.failed_reason, None);
    }
}

#[cfg(test)]
mod token_tests {
    use rustmodel::{KeyScheme, RequestParamsEthEip1559};

    use crate::blockchains::ethereum_lib::*;

    #[test]
    fn should_create_a_transaction() {
        let result = EthereumLib {}
            .create_transaction(&CreateTransactionRequest {
                blockchain: rustmodel::Blockchain::ETHEREUM,
                coin: rustmodel::Coin::USDT,
                signing_request: rustmodel::SigningRequest {
                    id: String::from(""),
                    wallet_id: "wallet1".to_string(),
                    key_scheme: KeyScheme::ECDSA,
                    blockchain: rustmodel::Blockchain::ETHEREUM,
                    coin: rustmodel::Coin::ETH,
                    pubkey: String::from(
                        "02c090469fbb29bed9419ace8d4acc50abbc39dedd00b0e3fa861f817fae78d873",
                    ),
                    from_address: String::from("0x2FFa03c290DdB5d3F0907802c1448258621246CB"),
                    threshold: 1,
                    request_transaction_type: rustmodel::RequestTransactionType::SEND_TOKEN,
                    status: rustmodel::SigningStatus::SIGNING_COMPLETED,
                    message: None,
                    signing_result: None,
                    send_request: None,
                    send_token_request: Some(rustmodel::SendTokenRequest {
                        amount: BigDecimal::from_str("0.0001").unwrap(),
                        decimals: 6,
                        to_address: String::from("0x422B707aBfd76c5366E05416649324e8d95666eF"),
                        token_contract_address: String::from(
                            "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                        ),
                    }),
                    eth_smart_contract_request: None,
                    signers: vec![1, 2],
                    version: 0,
                    fee_level: rustmodel::FeeLevel::HIGH,
                    fee: None,
                    created_at: String::from(""),
                },
                request_params_btc: None,
                request_params_ada: None,
                request_params_eth_eip1559: Some(RequestParamsEthEip1559 {
                    base_gas_fee: BigDecimal::from_str("0.00000002").unwrap(),
                    priority_fee: BigDecimal::from_str("0.000000001").unwrap(),
                    chain_id: String::from("11155111"),
                    nonce: 0,
                }),
                request_params_eth_legacy: None,
            })
            .unwrap();
        assert_eq!(result.fee, BigDecimal::from_str("0.00252").unwrap());
        assert_eq!(result.raw_transaction, "f87783aa36a780843b9aca008504a817c8008301d4c094dac17f958d2ee523a2206206994597c13d831ec7865af3107a4000b844a9059cbb000000000000000000000000422b707abfd76c5366e05416649324e8d95666ef0000000000000000000000000000000000000000000000000000000000000064c0");
        assert_eq!(
            result.hashes[0],
            "e0b61431efb3fae7a5dd77ffbe26caef25a8e4b6185e52d82903f0eccba7f5db"
        );
    }

    #[test]
    fn should_verify_valid_tx() {}
}

#[cfg(test)]
mod legacy_tests {
    use rustmodel::{
        GetAddressRequest, KeyScheme, RequestParamsEthLegacy, SignatureRecidHex,
        VerifyTransactionRequest, WalletCreationConfig, WalletCreationConfigPubkey,
    };

    use crate::blockchains::ethereum_lib::*;

    #[test]
    fn should_get_address_from_pubkey() {
        let result = EthereumLib {}
            .get_address(&GetAddressRequest {
                blockchain: rustmodel::Blockchain::ETHEREUM,
                coin: rustmodel::Coin::ETH,
                wallet_config: WalletCreationConfig {
                    is_segwit: false,
                    pubkeys: vec![WalletCreationConfigPubkey {
                        key_scheme: KeyScheme::ECDSA,
                        pubkey: String::from(
                            "02c090469fbb29bed9419ace8d4acc50abbc39dedd00b0e3fa861f817fae78d873",
                        ),
                    }],
                    is_mainnet: false,
                },
            })
            .unwrap();
        assert_eq!(result.address, "0x2FFa03c290DdB5d3F0907802c1448258621246CB");
    }

    #[test]
    fn should_create_a_transaction() {
        let result = EthereumLib {}
            .create_transaction(&CreateTransactionRequest {
                blockchain: rustmodel::Blockchain::ETHEREUM,
                coin: rustmodel::Coin::ETH,
                signing_request: rustmodel::SigningRequest {
                    id: String::from(""),
                    wallet_id: "wallet1".to_string(),
                    key_scheme: KeyScheme::ECDSA,
                    blockchain: rustmodel::Blockchain::ETHEREUM,
                    coin: rustmodel::Coin::ETH,
                    pubkey: String::from(""),
                    from_address: String::from(""),
                    threshold: 1,
                    request_transaction_type: rustmodel::RequestTransactionType::SEND,
                    status: rustmodel::SigningStatus::SIGNING_COMPLETED,
                    message: None,
                    signing_result: None,
                    send_token_request: None,
                    send_request: Some(rustmodel::SendRequest {
                        to_address: "0x1404DC99E220702365255145EeD9c2a0F7BB7727".to_string(),
                        amount: BigDecimal::from_str("0.01").unwrap(),
                    }),
                    eth_smart_contract_request: None,
                    signers: vec![1, 2],
                    version: 0,
                    fee_level: rustmodel::FeeLevel::HIGH,
                    fee: None,
                    created_at: String::from(""),
                },
                request_params_btc: None,
                request_params_eth_eip1559: None,
                request_params_ada: None,
                request_params_eth_legacy: Some(RequestParamsEthLegacy {
                    gas_fee: BigDecimal::from_str("0.000000021").unwrap(),
                    chain_id: String::from("1"),
                    nonce: 0,
                }),
            })
            .unwrap();
        assert_eq!(result.fee, BigDecimal::from_str("0.000441").unwrap());
        assert_eq!(result.raw_transaction, "eb808504e3b29200825208941404dc99e220702365255145eed9c2a0f7bb7727872386f26fc1000080018080");
        assert_eq!(
            result.hashes[0],
            "1c2e7631b8801663b56a771aeca54a0a219e72e70db9ff4b2616dd19e1d981ed"
        );
    }

    #[test]
    fn should_verify_valid_tx() {
        let result = EthereumLib {}.verify_transaction(&VerifyTransactionRequest {
            blockchain: rustmodel::Blockchain::ETHEREUM,
            coin: rustmodel::Coin::ETH,
            raw_transaction: "eb808504e3b29200825208941404dc99e220702365255145eed9c2a0f7bb7727872386f26fc1000080018080".to_string(),
            signing_request: rustmodel::SigningRequest {
                id: String::from(""),
                wallet_id: "wallet1".to_string(),
                key_scheme: KeyScheme::ECDSA,
                blockchain: rustmodel::Blockchain::ETHEREUM,
                coin: rustmodel::Coin::ETH,
                pubkey: String::from(""),
                from_address: String::from(""),
                threshold: 1,
                send_token_request: None,
                request_transaction_type: rustmodel::RequestTransactionType::SEND,
                status: rustmodel::SigningStatus::SIGNING_COMPLETED,
                message: None,
                signing_result: None,
                send_request: Some(rustmodel::SendRequest {
                    to_address: "0x1404DC99E220702365255145EeD9c2a0F7BB7727".to_string(),
                    amount: BigDecimal::from_str("0.01").unwrap(),
                }),
                eth_smart_contract_request: None,
                version: 0,
                signers: vec![1, 2],
                fee_level: rustmodel::FeeLevel::HIGH,
                fee: Some(BigDecimal::from_str("0.000441").unwrap()),
                created_at: String::from(""),
            },
        }).unwrap();
        assert_eq!(result.failed_reason, None);
    }

    // test real tx
    #[test]
    fn should_sign_a_transaction() {
        let result = EthereumLib {}.sign_transaction(&CreateSignTransactionRequest {
            blockchain: rustmodel::Blockchain::ETHEREUM,
            coin: rustmodel::Coin::ETH,
            pubkey: String::from("03ea000bfee287b950ae7246457b0b77d938170271461fe1d3eb56e258c478c027"),
            raw_transaction: "ec80847735940082520894396397247a4e9b9cc6397d103a3aaeb3c524bcda865af3107a40008083aa36a78080".to_string(),
            hashes: vec![],
            signatures: vec![SignatureRecidHex{ r: "0b5e6ebf9c3e51cde4298974d123753615444be957e368d6ebaf6f89c3fec327".to_string(), s: "6768339fbbd376e7f680cc7ce59e96f9b3ecfde113c75e5d947ccda17bec5b92".to_string(), recid: 1 }],
        }).unwrap();

        assert_eq!(result.signed_transaction,
                   "f86d80847735940082520894396397247a4e9b9cc6397d103a3aaeb3c524bcda865af3107a4000808401546d72a00b5e6ebf9c3e51cde4298974d123753615444be957e368d6ebaf6f89c3fec327a06768339fbbd376e7f680cc7ce59e96f9b3ecfde113c75e5d947ccda17bec5b92");

        assert_eq!(
            result.transaction_hash,
            "42af9da2926511a7c3c327c05e9b2de84882a3c9c566a6a8ef62ed623c9aaf2b"
        );
    }
}
