use std::hash::Hash;
use std::ops::{Div, Mul};
use std::str::FromStr;

use anyhow::Error;
use anyhow::{anyhow, Context};

use bigdecimal::{BigDecimal, ToPrimitive};

use cardano_serialization_lib::address::{Address, BaseAddress, NetworkInfo, StakeCredential};
use cardano_serialization_lib::crypto::{
    Ed25519Signature, PublicKey, TransactionHash, Vkey, Vkeywitness, Vkeywitnesses,
};
use cardano_serialization_lib::fees::LinearFee;
use cardano_serialization_lib::output_builder::TransactionOutputBuilder;
use cardano_serialization_lib::tx_builder::tx_inputs_builder::TxInputsBuilder;
use cardano_serialization_lib::tx_builder::{TransactionBuilder, TransactionBuilderConfigBuilder};
use cardano_serialization_lib::utils::{hash_transaction, BigNum, Value};
use cardano_serialization_lib::{
    Transaction, TransactionBody, TransactionInput, TransactionWitnessSet,
};
use rustmodel::{
    CreateSignTransactionRequest, CreateSignTransactionResult, CreateTransactionRequest,
    CreateTransactionResult, GetAddressRequest, GetAddressResult, KeyScheme,
    VerifyTransactionRequest, VerifyTransactionResult,
};

use crate::blockchain_lib::BlockchainLib;

pub struct CardanoLib {}

// check current epoch for this parameter. it may change in the future eras
const MAX_VALUE_SIZE: u32 = 5000;
const MAX_TX_SIZE: u32 = 16384;

fn build_transaction(
    transaction_request: &CreateTransactionRequest,
) -> Result<TransactionBuilder, Error> {
    let params = transaction_request
        .request_params_ada
        .clone()
        .expect("ada request params not found");
    let linear_fee = LinearFee::new(
        &BigNum::from(params.fee_coeff as u32),
        &BigNum::from(params.fee_constant as u32),
    );
    let tx_builder_config = TransactionBuilderConfigBuilder::new()
        .fee_algo(&linear_fee)
        .pool_deposit(&BigNum::from(500000000 as u32)) // not used
        .key_deposit(&BigNum::from(2000000 as u32)) // not used
        .max_value_size(MAX_VALUE_SIZE)
        .max_tx_size(MAX_TX_SIZE)
        .coins_per_utxo_byte(&BigNum::from(params.coin_per_utxo_byte as u32))
        .prefer_pure_change(true)
        .build()
        .expect("error building tx builder config");
    let mut tx_builder = TransactionBuilder::new(&tx_builder_config);

    let mut input_builder = TxInputsBuilder::new();
    let utxos = params.unspent_outputs;

    for i in 0..utxos.len() {
        input_builder.add_input(
            &Address::from_bech32(transaction_request.signing_request.from_address.as_str())?,
            &TransactionInput::new(
                &TransactionHash::from_hex(utxos[i].transaction_hash.as_str())?,
                utxos[i].index as u32,
            ),
            &Value::new(&convert_to_unit(&utxos[i].amount)),
        );
    }
    tx_builder.set_inputs(&input_builder);
    tx_builder
        .add_output(
            &TransactionOutputBuilder::new()
                .with_address(&Address::from_bech32(
                    transaction_request
                        .signing_request
                        .send_request
                        .clone()
                        .expect("send request not found")
                        .to_address
                        .as_str(),
                )?)
                .next()
                .expect("error building tx output")
                .with_coin(&convert_to_unit(
                    &transaction_request
                        .signing_request
                        .send_request
                        .clone()
                        .expect("send request not found")
                        .amount,
                ))
                .build()
                .expect("error building tx output"),
        )
        .expect("error adding tx output");
    tx_builder.set_ttl_bignum(&BigNum::from(params.ttl as u32));

    tx_builder.add_change_if_needed(&Address::from_bech32(
        transaction_request.signing_request.from_address.as_str(),
    )?)?;
    Ok(tx_builder)
}

fn convert_to_unit(amount: &BigDecimal) -> BigNum {
    return BigNum::from(
        amount
            .mul(&BigDecimal::from(1_000_000))
            .to_u64()
            .expect("error converting amount to u64"),
    );
}

fn convert_from_unit(amount: &str) -> Result<BigDecimal, Error> {
    return Ok(BigDecimal::from_str(amount)?.div(&BigDecimal::from(1_000_000)));
}

impl BlockchainLib for CardanoLib {
    fn get_address(&self, address_request: &GetAddressRequest) -> Result<GetAddressResult, Error> {
        let pubkey = address_request
            .wallet_config
            .pubkeys
            .iter()
            .find(|x| x.key_scheme == KeyScheme::EDDSA)
            .context("ECDSA pubkey not found")?
            .pubkey
            .clone();
        let cardano_pubkey = PublicKey::from_bytes(&hex::decode(pubkey)?)?
            .hash();
        let address = BaseAddress::new(
            if address_request.wallet_config.is_mainnet {
                NetworkInfo::mainnet().network_id()
            } else {
                NetworkInfo::testnet_preprod().network_id()
            },
            &StakeCredential::from_keyhash(&cardano_pubkey),
            &StakeCredential::from_keyhash(&cardano_pubkey),
        )
        .to_address()
        .to_bech32(None)?;
        return Ok(GetAddressResult { address });
    }

    fn create_transaction(
        &self,
        transaction_request: &CreateTransactionRequest,
    ) -> Result<CreateTransactionResult, Error> {
        let tx_builder = build_transaction(&transaction_request)?;
        let body = tx_builder.build().expect("error building tx");
        Ok(CreateTransactionResult {
            raw_transaction: body.clone().to_hex(),
            fee: convert_from_unit(
                tx_builder
                    .get_fee_if_set()
                    .expect("fee not set")
                    .to_str()
                    .as_str(),
            )
            .expect("error converting fee to bigdecimal"),
            hashes: vec![hash_transaction(&body).to_hex()],
        })
    }

    fn sign_transaction(
        &self,
        transaction_request: &CreateSignTransactionRequest,
    ) -> Result<CreateSignTransactionResult, Error> {
        let mut witness = TransactionWitnessSet::new();
        let mut vkey_witnesses = Vkeywitnesses::new();
        let vkey_witness = Vkeywitness::new(
            &Vkey::new(&PublicKey::from_hex(transaction_request.pubkey.as_str())?),
            &Ed25519Signature::from_hex(
                format!(
                    "{}{}",
                    transaction_request.signatures[0].r.as_str(),
                    transaction_request.signatures[0].s.as_str()
                )
                .as_str(),
            )?,
        );
        vkey_witnesses.add(&vkey_witness);
        witness.set_vkeys(&vkey_witnesses);
        let tx_body = TransactionBody::from_hex(transaction_request.raw_transaction.as_str())?;
        let signed_transaction = Transaction::new(&tx_body, &witness, None);
        Ok(CreateSignTransactionResult {
            signed_transaction: signed_transaction.to_hex(),
            transaction_hash: hash_transaction(&tx_body).to_hex(),
        })
    }

    fn verify_transaction(
        &self,
        transaction_request: &VerifyTransactionRequest,
    ) -> Result<VerifyTransactionResult, Error> {
        let tx_body = TransactionBody::from_hex(transaction_request.raw_transaction.as_str())?;
        // send amount
        // receive address
        // fee
        // fee must less than send amount
        let encoded_fee = convert_from_unit(tx_body.fee().to_str().as_str())?;
        let encoded_send_amount = if tx_body.outputs().len() == 1 {
            convert_from_unit(tx_body.outputs().get(0).amount().coin().to_str().as_str())?
        } else if tx_body.outputs().len() == 2 {
            convert_from_unit(tx_body.outputs().get(0).amount().coin().to_str().as_str())?
        } else {
            return Err(anyhow!("invalid number of outputs"));
        };
        let encoded_send_address = if tx_body.outputs().len() == 1 {
            tx_body.outputs().get(0).address().to_bech32(None)?
        } else if tx_body.outputs().len() == 2 {
            tx_body.outputs().get(0).address().to_bech32(None)?
        } else {
            return Err(anyhow!("invalid number of outputs"));
        };

        if encoded_send_amount < encoded_fee {
            return Err(anyhow!("fee must be less than send amount"));
        }
        if encoded_fee
            != transaction_request
                .signing_request
                .clone()
                .fee
                .expect("fee not set")
        {
            return Err(anyhow!("fee does not match"));
        }
        if encoded_send_address
            != transaction_request
                .signing_request
                .clone()
                .send_request
                .expect("send request not set")
                .to_address
        {
            return Err(anyhow!("send address does not match"));
        }
        if encoded_send_amount
            != transaction_request
                .signing_request
                .send_request
                .clone()
                .expect("send request not set")
                .amount
        {
            return Err(anyhow!("send amount does not match"));
        }

        return Ok(VerifyTransactionResult {
            failed_reason: None,
        });
    }
}

#[cfg(test)]
mod cardano_tests {
    use bigdecimal::FromPrimitive;
    use rustmodel::{
        GetAddressRequest, KeyScheme, RequestParamsAda, SendRequest, SignatureRecidHex,
        SigningRequest, UnspentOutput, WalletCreationConfig, WalletCreationConfigPubkey,
    };
    use std::str::FromStr;

    use crate::blockchains::cardano_lib::*;

    use crate::test_wallets::{eddsa_pubkey_wallet1, eddsa_sign_wallet1};

    #[test]
    fn should_convert_pubkey_to_address() {
        let result = CardanoLib {}
            .get_address(&GetAddressRequest {
                blockchain: rustmodel::Blockchain::CARDANO,
                coin: rustmodel::Coin::ADA,
                wallet_config: WalletCreationConfig {
                    is_segwit: false,
                    pubkeys: vec![WalletCreationConfigPubkey {
                        key_scheme: KeyScheme::EDDSA,
                        pubkey: eddsa_pubkey_wallet1(),
                    }],
                    is_mainnet: false,
                },
            }).unwrap();
        assert_eq!(result.address, "addr_test1qzk3de2c2p0jyymhv93u382kcg0xf4ftlldy67zszepmkq4dzmj4s5zlygfhwctrezw4dss7vn2jhl76f4u9q9jrhvpqd6l3hl");
    }

    #[test]
    fn should_sign_transaction() {
        let result = CardanoLib {}
            .create_transaction(&CreateTransactionRequest {
                blockchain: rustmodel::Blockchain::CARDANO,
                coin: rustmodel::Coin::ADA,
                signing_request: SigningRequest {
                    id: String::from(""),
                    wallet_id: "wallet1".to_string(),
                    key_scheme: KeyScheme::EDDSA,
                    blockchain: rustmodel::Blockchain::CARDANO,
                    coin: rustmodel::Coin::ADA,
                    pubkey: eddsa_pubkey_wallet1(),
                    from_address: String::from("addr_test1qzk3de2c2p0jyymhv93u382kcg0xf4ftlldy67zszepmkq4dzmj4s5zlygfhwctrezw4dss7vn2jhl76f4u9q9jrhvpqd6l3hl"),
                    threshold: 1,
                    request_transaction_type: rustmodel::RequestTransactionType::SEND,
                    status: rustmodel::SigningStatus::SIGNING_COMPLETED,
                    message: None,
                    signing_result: None,
                    send_request: Some(SendRequest {
                        to_address: String::from("addr_test1qp88xsv3x95d5c40qt5dmr5ndwnnvd49t8c0pq8gvgtvyz6wwdqezvtgmf327qhgmk8fx6a8xcm22k0s7zqwscskcg9su7t69k"),
                        amount: BigDecimal::from_str("1").unwrap(),
                    }),
                    send_token_request: None,
                    eth_smart_contract_request: None,
                    signers: vec![1, 2],
                    version: 0,
                    fee_level: rustmodel::FeeLevel::HIGH,
                    fee: None,
                    created_at: String::from(""),
                },
                request_params_eth_eip1559: None,
                request_params_eth_legacy: None,
                request_params_btc: None,
                request_params_ada: Some(RequestParamsAda{
                    unspent_outputs: vec![UnspentOutput {
                        transaction_hash: String::from("8d586914a6ba9f17980164a7b64999721474b9997e7b268837dab584349b34a4"),
                        amount: BigDecimal::from_str("10000").unwrap(),
                        index: 0,
                        script: String::from(""),
                    }],
                    ttl: 31337477 + 167040,
                    fee_coeff: 44,
                    fee_constant: 155381,
                    coin_per_utxo_byte: 4310,
                }),
            }).unwrap();

        assert_eq!(result.raw_transaction, "a400818258208d586914a6ba9f17980164a7b64999721474b9997e7b268837dab584349b34a4000182825839004e7341913168da62af02e8dd8e936ba73636a559f0f080e86216c20b4e7341913168da62af02e8dd8e936ba73636a559f0f080e86216c20b1a000f424082583900ad16e558505f2213776163c89d56c21e64d52bffda4d78501643bb02ad16e558505f2213776163c89d56c21e64d52bffda4d78501643bb021b0000000253fa0f93021a0002922d031a01e0b885");
        assert_eq!(result.fee, BigDecimal::from_f32(0.168493).unwrap());
        assert_eq!(
            result.hashes,
            vec!["de0b23b4000b3df2eee22fa73bd74f486804ca52012a1c4e6bad8fee507bf08c"]
        );

        let signature = eddsa_sign_wallet1(result.hashes[0].as_str());
        let result = CardanoLib {}
            .sign_transaction(&CreateSignTransactionRequest {
                blockchain: rustmodel::Blockchain::CARDANO,
                coin: rustmodel::Coin::ADA,
                pubkey: eddsa_pubkey_wallet1(),
                raw_transaction: result.raw_transaction.to_string(),
                hashes: result.hashes,
                signatures: vec![SignatureRecidHex {
                    r: signature.signature.clone().unwrap().r,
                    s: signature.signature.unwrap().s,
                    recid: 0,
                }],
            })
            .unwrap();

        // https://preprod.cardanoscan.io/transaction/de0b23b4000b3df2eee22fa73bd74f486804ca52012a1c4e6bad8fee507bf08c
        assert_eq!(result.signed_transaction, "84a400818258208d586914a6ba9f17980164a7b64999721474b9997e7b268837dab584349b34a4000182825839004e7341913168da62af02e8dd8e936ba73636a559f0f080e86216c20b4e7341913168da62af02e8dd8e936ba73636a559f0f080e86216c20b1a000f424082583900ad16e558505f2213776163c89d56c21e64d52bffda4d78501643bb02ad16e558505f2213776163c89d56c21e64d52bffda4d78501643bb021b0000000253fa0f93021a0002922d031a01e0b885a1008182582052d16db05136ddc0a64741a784a2d316b52f0ca3ba32ebcd1302d4c76ec4f4eb5840c778b1d931d96ce8709876d4c06708bfe0b7dd567ad24105118bad17352e5a830efa59f8230796f7cd05fe2d47ac3c9d33c695520aa25363b47d531c5a6d1a03f5f6");
        assert_eq!(
            result.transaction_hash,
            "de0b23b4000b3df2eee22fa73bd74f486804ca52012a1c4e6bad8fee507bf08c"
        );
    }

    #[test]
    fn should_verify_valid_tx() {
        let result = CardanoLib {}.verify_transaction(&VerifyTransactionRequest {
            blockchain: rustmodel::Blockchain::CARDANO,
            coin: rustmodel::Coin::ADA,
            raw_transaction: "a400818258208d586914a6ba9f17980164a7b64999721474b9997e7b268837dab584349b34a4000182825839004e7341913168da62af02e8dd8e936ba73636a559f0f080e86216c20b4e7341913168da62af02e8dd8e936ba73636a559f0f080e86216c20b1a000f424082583900ad16e558505f2213776163c89d56c21e64d52bffda4d78501643bb02ad16e558505f2213776163c89d56c21e64d52bffda4d78501643bb021b0000000253fa0f93021a0002922d031a01e0b885".to_string(),
            signing_request: rustmodel::SigningRequest {
                id: String::from(""),
                wallet_id: "wallet1".to_string(),
                key_scheme: KeyScheme::EDDSA,
                blockchain: rustmodel::Blockchain::CARDANO,
                coin: rustmodel::Coin::ADA,
                pubkey: eddsa_pubkey_wallet1(),
                from_address: String::from("addr_test1qzk3de2c2p0jyymhv93u382kcg0xf4ftlldy67zszepmkq4dzmj4s5zlygfhwctrezw4dss7vn2jhl76f4u9q9jrhvpqd6l3hl"),
                threshold: 1,
                request_transaction_type: rustmodel::RequestTransactionType::SEND,
                status: rustmodel::SigningStatus::SIGNING_IN_PROGRESS,
                message: None,
                signing_result: None,
                send_token_request: None,
                eth_smart_contract_request: None,
                send_request: Some(SendRequest {
                    to_address: String::from("addr_test1qp88xsv3x95d5c40qt5dmr5ndwnnvd49t8c0pq8gvgtvyz6wwdqezvtgmf327qhgmk8fx6a8xcm22k0s7zqwscskcg9su7t69k"),
                    amount: BigDecimal::from_str("1").unwrap(),
                }),
                version: 0,
                signers: vec![1, 2],
                fee_level: rustmodel::FeeLevel::HIGH,
                fee: Some(BigDecimal::from_f32(0.168493).unwrap()),
                created_at: String::from(""),
            },
        }).unwrap();
        assert_eq!(result.failed_reason, None);
    }
}
