use std::num::ParseIntError;

use anyhow::anyhow;
use base64::decode;
use hex::encode;
use rustmodel::{Blockchain, Coin};

use crate::{blockchain_lib::BlockchainLib, blockchains};

// convert hex to bytes
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, ParseIntError> {
    if s.starts_with("0x") {
        (2..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    } else {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }
}

// convert bytes to hex string
pub fn bytes_to_hex(bytes: Vec<u8>) -> String {
    let mut hex = String::new();
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    return hex;
}

pub fn base64_to_hex(base64_string: &str) -> String {
    // Decode the Base64 string to bytes
    let bytes = decode(base64_string).unwrap();

    // Convert the bytes to a hexadecimal string
    let hex_string = encode(&bytes);

    // Return the hexadecimal string
    hex_string
}

pub fn get_blockchain_service(
    blockchain: Blockchain,
    coin: Coin,
) -> Result<Box<dyn BlockchainLib>, anyhow::Error> {
    match (blockchain.clone(), coin.clone()) {
        (Blockchain::BITCOIN, Coin::BTC) => Ok(Box::new(blockchains::bitcoin_lib::BitcoinLib {})),
        (Blockchain::ETHEREUM, _) | (Blockchain::POLYGON, _) => Ok(Box::new(blockchains::ethereum_lib::EthereumLib {})),
        (Blockchain::CARDANO, Coin::ADA) => Ok(Box::new(blockchains::cardano_lib::CardanoLib {})),
        _ => Err(anyhow!(format!(
            "blockchain {:?} coin {:?} not supported",
            blockchain, coin
        ))),
    }
}
