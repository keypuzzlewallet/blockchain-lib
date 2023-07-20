mod blockchain_lib;
mod blockchains;

mod utils;

mod cexport;

// we only compile jni for server backend
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
#[cfg(not(test))]
pub mod jni;

#[cfg(test)]
mod test_wallets;
