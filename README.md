## Core Blockchain

This is a core blockchain library that implement several offline tasks for each blockchain we integrate in the wallet:

* Generate wallet address
* Create raw transaction data
* Sign transaction hash
* Verify signing transaction hash against information that is showing in the UI. This is to ensure that user is signing for what they are seeing on the UI. We would like to verify following details:
  * Destination address
  * Sending amount
  * Fee amount
  * Signing data/memo/message

It is written in rust and compiled to most of platforms e.g. java/C++/Go/Rust backend server, android and ios client.

## Build

### Prepare

* Update `rustmodel` in Cargo.tom to the path of `rustmodel` project. You can find rustmodel repository in this group.
* Make sure you installed rust at least version 1.70
* Run `make init` to install required tools

### Build for Linux or MAC (Java backend)

* Run command

```
cargo build --release
```

* If everything is ok, you will see the library at `target/release/libblockchain_lib.so`
* You can use it to integrate with java backend server

### Build for Linux or MAC (Other backends using static lib)

* This will generate static library and header file, so you can use on any other backend implementation.
* In this example, I will generate static library for a backend running on MAC M1 (arm64)
* First you need to remove jni dependency in Cargo.toml and remove jni related code in lib.rs
* Run command

```
make target/aarch64-apple-darwin/release/libtssv3.dylib
```

* If everything is ok, you will see the library at `target/aarch64-apple-darwin/release/libblockchain_lib.a`
* Run following command to generate c header file. The output is at `target/bindings.h`

```
make bindings
```

### Build for Android

* Make sure you have android NDK 25 or newer installed
* run `make init` to install required tools
* run build `make android`
* If everything is ok, you will see the library at `target/*-android/release/libblockchain_lib.so`
* Following Android CPU architecture are supported:
  * armv7-linux-androideabi
  * aarch64-linux-android
  * i686-linux-android
  * x86_64-linux-android

### Build for iOS

* You can only build this on MAC
* Make sure you have xcode and xcode-select --install installed
* run `make init` to install required tools
* run build `make ios`
* If everything is ok, you will see the library at `target/*-apple-ios/release/libblockchain_lib.a`
  * x86_64 is for simulator
  * aarch64 is for real device
* run build `make bindings`. This will generate header file at `target/ios/headers/blockchain_lib.h` which you will need to integrate with your iOS project

## Add new blockchain

* Add blockchain dependency in `Cargo.toml`
* Add a new rust file in `src/blockchains` folder. For example: `src/blockchains/ripple_lib.rs`
* Implement all required functions and unit tests. You can see example in `src/blockchain/bitcoin_lib.rs`
* Update `get_blockchain_service` function in `src/utils.rs` to return your new blockchain service
