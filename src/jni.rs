use robusta_jni::bridge;

#[bridge]
pub mod jni {

    use rustmodel::{
        CreateSignTransactionRequest, CreateTransactionRequest, GetAddressRequest,
        VerifyTransactionRequest,
    };

    #[package(com.walletbackend.blockchainlib)]
    pub struct JniBlockchainLib();

    impl JniBlockchainLib {
        pub extern "jni" fn jniGetAddress(
            request_json: String,
        ) -> jni::errors::Result<String> {
            Ok(Self::internalGetAddress(request_json).map_err(|e| robusta_jni::jni::errors::Error::from(e.to_string()))?)
        }

        fn internalGetAddress(request_json: String) -> Result<String, anyhow::Error> {
            let req: GetAddressRequest = serde_json::from_str(request_json.as_str())?;
            let blockchain_lib =
                crate::utils::get_blockchain_service(req.blockchain.clone(), req.coin.clone())?;
            let result = blockchain_lib
                .get_address(&req)?;
            Ok(serde_json::to_string(&result)?)
        }

        pub extern "jni" fn jniCreateTransaction(
            request_json: String,
        ) -> jni::errors::Result<String> {
            Ok(Self::internalCreateTransaction(request_json).map_err(|e| robusta_jni::jni::errors::Error::from(e.to_string()))?)
        }

        fn internalCreateTransaction(request_json: String) -> Result<String, anyhow::Error> {
            let req: CreateTransactionRequest = serde_json::from_str(request_json.as_str())?;
            let blockchain_lib =
                crate::utils::get_blockchain_service(req.blockchain.clone(), req.coin.clone())?;
            let result = blockchain_lib
                .create_transaction(&req)?;
            Ok(serde_json::to_string(&result)?)
        }

        pub extern "jni" fn jniSignTransaction(
            request_json: String,
        ) -> jni::errors::Result<String> {
            Ok(Self::internalSignTransaction(request_json).map_err(|e| robusta_jni::jni::errors::Error::from(e.to_string()))?)
        }

        fn internalSignTransaction(request_json: String) -> Result<String, anyhow::Error> {
            let req: CreateSignTransactionRequest = serde_json::from_str(request_json.as_str())?;
            let blockchain_lib =
                crate::utils::get_blockchain_service(req.blockchain.clone(), req.coin.clone())?;
            let result = blockchain_lib
                .sign_transaction(&req)?;
            Ok(serde_json::to_string(&result)?)
        }

        pub extern "jni" fn jniVerify(
            request_json: String,
        ) -> jni::errors::Result<String> {
            Ok(Self::internalVerify(request_json).map_err(|e| robusta_jni::jni::errors::Error::from(e.to_string()))?)
        }

        fn internalVerify(request_json: String) -> Result<String, anyhow::Error> {
            let req: VerifyTransactionRequest = serde_json::from_str(request_json.as_str())?;
            let blockchain_lib =
                crate::utils::get_blockchain_service(req.blockchain.clone(), req.coin.clone())?;
            let result = blockchain_lib
                .verify_transaction(&req)?;
            Ok(serde_json::to_string(&result)?)
        }
    }
}
