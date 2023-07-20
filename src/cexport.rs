use rustmodel::{CreateSignTransactionRequest, CreateSignTransactionResult, CreateTransactionRequest, CreateTransactionResult, GetAddressRequest, GetAddressResult, VerifyTransactionRequest, VerifyTransactionResult};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[no_mangle]
pub extern "C" fn get_address(request_str: *const c_char) -> *mut c_char {
    let req = match extract_request(request_str) {
        Ok(value) => value,
        Err(value) => return value,
    };
    fn internal(req: &GetAddressRequest) -> Result<GetAddressResult, anyhow::Error> {
        let blockchain_lib = crate::utils::get_blockchain_service(req.blockchain.clone(), req.coin.clone())?;
        let r = blockchain_lib.get_address(&req)?;
        Ok(r)
    }
    generate_response(internal(&req))
}

#[no_mangle]
pub extern "C" fn verify(request_str: *const c_char) -> *mut c_char {
    let req = match extract_request(request_str) {
        Ok(value) => value,
        Err(value) => return value,
    };
    fn internal(req: &VerifyTransactionRequest) -> Result<VerifyTransactionResult, anyhow::Error> {
        let blockchain_lib = crate::utils::get_blockchain_service(req.blockchain.clone(), req.coin.clone())?;
        let r = blockchain_lib.verify_transaction(&req)?;
        Ok(r)
    }
    generate_response(internal(&req))
}

#[no_mangle]
pub extern "C" fn sign_transaction(request_str: *const c_char) -> *mut c_char {
    let req = match extract_request(request_str) {
        Ok(value) => value,
        Err(value) => return value,
    };

    fn internal(req: &CreateSignTransactionRequest) -> Result<CreateSignTransactionResult, anyhow::Error> {
        let blockchain_lib = crate::utils::get_blockchain_service(req.blockchain.clone(), req.coin.clone())?;
        let r = blockchain_lib.sign_transaction(&req)?;
        Ok(r)
    }
    generate_response(internal(&req))
}

#[no_mangle]
pub extern "C" fn create_transaction(request_str: *const c_char) -> *mut c_char {
    let req = match extract_request(request_str) {
        Ok(value) => value,
        Err(value) => return value,
    };


    fn internal(req: &CreateTransactionRequest) -> Result<CreateTransactionResult, anyhow::Error> {
        let blockchain_lib = crate::utils::get_blockchain_service(req.blockchain.clone(), req.coin.clone())?;
        let r = blockchain_lib.create_transaction(&req)?;
        Ok(r)
    }
    generate_response(internal(&req))
}

fn generate_response<T: Serialize>(result: Result<T, anyhow::Error>) -> *mut c_char {
    match result {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(r) => CString::new(r).unwrap().into_raw(),
            Err(e) => {
                return CString::new(format!("error: {}", e.to_string()))
                    .unwrap()
                    .into_raw();
            }
        },
        Err(e) => CString::new(format!("error: {}", e.to_string()))
            .unwrap()
            .into_raw(),
    }

}

fn extract_request<T: DeserializeOwned>(request_str: *const c_char) -> Result<T, *mut c_char> {
    let request_json = unsafe { CStr::from_ptr(request_str) }
        .to_str()
        .unwrap()
        .to_string();
    let req: T = match serde_json::from_str(request_json.as_str()) {
        Ok(r) => r,
        Err(e) => {
            return Err(CString::new(format!("error: {}", e.to_string()))
                .unwrap()
                .into_raw());
        }
    };
    Ok(req)
}
