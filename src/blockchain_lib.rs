use anyhow::Error;
use rustmodel::{
    CreateSignTransactionRequest, CreateSignTransactionResult, CreateTransactionRequest,
    CreateTransactionResult, GetAddressRequest, GetAddressResult, VerifyTransactionRequest,
    VerifyTransactionResult,
};

pub trait BlockchainLib {
    fn get_address(&self, address_request: &GetAddressRequest) -> Result<GetAddressResult, Error>;
    // create transaction and fee amount
    fn create_transaction(
        &self,
        transaction_request: &CreateTransactionRequest,
    ) -> Result<CreateTransactionResult, Error>;
    // create signed transaction that is ready to broadcast to the network
    fn sign_transaction(
        &self,
        transaction_request: &CreateSignTransactionRequest,
    ) -> Result<CreateSignTransactionResult, Error>;
    // verify (1) send amount, (2) receive address, (3) fee and (4) fee must less than send amount
    fn verify_transaction(
        &self,
        transaction_request: &VerifyTransactionRequest,
    ) -> Result<VerifyTransactionResult, Error>;
}
