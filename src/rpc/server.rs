use crate::{
    rpc::{self, phoenix_server::Phoenix},
    Scalar, SecretKey,
};

pub struct Server {}

#[tonic::async_trait]
impl Phoenix for Server {
    async fn keys(
        &self,
        request: tonic::Request<rpc::SecretKey>,
    ) -> Result<tonic::Response<rpc::KeysResponse>, tonic::Status> {
        let sk = request.into_inner();

        let a: Scalar = sk.a.unwrap_or_default().into();
        let b: Scalar = sk.b.unwrap_or_default().into();

        let sk = SecretKey::new(a, b);
        let vk: rpc::ViewKey = sk.view_key().into();
        let pk: rpc::PublicKey = sk.public_key().into();

        let keys = rpc::KeysResponse {
            vk: Some(vk),
            pk: Some(pk),
        };

        Ok(tonic::Response::new(keys))
    }

    async fn fetch_note(
        &self,
        request: tonic::Request<rpc::Idx>,
    ) -> Result<tonic::Response<rpc::FetchNoteResponse>, tonic::Status> {
        unimplemented!()
    }

    async fn fetch_decrypted_note(
        &self,
        request: tonic::Request<rpc::FetchDecryptedNoteRequest>,
    ) -> Result<tonic::Response<rpc::FetchNoteResponse>, tonic::Status> {
        unimplemented!()
    }

    async fn verify_transaction(
        &self,
        request: tonic::Request<rpc::Transaction>,
    ) -> Result<tonic::Response<rpc::VerifyTransactionResponse>, tonic::Status> {
        unimplemented!()
    }

    async fn verify_transaction_root(
        &self,
        request: tonic::Request<rpc::VerifyTransactionRootRequest>,
    ) -> Result<tonic::Response<rpc::VerifyTransactionRootResponse>, tonic::Status> {
        unimplemented!()
    }

    async fn store_transactions(
        &self,
        request: tonic::Request<rpc::StoreTransactionsRequest>,
    ) -> Result<tonic::Response<rpc::StoreTransactionsResponse>, tonic::Status> {
        unimplemented!()
    }

    async fn get_fee(
        &self,
        request: tonic::Request<rpc::Transaction>,
    ) -> Result<tonic::Response<rpc::GetFeeResponse>, tonic::Status> {
        unimplemented!()
    }

    async fn set_fee_pk(
        &self,
        request: tonic::Request<rpc::SetFeePkRequest>,
    ) -> Result<tonic::Response<rpc::SetFeePkResponse>, tonic::Status> {
        unimplemented!()
    }
}
