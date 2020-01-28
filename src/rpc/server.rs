use crate::{
    rpc::{self, phoenix_server::Phoenix},
    Db, Error, Idx, PublicKey, Scalar, SecretKey, Transaction, ViewKey,
};

use std::convert::TryInto;

fn error_to_tonic(e: Error) -> tonic::Status {
    e.into()
}

pub struct Server {
    db: Db,
}

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

    async fn nullifier(
        &self,
        request: tonic::Request<rpc::NullifierRequest>,
    ) -> Result<tonic::Response<rpc::NullifierResponse>, tonic::Status> {
        unimplemented!()
    }

    async fn nullifier_status(
        &self,
        request: tonic::Request<super::NullifierStatusRequest>,
    ) -> Result<tonic::Response<super::NullifierStatusResponse>, tonic::Status> {
        unimplemented!()
    }

    async fn fetch_note(
        &self,
        request: tonic::Request<rpc::Idx>,
    ) -> Result<tonic::Response<rpc::Note>, tonic::Status> {
        let idx: Idx = request.into_inner().into();
        let note = self
            .db
            .fetch_box_note(&idx)
            .and_then(|note| note.rpc_note(None))
            .map_err(error_to_tonic)?;

        Ok(tonic::Response::new(note))
    }

    async fn fetch_decrypted_note(
        &self,
        request: tonic::Request<rpc::FetchDecryptedNoteRequest>,
    ) -> Result<tonic::Response<rpc::Note>, tonic::Status> {
        let request = request.into_inner();
        let idx: Idx = request.pos.unwrap_or_default().into();
        let vk: ViewKey = request
            .vk
            .unwrap_or_default()
            .try_into()
            .map_err(error_to_tonic)?;

        let note = self
            .db
            .fetch_box_note(&idx)
            .and_then(|note| note.rpc_note(Some(&vk)))
            .map_err(error_to_tonic)?;

        Ok(tonic::Response::new(note))
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
    ) -> Result<tonic::Response<rpc::Scalar>, tonic::Status> {
        unimplemented!()
    }

    async fn set_fee_pk(
        &self,
        request: tonic::Request<rpc::SetFeePkRequest>,
    ) -> Result<tonic::Response<rpc::Transaction>, tonic::Status> {
        let request = request.into_inner();

        let transaction = request.transaction.unwrap_or_default();
        let mut transaction =
            Transaction::try_from_rpc_transaction(&self.db, transaction).map_err(error_to_tonic)?;

        let pk: PublicKey = request
            .pk
            .unwrap_or_default()
            .try_into()
            .map_err(error_to_tonic)?;

        transaction.set_fee_pk(&pk);

        Ok(tonic::Response::new(transaction.into()))
    }
}
