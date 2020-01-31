use crate::{
    rpc::{self, phoenix_server::Phoenix},
    Db, Error, Idx, Note, NoteGenerator, NoteType, Nullifier, ObfuscatedNote, PublicKey, Scalar,
    SecretKey, Transaction, TransparentNote, ViewKey,
};

use std::convert::TryInto;

use tracing::trace;

fn error_to_tonic(e: Error) -> tonic::Status {
    e.into()
}

pub struct Server {
    db: Db,
}

impl Server {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl Phoenix for Server {
    async fn echo(
        &self,
        request: tonic::Request<rpc::EchoMethod>,
    ) -> Result<tonic::Response<rpc::EchoMethod>, tonic::Status> {
        trace!("Icoming echo request");
        Ok(tonic::Response::new(request.into_inner()))
    }

    async fn generate_secret_key(
        &self,
        request: tonic::Request<rpc::GenerateSecretKeyRequest>,
    ) -> Result<tonic::Response<rpc::SecretKey>, tonic::Status> {
        let sk = SecretKey::from(request.into_inner().b);
        let sk = rpc::SecretKey::from(sk);
        Ok(tonic::Response::new(sk))
    }

    async fn keys(
        &self,
        request: tonic::Request<rpc::SecretKey>,
    ) -> Result<tonic::Response<rpc::KeysResponse>, tonic::Status> {
        trace!("Icoming keys request");
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
        trace!("Icoming nullifier request");
        let request = request.into_inner();

        let sk: SecretKey = request
            .sk
            .ok_or(Error::InvalidParameters)
            .map_err(error_to_tonic)?
            .into();
        let note: Box<dyn Note> = request
            .note
            .ok_or(Error::InvalidParameters)
            .and_then(|note| note.try_into())
            .map_err(error_to_tonic)?;

        let nullifier = note.generate_nullifier(&sk);
        let response = rpc::NullifierResponse {
            nullifier: Some(nullifier.into()),
        };

        Ok(tonic::Response::new(response))
    }

    async fn nullifier_status(
        &self,
        request: tonic::Request<rpc::NullifierStatusRequest>,
    ) -> Result<tonic::Response<rpc::NullifierStatusResponse>, tonic::Status> {
        trace!("Icoming nullifier status request");
        let request = request.into_inner();

        let nullifier: Nullifier = request
            .nullifier
            .ok_or(Error::InvalidParameters)
            .and_then(|n| n.try_into())
            .map_err(error_to_tonic)?;

        let unspent = self
            .db
            .fetch_nullifier(&nullifier)
            .map(|r| r.is_none())
            .map_err(error_to_tonic)?;

        let response = rpc::NullifierStatusResponse { unspent };
        Ok(tonic::Response::new(response))
    }

    async fn fetch_note(
        &self,
        request: tonic::Request<rpc::Idx>,
    ) -> Result<tonic::Response<rpc::Note>, tonic::Status> {
        trace!("Icoming fetch note request");
        let idx: Idx = request.into_inner();
        let note = self
            .db
            .fetch_box_note(&idx)
            .map(|note| note.into())
            .map_err(error_to_tonic)?;

        Ok(tonic::Response::new(note))
    }

    async fn decrypt_note(
        &self,
        request: tonic::Request<rpc::DecryptNoteRequest>,
    ) -> Result<tonic::Response<rpc::DecryptedNote>, tonic::Status> {
        trace!("Icoming decrypt note request");
        let request = request.into_inner();

        let note: Box<dyn Note> = request
            .note
            .ok_or(Error::InvalidParameters)
            .and_then(|note| note.try_into())
            .map_err(error_to_tonic)?;

        let vk: ViewKey = request
            .vk
            .ok_or(Error::InvalidParameters)
            .and_then(|vk| vk.try_into())
            .map_err(error_to_tonic)?;

        let note = note.rpc_decrypted_note(&vk);
        Ok(tonic::Response::new(note))
    }

    async fn owned_notes(
        &self,
        request: tonic::Request<rpc::OwnedNotesRequest>,
    ) -> Result<tonic::Response<rpc::OwnedNotesResponse>, tonic::Status> {
        trace!("Icoming owned notes request");
        let request = request.into_inner();

        let vk: ViewKey = request
            .vk
            .ok_or(Error::InvalidParameters)
            .and_then(|vk| vk.try_into())
            .map_err(error_to_tonic)?;

        let notes: Vec<rpc::DecryptedNote> = request
            .notes
            .into_iter()
            .try_fold(vec![], |mut notes, note| {
                let note: Box<dyn Note> = note.try_into()?;

                if note.is_owned_by(&vk) {
                    notes.push(note.rpc_decrypted_note(&vk));
                }

                Ok(notes)
            })
            .map_err(error_to_tonic)?;

        Ok(tonic::Response::new(rpc::OwnedNotesResponse { notes }))
    }

    async fn full_scan_owned_notes(
        &self,
        request: tonic::Request<rpc::ViewKey>,
    ) -> Result<tonic::Response<rpc::OwnedNotesResponse>, tonic::Status> {
        trace!("Icoming full scan owned notes request");
        let vk: ViewKey = request.into_inner().try_into().map_err(error_to_tonic)?;

        let notes: Vec<rpc::DecryptedNote> = self
            .db
            .filter_all_notes(|note| {
                if note.is_owned_by(&vk) {
                    Some(note.box_clone())
                } else {
                    None
                }
            })
            .map_err(error_to_tonic)?
            .into_iter()
            .map(|n| n.rpc_decrypted_note(&vk))
            .collect();

        Ok(tonic::Response::new(rpc::OwnedNotesResponse { notes }))
    }

    async fn new_transaction_input(
        &self,
        request: tonic::Request<rpc::NewTransactionInputRequest>,
    ) -> Result<tonic::Response<rpc::TransactionInput>, tonic::Status> {
        trace!("Icoming new transaction input request");
        let request = request.into_inner();

        let idx: Idx = request
            .pos
            .ok_or(Error::InvalidParameters)
            .map_err(error_to_tonic)?
            .into();

        let sk: SecretKey = request
            .sk
            .ok_or(Error::InvalidParameters)
            .map_err(error_to_tonic)?
            .into();

        let note = self.db.fetch_box_note(&idx).map_err(error_to_tonic)?;
        let txi = match note.note() {
            NoteType::Transparent => {
                Db::note_box_into::<TransparentNote>(note).to_transaction_input(sk)
            }
            NoteType::Obfuscated => {
                Db::note_box_into::<ObfuscatedNote>(note).to_transaction_input(sk)
            }
        };

        let txi: rpc::TransactionInput = txi.into();
        Ok(tonic::Response::new(txi))
    }

    async fn new_transaction_output(
        &self,
        request: tonic::Request<rpc::NewTransactionOutputRequest>,
    ) -> Result<tonic::Response<rpc::TransactionOutput>, tonic::Status> {
        trace!("Icoming new transaction output request");
        let request = request.into_inner();

        let pk: PublicKey = request
            .pk
            .ok_or(Error::InvalidParameters)
            .and_then(|pk| pk.try_into())
            .map_err(error_to_tonic)?;

        let note_type: rpc::NoteType = request.note_type.try_into().map_err(error_to_tonic)?;

        let txo = match note_type.into() {
            NoteType::Transparent => {
                let (note, blinding_factor) = TransparentNote::output(&pk, request.value);
                note.to_transaction_output(request.value, blinding_factor, pk)
            }
            NoteType::Obfuscated => {
                let (note, blinding_factor) = ObfuscatedNote::output(&pk, request.value);
                note.to_transaction_output(request.value, blinding_factor, pk)
            }
        };

        let txo: rpc::TransactionOutput = txo.into();
        Ok(tonic::Response::new(txo))
    }

    async fn new_transaction(
        &self,
        request: tonic::Request<rpc::NewTransactionRequest>,
    ) -> Result<tonic::Response<rpc::Transaction>, tonic::Status> {
        trace!("Icoming new transaction request");
        let request = request.into_inner();

        let transaction: rpc::Transaction =
            Transaction::try_from_rpc_io(&self.db, request.fee, request.inputs, request.outputs)
                .map_err(error_to_tonic)?
                .into();

        Ok(tonic::Response::new(transaction))
    }

    async fn verify_transaction(
        &self,
        request: tonic::Request<rpc::Transaction>,
    ) -> Result<tonic::Response<rpc::VerifyTransactionResponse>, tonic::Status> {
        trace!("Icoming verify transaction request");
        Transaction::try_from_rpc_transaction(&self.db, request.into_inner())
            .and_then(|tx| tx.verify())
            .map(|_| tonic::Response::new(rpc::VerifyTransactionResponse {}))
            .map_err(error_to_tonic)
    }

    async fn verify_transaction_root(
        &self,
        _request: tonic::Request<rpc::VerifyTransactionRootRequest>,
    ) -> Result<tonic::Response<rpc::VerifyTransactionRootResponse>, tonic::Status> {
        trace!("Icoming verify transaction root request");
        unimplemented!()
    }

    async fn store_transactions(
        &self,
        request: tonic::Request<rpc::StoreTransactionsRequest>,
    ) -> Result<tonic::Response<rpc::StoreTransactionsResponse>, tonic::Status> {
        trace!("Icoming store transactions request");
        let request = request.into_inner();
        let mut transactions = vec![];

        for tx in request.transactions {
            transactions
                .push(Transaction::try_from_rpc_transaction(&self.db, tx).map_err(error_to_tonic)?);
        }

        for tx in &transactions {
            tx.verify().map_err(error_to_tonic)?;
        }

        let notes: Vec<rpc::Note> = self
            .db
            .store_bulk_transactions(transactions.as_slice())
            .map_err(error_to_tonic)?
            .iter()
            .try_fold(vec![], |mut v, idx| {
                v.push(self.db.fetch_box_note(idx)?.into());
                Ok(v)
            })
            .map_err(error_to_tonic)?;

        let root: rpc::Scalar = self.db.root().into();
        let root = Some(root);

        let response = rpc::StoreTransactionsResponse { notes, root };
        Ok(tonic::Response::new(response))
    }

    async fn set_fee_pk(
        &self,
        request: tonic::Request<rpc::SetFeePkRequest>,
    ) -> Result<tonic::Response<rpc::Transaction>, tonic::Status> {
        trace!("Icoming set fee pk request");
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
