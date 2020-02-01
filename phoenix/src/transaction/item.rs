use crate::{
    rpc, Db, Error, Idx, Note, NoteGenerator, NoteType, NoteUtxoType, Nullifier, ObfuscatedNote,
    PublicKey, Scalar, SecretKey, TransparentNote,
};

use std::convert::{TryFrom, TryInto};

#[derive(Debug)]
pub struct TransactionItem {
    note: Box<dyn Note>,
    nullifier: Nullifier,
    value: u64,
    blinding_factor: Scalar,
    sk: Option<SecretKey>,
    pk: PublicKey,
}

impl PartialEq for TransactionItem {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
            && self.nullifier == other.nullifier
            && self.blinding_factor == other.blinding_factor
            && self.sk == other.sk
            && self.pk == other.pk
            && self.note.hash() == other.note.hash()
    }
}
impl Eq for TransactionItem {}

impl Clone for TransactionItem {
    fn clone(&self) -> Self {
        TransactionItem {
            note: self.note.box_clone(),
            nullifier: self.nullifier,
            value: self.value,
            blinding_factor: self.blinding_factor,
            sk: None,
            pk: self.pk,
        }
    }
}

impl Default for TransactionItem {
    fn default() -> Self {
        let note = TransparentNote::default();
        let nullifier = Nullifier::default();
        let value = 0;
        let blinding_factor = Scalar::one();
        let sk = Some(SecretKey::default());
        let pk = PublicKey::default();

        TransactionItem::new(note, nullifier, value, blinding_factor, sk, pk)
    }
}

impl TransactionItem {
    pub fn new<N: Note>(
        note: N,
        nullifier: Nullifier,
        value: u64,
        blinding_factor: Scalar,
        sk: Option<SecretKey>,
        pk: PublicKey,
    ) -> Self {
        TransactionItem {
            note: note.box_clone(),
            nullifier,
            value,
            blinding_factor,
            sk,
            pk,
        }
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn set_value(&mut self, value: u64) {
        self.value = value;
    }

    pub fn pk(&self) -> &PublicKey {
        &self.pk
    }

    pub fn set_pk(&mut self, pk: PublicKey) {
        self.pk = pk;
    }

    pub fn idx(&self) -> &Idx {
        self.note.idx()
    }

    pub fn blinding_factor(&self) -> &Scalar {
        &self.blinding_factor
    }

    pub fn set_blinding_factor(&mut self, blinding_factor: Scalar) {
        self.blinding_factor = blinding_factor;
    }

    pub fn note_type(&self) -> NoteType {
        self.note.note()
    }

    pub fn utxo(&self) -> NoteUtxoType {
        self.note.utxo()
    }

    pub fn note(&self) -> Box<dyn Note> {
        self.note.box_clone()
    }

    pub fn set_note(&mut self, note: Box<dyn Note>) {
        self.note = note;
    }

    pub fn nullifier(&self) -> &Nullifier {
        &self.nullifier
    }

    pub fn try_from_rpc_transaction_input(
        db: &Db,
        item: rpc::TransactionInput,
    ) -> Result<Self, Error> {
        let sk: SecretKey = item.sk.ok_or(Error::InvalidParameters).map(|k| k.into())?;
        let note = db.fetch_box_note(&item.pos.ok_or(Error::InvalidParameters)?)?;

        let item = match note.note() {
            NoteType::Transparent => {
                Db::note_box_into::<TransparentNote>(note).to_transaction_input(sk)
            }
            NoteType::Obfuscated => {
                Db::note_box_into::<ObfuscatedNote>(note).to_transaction_input(sk)
            }
        };

        Ok(item)
    }
}

impl TryFrom<rpc::TransactionOutput> for TransactionItem {
    type Error = Error;

    fn try_from(txo: rpc::TransactionOutput) -> Result<Self, Self::Error> {
        let pk: PublicKey = txo
            .pk
            .ok_or(Error::InvalidParameters)
            .and_then(|k| k.try_into())?;

        let note: Box<dyn Note> = txo.note.ok_or(Error::InvalidParameters)?.try_into()?;

        let mut item = TransactionItem::default();

        item.set_value(txo.value);
        item.set_pk(pk);
        item.set_note(note);
        item.set_blinding_factor(txo.blinding_factor.ok_or(Error::InvalidParameters)?.into());

        Ok(item)
    }
}

impl From<TransactionItem> for rpc::TransactionInput {
    fn from(item: TransactionItem) -> rpc::TransactionInput {
        rpc::TransactionInput {
            pos: Some(item.note().idx().clone()),
            sk: item.sk.map(|sk| sk.into()),
        }
    }
}

impl From<TransactionItem> for rpc::TransactionOutput {
    fn from(item: TransactionItem) -> rpc::TransactionOutput {
        rpc::TransactionOutput {
            note: Some(item.note().into()),
            pk: Some(item.pk.into()),
            value: item.value,
            blinding_factor: Some((*item.blinding_factor()).into()),
        }
    }
}
