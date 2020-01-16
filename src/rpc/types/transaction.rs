use super::{Idx, NoteType, PublicKey, SecretKey};
use crate::{
    Db, Error, Idx as BaseIdx, NoteGenerator, NoteType as BaseNoteType,
    ObfuscatedNote as BaseObfuscatedNote, PublicKey as BasePublicKey, SecretKey as BaseSecretKey,
    Transaction as BaseTransaction, TransactionItem as BaseTransactionItem,
    TransparentNote as BaseTransparentNote,
};

use std::convert::TryInto;

use prost::Message;

#[derive(Clone, PartialEq, Message)]
pub struct TransactionInput {
    #[prost(message, required, tag = "1")]
    pub pos: Idx,
    #[prost(message, required, tag = "2")]
    pub sk: SecretKey,
}

impl TransactionInput {
    pub fn new(pos: Idx, sk: SecretKey) -> Self {
        Self { pos, sk }
    }

    pub fn from_transaction_item(item: &BaseTransactionItem, sk: BaseSecretKey) -> Self {
        Self {
            pos: (*item.idx()).into(),
            sk: sk.into(),
        }
    }

    pub fn to_transaction_item(self, db: &Db) -> Result<BaseTransactionItem, Error> {
        let idx: BaseIdx = self.pos.into();
        let sk: BaseSecretKey = self.sk.into();

        let note = db.fetch_box_note(&idx)?;

        let item = match note.note() {
            BaseNoteType::Transparent => {
                Db::note_box_into::<BaseTransparentNote>(note).to_transaction_input(&sk)
            }
            BaseNoteType::Obfuscated => {
                Db::note_box_into::<BaseObfuscatedNote>(note).to_transaction_input(&sk)
            }
        };

        Ok(item)
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct TransactionOutput {
    #[prost(enumeration = "NoteType", required, tag = "1")]
    pub note_type: i32,
    #[prost(message, required, tag = "2")]
    pub pk: PublicKey,
    #[prost(uint64, required, tag = "3")]
    pub value: u64,
}

impl TransactionOutput {
    pub fn new(note_type: NoteType, pk: PublicKey, value: u64) -> Self {
        Self {
            note_type: note_type.into(),
            pk,
            value,
        }
    }

    pub fn from_transaction_item(item: &BaseTransactionItem, pk: BasePublicKey) -> Self {
        let note_type: NoteType = item.note_type().into();

        Self {
            note_type: note_type.into(),
            pk: pk.into(),
            value: item.value(),
        }
    }
}

impl TryInto<BaseTransactionItem> for TransactionOutput {
    type Error = Error;

    fn try_into(self) -> Result<BaseTransactionItem, Self::Error> {
        let pk: BasePublicKey = self.pk.try_into()?;
        let note_type: NoteType = self.note_type.try_into()?;

        match note_type {
            NoteType::TRANSPARENT => {
                let (note, blinding_factor) = BaseTransparentNote::output(&pk, self.value);
                Ok(note.to_transaction_output(self.value, blinding_factor))
            }
            NoteType::OBFUSCATED => {
                let (note, blinding_factor) = BaseObfuscatedNote::output(&pk, self.value);
                Ok(note.to_transaction_output(self.value, blinding_factor))
            }
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct Transaction {
    #[prost(message, repeated, tag = "1")]
    pub inputs: Vec<TransactionInput>,
    #[prost(message, repeated, tag = "2")]
    pub outputs: Vec<TransactionOutput>,
}

impl Transaction {
    pub fn to_transaction(self, db: &Db) -> Result<BaseTransaction, Error> {
        let mut transaction = BaseTransaction::default();

        for i in self.inputs {
            transaction.push(i.to_transaction_item(db)?);
        }
        for o in self.outputs {
            transaction.push(o.try_into()?);
        }

        Ok(transaction)
    }

    pub fn push_input(&mut self, input: TransactionInput) {
        self.inputs.push(input);
    }

    pub fn push_output(&mut self, output: TransactionOutput) {
        self.outputs.push(output);
    }
}
