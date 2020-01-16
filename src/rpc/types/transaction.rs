use super::{Idx, NoteType, PublicKey, SecretKey};

use prost::Message;

#[derive(Clone, PartialEq, Message)]
pub struct TransactionInput {
    #[prost(message, required, tag = "1")]
    pub pos: Idx,
    #[prost(message, required, tag = "2")]
    pub sk: SecretKey,
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

#[derive(Clone, PartialEq, Message)]
pub struct Transaction {
    #[prost(message, repeated, tag = "1")]
    pub inputs: Vec<TransactionInput>,
    #[prost(message, repeated, tag = "2")]
    pub outputs: Vec<TransactionOutput>,
}
