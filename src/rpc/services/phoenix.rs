use super::super::{Idx, Note, PublicKey, Scalar, Transaction, ViewKey};
use crate::Error;

use std::convert::TryFrom;

use prost::{Enumeration, Message};

#[derive(Clone, Copy, Debug, PartialEq, Enumeration)]
pub enum Status {
    OK = 0,
    ERROR = 1,
}

impl TryFrom<i32> for Status {
    type Error = Error;

    fn try_from(t: i32) -> Result<Self, Self::Error> {
        match t {
            0 => Ok(Status::OK),
            1 => Ok(Status::ERROR),
            _ => Err(Error::InvalidParameters),
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct FetchDecryptedNoteRequest {
    #[prost(message, required, tag = "1")]
    pub pos: Idx,
    #[prost(message, required, tag = "2")]
    pub vk: ViewKey,
}

#[derive(Clone, PartialEq, Message)]
pub struct FetchNoteResponse {
    #[prost(enumeration = "Status", required, tag = "1")]
    pub status: i32,
    #[prost(message, required, tag = "2")]
    pub note: Note,
}

#[derive(Clone, PartialEq, Message)]
pub struct VerifyTransactionResponse {
    #[prost(enumeration = "Status", required, tag = "1")]
    pub status: i32,
}

#[derive(Clone, PartialEq, Message)]
pub struct VerifyTransactionRootRequest {
    #[prost(message, required, tag = "1")]
    pub transaction: Transaction,
    #[prost(message, required, tag = "2")]
    pub root: Scalar,
}

#[derive(Clone, PartialEq, Message)]
pub struct StoreTransactionsRequest {
    #[prost(message, repeated, tag = "1")]
    pub transactions: Vec<Transaction>,
}

#[derive(Clone, PartialEq, Message)]
pub struct StoreTransactionsResponse {
    #[prost(enumeration = "Status", required, tag = "1")]
    pub status: i32,
    #[prost(message, required, tag = "2")]
    pub root: Scalar,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetFeeResponse {
    #[prost(uint64, required, tag = "1")]
    pub fee: u64,
}

#[derive(Clone, PartialEq, Message)]
pub struct SetFeePkRequest {
    #[prost(message, required, tag = "1")]
    pub transaction: Transaction,
    #[prost(message, required, tag = "2")]
    pub pk: PublicKey,
}

#[derive(Clone, PartialEq, Message)]
pub struct SetFeePkResponse {
    #[prost(enumeration = "Status", required, tag = "1")]
    pub status: i32,
    #[prost(message, required, tag = "2")]
    pub transaction: Transaction,
}

#[derive(Clone, PartialEq, Message)]
pub struct KeysResponse {
    #[prost(message, required, tag = "1")]
    pub vk: ViewKey,
    #[prost(message, required, tag = "2")]
    pub pk: PublicKey,
}
