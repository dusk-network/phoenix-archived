#![allow(non_snake_case)]
#![feature(maybe_uninit_extra)]

pub use dusk_bls12_381::Scalar as BlsScalar;
pub use jubjub::Fr as JubJubScalar;
pub use jubjub::{AffinePoint as JubJubAffine, ExtendedPoint as JubJubExtended};

pub use crypto::MerkleProofProvider;
pub use db::{NotesDb, NotesIter};
pub use error::Error;
pub use keys::{PublicKey, SecretKey, ViewKey};
pub use note::{Note, NoteGenerator, NoteVariant, Nullifier, ObfuscatedNote, TransparentNote};
pub use rpc::NoteType;
pub use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{Nonce, NONCEBYTES};
pub use transaction::{
    Transaction, TransactionInput, TransactionItem, TransactionOutput,
    MAX_INPUT_NOTES_PER_TRANSACTION, MAX_NOTES_PER_TRANSACTION, MAX_OUTPUT_NOTES_PER_TRANSACTION,
    TX_SERIALIZED_SIZE,
};

/// Crypto primitives
pub mod crypto;
/// Storage implementation
pub mod db;
/// General error for phoenix operations
pub mod error;
/// Secret, view and public keys defition
pub mod keys;
/// Transparent and obfuscated notes defition
pub mod note;
/// RPC data generated via protobuf
pub mod rpc;
/// Transaction operations
pub mod transaction;
/// General toolkit
pub mod utils;
/// ZK Gadgets and value proof
pub mod zk;
