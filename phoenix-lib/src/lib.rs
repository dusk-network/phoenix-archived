pub use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier,
};
pub use curve25519_dalek::edwards::CompressedEdwardsY;
pub use curve25519_dalek::edwards::EdwardsPoint;
pub use curve25519_dalek::montgomery::MontgomeryPoint;
pub use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
pub use curve25519_dalek::scalar::Scalar;

pub use db::Db;
pub use error::Error;
pub use keys::{PublicKey, SecretKey, ViewKey};
pub use note::{
    Note, NoteGenerator, NoteUtxoType, NoteVariant, Nullifier, ObfuscatedNote, TransparentNote,
};
pub use rpc::{Idx, NoteType};
pub use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce;
pub use transaction::{Transaction, TransactionItem};
pub use zk::value::Value;

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

/// Bulletproofs generators capacity
pub const GENERATORS_CAPACITY: usize = 4096;
/// Maximum allowed number of notes per transaction. If this is updated, then
/// [`GENERATORS_CAPACITY`] must also be updated.
pub const MAX_NOTES_PER_TRANSACTION: usize = 10;
