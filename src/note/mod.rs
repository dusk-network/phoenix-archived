use crate::{Error, PublicKey, R1CSProof, RistrettoPoint, SecretKey};

use serde::{Deserialize, Serialize};

pub mod obfuscated;
pub mod transparent;

#[cfg(test)]
mod tests;

pub use obfuscated::ObfuscatedNote;
pub use transparent::TransparentNote;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Nullifier {
    point: RistrettoPoint,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Idx(pub u64);

impl From<u64> for Idx {
    fn from(idx: u64) -> Self {
        Idx(idx)
    }
}

pub trait Note: Sized {
    /// Create a new phoenix note
    fn input(idx: &Idx) -> Self;
    fn output(pk: &PublicKey, value: u64) -> Self;

    /// Generate a proof of knowledge of the value
    ///
    /// N/A to transparent notes.
    fn prove_value(&self, _sk_r: &SecretKey) -> Result<R1CSProof, Error> {
        Err(Error::Generic)
    }
    fn verify_value(&self, _proof: &R1CSProof) -> Result<(), Error> {
        Err(Error::Generic)
    }

    /// Attributes
    fn utxo(&self) -> NoteUtxoType;
    fn note(&self) -> NoteType;
    fn idx(&self) -> &Idx;
    fn set_idx(self, idx: Idx) -> Self;
    fn nullifier(&self, _sk_r: &SecretKey) -> Nullifier {
        unimplemented!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteUtxoType {
    Input,
    Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteType {
    Transparent,
    Obfuscated,
}
