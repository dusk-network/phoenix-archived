use crate::{Error, PublicKey, R1CSProof, SecretKey};

use serde::{Deserialize, Serialize};

pub mod obfuscated;
pub mod transparent;

#[cfg(test)]
mod tests;

pub use obfuscated::ObfuscatedNote;
pub use transparent::TransparentNote;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PhoenixIdx(pub u64);

impl From<u64> for PhoenixIdx {
    fn from(idx: u64) -> Self {
        PhoenixIdx(idx)
    }
}

pub trait PhoenixNote: Sized {
    /// Create a new phoenix note
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
    fn idx(&self) -> &PhoenixIdx;
    fn set_idx(self, idx: PhoenixIdx) -> Self;
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
