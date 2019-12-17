use crate::{Db, Error, PublicKey, R1CSProof, SecretKey, TransactionItem};

use std::fmt::Debug;

use serde::{Deserialize, Serialize};

pub mod idx;
pub mod nullifier;
pub mod obfuscated;
pub mod transparent;

#[cfg(test)]
mod tests;

pub use idx::Idx;
pub use nullifier::Nullifier;
pub use obfuscated::ObfuscatedNote;
pub use transparent::TransparentNote;

pub trait NoteGenerator: Sized + Note {
    /// Create a new phoenix note
    fn input(db: &Db, idx: &Idx) -> Result<Self, Error>;
    fn output(pk: &PublicKey, value: u64) -> Self;

    /// Transaction
    fn to_transaction_input(mut self, sk_r: &SecretKey) -> TransactionItem {
        let nullifier = self.generate_nullifier(sk_r);
        self.set_utxo(NoteUtxoType::Input);
        TransactionItem::new(self, Some(nullifier))
    }
    fn to_transaction_output(self) -> TransactionItem {
        TransactionItem::new(self, None)
    }
}

pub trait Note: Debug + Send + Sync {
    fn box_clone(&self) -> Box<dyn Note>;

    /// Generate a proof of knowledge of the value
    ///
    /// N/A to transparent notes.
    fn prove_value(&self, _sk_r: &SecretKey) -> Result<R1CSProof, Error> {
        Err(Error::Generic)
    }
    fn verify_value(&self, _proof: &R1CSProof) -> Result<(), Error> {
        Err(Error::Generic)
    }

    /// Nullifier handle
    fn generate_nullifier(&self, _sk_r: &SecretKey) -> Nullifier {
        // TODO - Create a secure nullifier
        Nullifier::new(self.idx().0)
    }
    fn validate_nullifier(&self, nullifier: &Nullifier) -> Result<(), Error> {
        // TODO - Validate the nullifier securely
        if nullifier.point() == self.idx().0 {
            Ok(())
        } else {
            Err(Error::Generic)
        }
    }

    /// Attributes
    fn utxo(&self) -> NoteUtxoType;
    fn set_utxo(&mut self, utxo: NoteUtxoType);
    fn note(&self) -> NoteType;
    fn idx(&self) -> &Idx;
    fn set_idx(&mut self, idx: Idx);
    // N/A to obfuscated notes
    fn value(&self) -> u64 {
        0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteUtxoType {
    Input,
    Output,
}

impl Default for NoteUtxoType {
    fn default() -> Self {
        NoteUtxoType::Input
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteType {
    Transparent,
    Obfuscated,
}
