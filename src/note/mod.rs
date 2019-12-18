use crate::{
    utils, Db, Error, PublicKey, R1CSProof, RistrettoPoint, SecretKey, TransactionItem, ViewKey,
};

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
    fn to_transaction_input(mut self, nullifier: Nullifier) -> TransactionItem {
        self.set_utxo(NoteUtxoType::Input);
        TransactionItem::new(self, Some(nullifier))
    }
    fn to_transaction_output(self) -> TransactionItem {
        TransactionItem::new(self, None)
    }

    /// Attributes
    fn generate_pk_r(pk: &PublicKey) -> (RistrettoPoint, RistrettoPoint) {
        let r = utils::gen_random_scalar();
        let r_p = utils::mul_by_basepoint(&r);
        let pk_r = (&r * &pk.a_p) + pk.b_p;

        (r_p, pk_r)
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
    fn r_p(&self) -> &RistrettoPoint;
    fn pk_r(&self) -> &RistrettoPoint;
    fn set_idx(&mut self, idx: Idx);
    // N/A to obfuscated notes
    fn value(&self) -> u64 {
        0
    }

    /// Validations
    fn is_owned_by(&self, vk: &ViewKey) -> bool {
        let pk_r = (&vk.a * self.r_p()) + vk.b_p;
        self.pk_r() == &pk_r
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
