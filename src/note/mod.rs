use crate::{
    utils, Db, EdwardsPoint, Error, Nonce, PublicKey, R1CSProof, Scalar, SecretKey,
    TransactionItem, ViewKey,
};

use std::fmt::Debug;

use hades252::scalar;
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
    fn to_transaction_input(mut self, nullifier: Nullifier, value: u64) -> TransactionItem {
        self.set_utxo(NoteUtxoType::Input);
        TransactionItem::new(self, Some(nullifier), Some(value))
    }
    fn to_transaction_output(self, value: u64) -> TransactionItem {
        TransactionItem::new(self, None, Some(value))
    }

    /// Attributes
    fn generate_pk_r(pk: &PublicKey) -> (Scalar, EdwardsPoint, EdwardsPoint) {
        let r = utils::gen_random_clamped_scalar();
        let r_g = utils::mul_by_basepoint_edwards(&r);

        let pk_r = &pk.a_g * &r + &pk.b_g;

        (r, r_g, pk_r)
    }
}

pub trait Note: Debug + Send + Sync {
    fn box_clone(&self) -> Box<dyn Note>;

    /// Generate a proof of knowledge of the value
    ///
    /// N/A to transparent notes.
    fn prove_value(&self, _vk: &ViewKey) -> Result<R1CSProof, Error> {
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
    fn hash(&self) -> Scalar {
        // TODO - Hash the entire note
        Scalar::from_bits(self.pk_r().compress().to_bytes())
    }
    /// Generate y, x for the zero-knowledge pre-image
    fn zk_preimage(&self) -> (Scalar, Scalar) {
        let y = self.hash();
        // TODO - Update hades252 to a never-fail scalar hash
        let x = scalar::hash(&[y]).unwrap();

        (y, x)
    }
    fn utxo(&self) -> NoteUtxoType;
    fn set_utxo(&mut self, utxo: NoteUtxoType);
    fn note(&self) -> NoteType;
    fn idx(&self) -> &Idx;
    fn nonce(&self) -> &Nonce;
    fn r_g(&self) -> &EdwardsPoint;
    fn pk_r(&self) -> &EdwardsPoint;
    fn generate_sk_r(&self, _sk: &SecretKey) {
        // TODO - Find the proper Schnorr signature
        unimplemented!()
    }
    fn set_idx(&mut self, idx: Idx);
    // N/A to obfuscated notes
    fn value(&self) -> u64 {
        0
    }

    /// Validations
    fn is_owned_by(&self, vk: &ViewKey) -> bool {
        let pk_r = &vk.a * self.r_g() + &vk.b_g;
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
