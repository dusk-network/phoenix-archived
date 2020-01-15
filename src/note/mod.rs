use crate::{
    crypto, rpc, utils, CompressedRistretto, Db, EdwardsPoint, Error, Nonce, PublicKey, R1CSProof,
    Scalar, SecretKey, TransactionItem, ViewKey,
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
    fn output(pk: &PublicKey, value: u64) -> (Self, Scalar);

    /// Transaction
    fn to_transaction_input(mut self, sk: &SecretKey) -> TransactionItem {
        let vk = sk.view_key();

        self.set_utxo(NoteUtxoType::Input);

        let nullifier = self.generate_nullifier(sk);
        let value = self.value(Some(&vk));
        let blinding_factor = self.blinding_factor(&vk);

        TransactionItem::new(self, nullifier, value, blinding_factor)
    }
    fn to_transaction_output(mut self, value: u64, blinding_factor: Scalar) -> TransactionItem {
        self.set_utxo(NoteUtxoType::Output);

        TransactionItem::new(self, Nullifier::default(), value, blinding_factor)
    }

    /// RPC
    fn from_rpc_note(note: rpc::Note) -> Result<Self, Error>
    where
        Self: for<'a> Deserialize<'a>,
    {
        Ok(bincode::deserialize(note.raw.as_slice())?)
    }
    fn to_rpc_note(
        self,
        db: Option<&Db>,
        vk: Option<&ViewKey>,
        nullifier: Option<&Nullifier>,
    ) -> Result<rpc::Note, Error>
    where
        Self: Serialize,
    {
        let note_type: rpc::NoteType = self.note().into();
        let pos: u64 = (*self.idx()).into();
        let value = self.value(vk);
        let unspent = if db.is_some() || nullifier.is_some() {
            let db = db.ok_or(Error::InvalidParameters)?;
            let nullifier = nullifier.ok_or(Error::InvalidParameters)?;

            db.fetch_nullifier(nullifier)?.is_none()
        } else {
            false
        };
        let raw = bincode::serialize(&self)?;

        Ok(rpc::Note::new(note_type.into(), pos, value, unspent, raw))
    }

    /// Attributes
    fn generate_pk_r(pk: &PublicKey) -> (Scalar, EdwardsPoint, EdwardsPoint) {
        let r = utils::gen_random_clamped_scalar();
        let r_g = utils::mul_by_basepoint_edwards(&r);

        let r_a_g = &pk.a_g * &r;
        let r_a_g = utils::edwards_to_scalar(r_a_g);
        let r_a_g = crypto::hash_scalar(&r_a_g);
        let r_a_g = utils::mul_by_basepoint_edwards(&r_a_g);

        let pk_r = &r_a_g + &pk.b_g;

        (r, r_g, pk_r)
    }

    fn encrypt_value(r: &Scalar, pk: &PublicKey, nonce: &Nonce, value: u64) -> Vec<u8> {
        crypto::encrypt(r, pk, nonce, &value.to_le_bytes()[..])
    }

    fn encrypt_blinding_factor(
        r: &Scalar,
        pk: &PublicKey,
        nonce: &Nonce,
        blinding_factor: &Scalar,
    ) -> Vec<u8> {
        crypto::encrypt(r, pk, &nonce.increment_le(), blinding_factor.as_bytes())
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

    /// Generate y, x for the zero-knowledge pre-image
    fn zk_preimage(&self) -> (Scalar, Scalar) {
        let y = self.hash();
        let x = crypto::hash_scalar(&y);

        (y, x)
    }

    /// Attributes
    fn hash(&self) -> Scalar;
    fn utxo(&self) -> NoteUtxoType;
    fn set_utxo(&mut self, utxo: NoteUtxoType);
    fn note(&self) -> NoteType;
    fn idx(&self) -> &Idx;
    fn nonce(&self) -> &Nonce;
    fn set_idx(&mut self, idx: Idx);
    fn value(&self, vk: Option<&ViewKey>) -> u64;
    fn commitment(&self) -> &CompressedRistretto;
    fn blinding_factor(&self, vk: &ViewKey) -> Scalar;
    fn r_g(&self) -> &EdwardsPoint;
    fn pk_r(&self) -> &EdwardsPoint;
    fn sk_r(&self, sk: &SecretKey) -> Scalar {
        let r_a_g = &sk.a * self.r_g();
        let r_a_g = utils::edwards_to_scalar(r_a_g);
        let r_a_g = crypto::hash_scalar(&r_a_g);

        r_a_g + sk.b
    }

    /// Validations
    fn is_owned_by(&self, vk: &ViewKey) -> bool {
        let r_a_g = &vk.a * self.r_g();
        let r_a_g = utils::edwards_to_scalar(r_a_g);
        let r_a_g = crypto::hash_scalar(&r_a_g);
        let r_a_g = utils::mul_by_basepoint_edwards(&r_a_g);

        let pk_r = &r_a_g + &vk.b_g;

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

impl Into<u8> for NoteUtxoType {
    fn into(self) -> u8 {
        match self {
            NoteUtxoType::Input => 0,
            NoteUtxoType::Output => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteType {
    Transparent,
    Obfuscated,
}

impl From<rpc::NoteType> for NoteType {
    fn from(t: rpc::NoteType) -> Self {
        match t {
            rpc::NoteType::TRANSPARENT => NoteType::Transparent,
            rpc::NoteType::OBFUSCATED => NoteType::Obfuscated,
        }
    }
}
