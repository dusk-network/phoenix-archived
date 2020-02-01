use crate::{
    crypto, rpc, utils, CompressedRistretto, Db, EdwardsPoint, Error, Idx, Nonce, NoteType,
    PublicKey, R1CSProof, Scalar, SecretKey, TransactionItem, ViewKey,
};

use std::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
};

pub mod idx;
pub mod nullifier;
pub mod obfuscated;
pub mod transparent;

#[cfg(test)]
mod tests;

pub use nullifier::Nullifier;
pub use obfuscated::ObfuscatedNote;
pub use transparent::TransparentNote;

pub trait NoteGenerator:
    Sized + Note + TryFrom<rpc::Note> + TryFrom<rpc::DecryptedNote> + Into<rpc::Note>
{
    /// Create a new phoenix note
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn input(db: &Db, idx: &Idx) -> Result<Self, Error>;
    fn output(pk: &PublicKey, value: u64) -> (Self, Scalar);

    /// Transaction
    fn to_transaction_input(mut self, sk: SecretKey) -> TransactionItem {
        let vk = sk.view_key();
        let pk = sk.public_key();

        self.set_utxo(NoteUtxoType::Input);

        let nullifier = self.generate_nullifier(&sk);
        let value = self.value(Some(&vk));
        let blinding_factor = self.blinding_factor(&vk);

        TransactionItem::new(self, nullifier, value, blinding_factor, Some(sk), pk)
    }
    fn to_transaction_output(
        mut self,
        value: u64,
        blinding_factor: Scalar,
        pk: PublicKey,
    ) -> TransactionItem {
        self.set_utxo(NoteUtxoType::Output);

        TransactionItem::new(self, Nullifier::default(), value, blinding_factor, None, pk)
    }

    /// Attributes
    fn generate_pk_r(pk: &PublicKey) -> (Scalar, EdwardsPoint, EdwardsPoint) {
        let r = utils::gen_random_clamped_scalar();
        let r_g = utils::mul_by_basepoint_edwards(&r);

        let r_a_g = pk.a_g * r;
        let r_a_g = utils::edwards_to_scalar(r_a_g);
        let r_a_g = crypto::hash_scalar(&r_a_g);
        let r_a_g = utils::mul_by_basepoint_edwards(&r_a_g);

        let pk_r = r_a_g + pk.b_g;

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
    fn generate_nullifier(&self, _sk: &SecretKey) -> Nullifier {
        // TODO - Create a secure nullifier
        Nullifier::new(self.idx().pos.into())
    }

    #[allow(clippy::trivially_copy_pass_by_ref)] // Nullifier
    fn validate_nullifier(&self, nullifier: &Nullifier) -> Result<(), Error> {
        // TODO - Validate the nullifier securely
        if nullifier.x == self.idx().pos.into() {
            Ok(())
        } else {
            Err(Error::Generic)
        }
    }

    fn rpc_decrypted_note(&self, vk: &ViewKey) -> rpc::DecryptedNote {
        let note_type: rpc::NoteType = self.note().into();
        let note_type = note_type.into();
        let pos = Some((self.idx().clone()).into());
        let value = self.value(Some(vk));
        let io: rpc::InputOutput = self.utxo().into();
        let io = io.into();
        let nonce = Some((*self.nonce()).into());
        let r_g = Some((*self.r_g()).into());
        let pk_r = Some((*self.pk_r()).into());
        let commitment = Some((*self.commitment()).into());
        let blinding_factor = Some(self.blinding_factor(vk).into());
        let encrypted_blinding_factor = self.encrypted_blinding_factor().clone();
        let raw_value = self
            .encrypted_value()
            .map(|ev| rpc::decrypted_note::RawValue::EncryptedValue(ev.clone()))
            .unwrap_or(rpc::decrypted_note::RawValue::TransparentValue(value));
        let raw_value = Some(raw_value);

        rpc::DecryptedNote {
            note_type,
            pos,
            value,
            io,
            nonce,
            r_g,
            pk_r,
            commitment,
            blinding_factor,
            encrypted_blinding_factor,
            raw_value,
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
    // TODO - This is not really a property of the note, but of the transaction item. Remove it.
    fn utxo(&self) -> NoteUtxoType;
    fn set_utxo(&mut self, utxo: NoteUtxoType);
    fn note(&self) -> NoteType;
    fn idx(&self) -> &Idx;
    fn nonce(&self) -> &Nonce;
    fn set_idx(&mut self, idx: Idx);
    fn value(&self, vk: Option<&ViewKey>) -> u64;
    fn encrypted_value(&self) -> Option<&Vec<u8>>;
    fn commitment(&self) -> &CompressedRistretto;
    fn blinding_factor(&self, vk: &ViewKey) -> Scalar;
    fn encrypted_blinding_factor(&self) -> &Vec<u8>;
    fn r_g(&self) -> &EdwardsPoint;
    fn pk_r(&self) -> &EdwardsPoint;
    fn sk_r(&self, sk: &SecretKey) -> Scalar {
        let r_a_g = sk.a * self.r_g();
        let r_a_g = utils::edwards_to_scalar(r_a_g);
        let r_a_g = crypto::hash_scalar(&r_a_g);

        r_a_g + sk.b
    }

    /// Validations
    fn is_owned_by(&self, vk: &ViewKey) -> bool {
        let r_a_g = vk.a * self.r_g();
        let r_a_g = utils::edwards_to_scalar(r_a_g);
        let r_a_g = crypto::hash_scalar(&r_a_g);
        let r_a_g = utils::mul_by_basepoint_edwards(&r_a_g);

        let pk_r = r_a_g + vk.b_g;

        self.pk_r() == &pk_r
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl TryFrom<i32> for NoteType {
    type Error = Error;

    fn try_from(note_type: i32) -> Result<Self, Self::Error> {
        match note_type {
            0 => Ok(NoteType::Transparent),
            1 => Ok(NoteType::Obfuscated),
            _ => Err(Error::InvalidParameters),
        }
    }
}

impl From<Box<dyn Note>> for rpc::Note {
    fn from(note: Box<dyn Note>) -> Self {
        match note.note() {
            NoteType::Transparent => Db::note_box_into::<TransparentNote>(note).into(),
            NoteType::Obfuscated => Db::note_box_into::<ObfuscatedNote>(note).into(),
        }
    }
}

impl TryFrom<rpc::Note> for Box<dyn Note> {
    type Error = Error;

    fn try_from(note: rpc::Note) -> Result<Self, Self::Error> {
        match note.note_type.try_into()? {
            rpc::NoteType::Transparent => Ok(Box::new(TransparentNote::try_from(note)?)),
            rpc::NoteType::Obfuscated => Ok(Box::new(ObfuscatedNote::try_from(note)?)),
        }
    }
}
