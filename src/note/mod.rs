use crate::{
    crypto, db, rpc, utils, BlsScalar, Error, JubJubProjective, JubJubScalar, Nonce, NoteType,
    PublicKey, SecretKey, TransactionInput, TransactionOutput, ViewKey,
};

use std::convert::TryFrom;
use std::fmt::Debug;
use std::ops::Mul;
use std::path::Path;

//use kelvin::{ByteHash, Content, Sink, Source};

/// Nullifier definition
pub mod nullifier;
/// Obfuscated note definitions
pub mod obfuscated;
/// Transparent note definitions
pub mod transparent;
/// Note variant definitions (Transparent and Obfuscated)
pub mod variant;

#[cfg(test)]
mod tests;

pub use nullifier::Nullifier;
pub use obfuscated::ObfuscatedNote;
pub use transparent::TransparentNote;
pub use variant::NoteVariant;

/// Trait for the notes construction
pub trait NoteGenerator:
    Sized
    + Note
    + TryFrom<rpc::Note>
    + TryFrom<rpc::DecryptedNote>
    + Into<rpc::Note>
    + Into<NoteVariant>
    + TryFrom<NoteVariant>
{
    /// Create a new phoenix input note
    fn input<P: AsRef<Path>>(db_path: P, idx: u64) -> Result<Self, Error> {
        Self::try_from(db::fetch_note(db_path, idx)?).map_err(|_| Error::InvalidParameters)
    }

    /// Create a new phoenix output note
    fn output(pk: &PublicKey, value: u64) -> (Self, BlsScalar);

    /// Create a new transaction input item provided the secret key for the nullifier generation
    /// and value / blinding factor decrypt
    fn to_transaction_input(self, sk: SecretKey) -> TransactionInput {
        let vk = sk.view_key();

        let nullifier = self.generate_nullifier(&sk);
        let value = self.value(Some(&vk));
        let blinding_factor = self.blinding_factor(&vk);

        TransactionInput::new(self.into(), nullifier, value, blinding_factor, sk)
    }

    /// Create a new transaction output item provided the target value, blinding factor and pk for
    /// the proof construction.
    ///
    /// The parameters are not present on the note; hence they need to be provided.
    fn to_transaction_output(
        self,
        value: u64,
        blinding_factor: BlsScalar,
        pk: PublicKey,
    ) -> TransactionOutput {
        TransactionOutput::new(self.into(), value, blinding_factor, pk)
    }

    /// Create a `PKr = r · A + B` for the diffie-hellman key exchange
    fn generate_pk_r(pk: &PublicKey) -> (JubJubScalar, JubJubProjective, JubJubProjective) {
        let r = utils::gen_random_scalar();
        let R = utils::mul_by_basepoint_jubjub(&r);

        let rA = pk.A.mul(&r);
        let pk_r = rA + pk.B;

        (r, R, pk_r)
    }

    /// Internally calls the [`crypto::encrypt`] to mask the value
    fn encrypt_value(r: &JubJubScalar, pk: &PublicKey, nonce: &Nonce, value: u64) -> [u8; 24] {
        let bytes = crypto::encrypt(r, pk, nonce, &value.to_le_bytes()[..]);
        utils::safe_24_chunk(bytes.as_slice())
    }

    /// Internally calls the [`crypto::encrypt`] to mask the blinding factor
    fn encrypt_blinding_factor(
        r: &JubJubScalar,
        pk: &PublicKey,
        nonce: &Nonce,
        blinding_factor: &BlsScalar,
    ) -> [u8; 48] {
        let mut blinding_factor_bytes = [0x00u8; utils::BLS_SCALAR_SERIALIZED_SIZE];
        utils::serialize_bls_scalar(blinding_factor, &mut blinding_factor_bytes)
            .expect("In-memory write");

        let bytes = crypto::encrypt(r, pk, &nonce.increment_le(), blinding_factor_bytes);
        utils::safe_48_chunk(bytes.as_slice())
    }
}

/// Phoenix note methods. Both transparent and obfuscated notes implements this
pub trait Note: Debug + Send + Sync {
    /// Create a unique nullifier for the note
    fn generate_nullifier(&self, _sk: &SecretKey) -> Nullifier {
        // TODO - Set nullifier as `H(a, b, idx)`
        crypto::hash_merkle(&[BlsScalar::from(self.idx())]).into()
    }

    /// Fully decrypt the note (value and blinding factor) with the provided [`ViewKey`], and
    /// return an instance of [`rpc::DecryptedNote`]
    fn rpc_decrypted_note(&self, vk: &ViewKey) -> rpc::DecryptedNote {
        let note_type = self.note().into();
        let pos = self.idx();
        let value = self.value(Some(vk));
        let nonce = Some((*self.nonce()).into());
        let r_g = Some((*self.R()).into());
        let pk_r = Some((*self.pk_r()).into());
        let value_commitment = Some((*self.value_commitment()).into());

        let blinding_factor = self.blinding_factor(vk);
        let raw_blinding_factor = match self.note() {
            NoteType::Transparent => {
                rpc::decrypted_note::RawBlindingFactor::TransparentBlindingFactor(
                    blinding_factor.into(),
                )
            }
            NoteType::Obfuscated => {
                rpc::decrypted_note::RawBlindingFactor::EncryptedBlindingFactor(
                    self.encrypted_blinding_factor().to_vec(),
                )
            }
        };
        let raw_blinding_factor = Some(raw_blinding_factor);
        let blinding_factor = Some(blinding_factor.into());

        let raw_value = self
            .encrypted_value()
            .map(|v| rpc::decrypted_note::RawValue::EncryptedValue(v.to_vec()))
            .unwrap_or(rpc::decrypted_note::RawValue::TransparentValue(value));
        let raw_value = Some(raw_value);

        rpc::DecryptedNote {
            note_type,
            pos,
            value,
            nonce,
            r_g,
            pk_r,
            value_commitment,
            blinding_factor,
            raw_blinding_factor,
            raw_value,
        }
    }

    //    /// Generate a tuple (H(note), H(H(note))) for the zero-knowledge note pre-image
    //    fn zk_preimage(&self) -> (Scalar, Scalar) {
    //        let y = self.hash();
    //        let x = crypto::hash_scalar(&y);
    //
    //        (y, x)
    //    }

    /// Return a hash represented by `H(value_commitment, idx, H([R]), H([PKr]))`
    fn hash(&self) -> BlsScalar {
        crypto::hash_merkle(&[
            *self.value_commitment(),
            BlsScalar::from(self.idx()),
            crypto::hash_jubjub_projective(self.R()),
            crypto::hash_jubjub_projective(self.pk_r()),
        ])
    }

    /// Return the type of the note
    fn note(&self) -> NoteType;
    /// Return the position of the note on the tree. For transaction outputs, the position is
    /// undefined; therefore, random
    fn idx(&self) -> u64;
    /// Set the position of the note on the tree. This, naturally, won't reflect immediatelly on
    /// the data storage
    fn set_idx(&mut self, idx: u64);
    /// Nonce used for the encrypt / decrypt of data for this note
    fn nonce(&self) -> &Nonce;

    /// Attempt to decrypt the note value provided a [`ViewKey`]. Always succeeds for transparent
    /// notes, and will return random values for obfuscated notes provided the wrong view key.
    fn value(&self, vk: Option<&ViewKey>) -> u64;

    /// Return the raw encrypted bytes of the value. If the note is transparent, `None` is returned
    fn encrypted_value(&self) -> Option<&[u8; 24]>;
    /// Return the value commitment `H(value, blinding_factor)`
    fn value_commitment(&self) -> &BlsScalar;
    /// Decrypt the blinding factor with the provided [`ViewKey`]
    ///
    /// If the decrypt fails, a random value is returned
    fn blinding_factor(&self, vk: &ViewKey) -> BlsScalar;
    /// Return the raw encrypted value blinding factor
    fn encrypted_blinding_factor(&self) -> &[u8; 48];
    /// Return the `r · G` used for the DHKE randomness
    fn R(&self) -> &JubJubProjective;
    /// Return the public DHKE combined with the secret key of the owner of the note
    fn pk_r(&self) -> &JubJubProjective;

    /// Return true if the note was constructed with the same secret that constructed the provided
    /// view key
    ///
    /// This holds true if `a · R + B == PKr`
    fn is_owned_by(&self, vk: &ViewKey) -> bool {
        let aR = self.R().mul(&vk.a);
        let pk_r = aR + vk.B;

        self.pk_r() == &pk_r
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
