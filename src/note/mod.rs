use crate::{
    crypto, db, rpc, utils, CompressedRistretto, Error, Idx, Nonce, NoteType, PublicKey, R1CSProof,
    RistrettoPoint, Scalar, SecretKey, TransactionItem, ViewKey,
};

use kelvin::{ByteHash, Content, Sink, Source};

use std::io;
use std::{cmp::Ordering, convert::TryFrom, fmt::Debug};

/// Note position definitions
pub mod idx;
/// Note nullifier definitions
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
    #[allow(clippy::trivially_copy_pass_by_ref)]
    /// Create a new phoenix input note
    fn input(db_path: &'static str, idx: &Idx) -> Result<Self, Error> {
        Self::try_from(db::fetch_note(db_path, idx)?).map_err(|_| Error::InvalidParameters)
    }

    /// Create a new phoenix output note
    fn output(pk: &PublicKey, value: u64) -> (Self, Scalar);

    /// Create a new transaction input item provided the secret key for the nullifier generation
    /// and value / blinding factor decrypt
    fn to_transaction_input(mut self, sk: SecretKey) -> TransactionItem {
        let vk = sk.view_key();
        let pk = sk.public_key();

        self.set_utxo(NoteUtxoType::Input);

        let nullifier = self.generate_nullifier(&sk);
        let value = self.value(Some(&vk));
        let blinding_factor = self.blinding_factor(&vk);

        TransactionItem::new(self.into(), nullifier, value, blinding_factor, Some(sk), pk)
    }

    /// Create a new transaction output item provided the target value, blinding factor and pk for
    /// the proof construction.
    ///
    /// The parameters are not present on the note; hence they need to be provided.
    fn to_transaction_output(
        mut self,
        value: u64,
        blinding_factor: Scalar,
        pk: PublicKey,
    ) -> TransactionItem {
        self.set_utxo(NoteUtxoType::Output);

        TransactionItem::new(
            self.into(),
            Nullifier::default(),
            value,
            blinding_factor,
            None,
            pk,
        )
    }

    /// Create a `PKr = r · A + B` for the diffie-hellman key exchange
    fn generate_pk_r(pk: &PublicKey) -> (Scalar, RistrettoPoint, RistrettoPoint) {
        let r = utils::gen_random_clamped_scalar();
        let r_g = utils::mul_by_basepoint_ristretto(&r);

        let r_a_g = pk.a_g * r;
        let r_a_g = utils::ristretto_to_scalar(r_a_g);
        let r_a_g = crypto::hash_scalar(&r_a_g);
        let r_a_g = utils::mul_by_basepoint_ristretto(&r_a_g);

        let pk_r = r_a_g + pk.b_g;

        (r, r_g, pk_r)
    }

    /// Internally calls the [`crypto::encrypt`] to mask the value
    fn encrypt_value(r: &Scalar, pk: &PublicKey, nonce: &Nonce, value: u64) -> [u8; 24] {
        let bytes = crypto::encrypt(r, pk, nonce, &value.to_le_bytes()[..]);
        utils::safe_24_chunk(bytes.as_slice())
    }

    /// Internally calls the [`crypto::encrypt`] to mask the blinding factor
    fn encrypt_blinding_factor(
        r: &Scalar,
        pk: &PublicKey,
        nonce: &Nonce,
        blinding_factor: &Scalar,
    ) -> [u8; 48] {
        let bytes = crypto::encrypt(r, pk, &nonce.increment_le(), blinding_factor.as_bytes());
        utils::safe_48_chunk(bytes.as_slice())
    }
}

/// Phoenix note methods. Both transparent and obfuscated notes implements this
pub trait Note: Debug + Send + Sync {
    /// Generate a proof of knowledge of the value
    ///
    /// N/A to transparent notes.
    fn prove_value(&self, _vk: &ViewKey) -> Result<R1CSProof, Error> {
        Err(Error::Generic)
    }

    /// Verify a proof of knowledge of the value
    ///
    /// N/A to transparent notes.
    fn verify_value(&self, _proof: &R1CSProof) -> Result<(), Error> {
        Err(Error::Generic)
    }

    /// Create a unique nullifier for the note
    fn generate_nullifier(&self, _sk: &SecretKey) -> Nullifier {
        // TODO - Create a secure nullifier
        Nullifier::new(self.idx().pos.into())
    }

    #[allow(clippy::trivially_copy_pass_by_ref)] // Nullifier
    /// Validate the note against a provided nullifier. It will be checked against `PKr`
    fn validate_nullifier(&self, nullifier: &Nullifier) -> Result<(), Error> {
        // TODO - Validate the nullifier securely
        if nullifier.x == self.idx().pos.into() {
            Ok(())
        } else {
            Err(Error::Generic)
        }
    }

    /// Fully decrypt the note (value and blinding factor) with the provided [`ViewKey`], and
    /// return an instance of [`rpc::DecryptedNote`]
    fn rpc_decrypted_note(&self, vk: &ViewKey) -> rpc::DecryptedNote {
        let note_type: rpc::NoteType = self.note();
        let note_type = note_type.into();
        let pos = Some(self.idx().clone());
        let value = self.value(Some(vk));
        let io: rpc::InputOutput = self.utxo().into();
        let io = io.into();
        let nonce = Some((*self.nonce()).into());
        let r_g = Some((*self.r_g()).into());
        let pk_r = Some((*self.pk_r()).into());
        let commitment = Some((*self.commitment()).into());
        let blinding_factor = Some(self.blinding_factor(vk).into());
        let encrypted_blinding_factor = self.encrypted_blinding_factor().to_vec();
        let raw_value = self
            .encrypted_value()
            .map(|ev| rpc::decrypted_note::RawValue::EncryptedValue(ev.to_vec()))
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

    /// Generate a tuple (H(note), H(H(note))) for the zero-knowledge note pre-image
    fn zk_preimage(&self) -> (Scalar, Scalar) {
        let y = self.hash();
        let x = crypto::hash_scalar(&y);

        (y, x)
    }

    /// Deterministically hash the note to a [`Scalar`]
    fn hash(&self) -> Scalar;
    // TODO - This is not really a property of the note, but of the transaction item. Remove it.
    /// Return the I/O direction of the note in a transaction item
    fn utxo(&self) -> NoteUtxoType;
    /// Set the I/O direction of the note in a transaction item
    fn set_utxo(&mut self, utxo: NoteUtxoType);
    /// Return the type of the note
    fn note(&self) -> NoteType;
    /// Return the position of the note on the tree. For transaction outputs, the position is
    /// undefined; therefore, random
    fn idx(&self) -> &Idx;
    /// Set the position of the note on the tree. This, naturally, won't reflect immediatelly on
    /// the data storage
    fn set_idx(&mut self, idx: Idx);
    /// Nonce used for the encrypt / decrypt of data for this note
    fn nonce(&self) -> &Nonce;
    /// Attempt to decrypt the note value provided a [`ViewKey`]. Always succeeds for transparent
    /// notes, and will return random values for obfuscated notes provided the wrong view key.
    fn value(&self, vk: Option<&ViewKey>) -> u64;
    /// Return the raw encrypted bytes for the note. Return an empty `[u8; 24]` for transparent
    /// notes
    fn encrypted_value(&self) -> Option<&[u8; 24]>;
    /// Return the commitment point to the value
    fn commitment(&self) -> &CompressedRistretto;
    /// Attempt to decrypt and return the decrypted blinding factor used to prove the obfuscated note value. If a wrong view key is provided, a random scalar is returned
    fn blinding_factor(&self, vk: &ViewKey) -> Scalar;
    /// Return the raw encrypted value blinding factor
    fn encrypted_blinding_factor(&self) -> &[u8; 48];
    /// Return the `r · G` used for the DHKE randomness
    fn r_g(&self) -> &RistrettoPoint;
    /// Return the public DHKE combined with the secret key of the owner of the note
    fn pk_r(&self) -> &RistrettoPoint;
    /// Provided a secret, return `H(a · R) + B`
    fn sk_r(&self, sk: &SecretKey) -> Scalar {
        let r_a_g = sk.a * self.r_g();
        let r_a_g = utils::ristretto_to_scalar(r_a_g);
        let r_a_g = crypto::hash_scalar(&r_a_g);

        r_a_g + sk.b
    }

    /// Return true if the note was constructed with the same secret that constructed the provided
    /// view key
    ///
    /// This holds true if `H(a · R) · G + B == PKr`
    fn is_owned_by(&self, vk: &ViewKey) -> bool {
        let r_a_g = vk.a * self.r_g();
        let r_a_g = utils::ristretto_to_scalar(r_a_g);
        let r_a_g = crypto::hash_scalar(&r_a_g);
        let r_a_g = utils::mul_by_basepoint_ristretto(&r_a_g);

        let pk_r = r_a_g + vk.b_g;

        self.pk_r() == &pk_r
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// UTXO direction variants
pub enum NoteUtxoType {
    /// Input variant of the UTXO
    Input,
    /// Output variant of the UTXO
    Output,
}

impl Default for NoteUtxoType {
    fn default() -> Self {
        NoteUtxoType::Input
    }
}

impl Ord for NoteUtxoType {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            Ordering::Equal
        } else if self == &NoteUtxoType::Input {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl PartialOrd for NoteUtxoType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self == other {
            Some(Ordering::Equal)
        } else if self == &NoteUtxoType::Input {
            Some(Ordering::Less)
        } else {
            Some(Ordering::Greater)
        }
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

impl<H: ByteHash> Content<H> for NoteUtxoType {
    fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
        match self {
            NoteUtxoType::Input => false.persist(sink),
            NoteUtxoType::Output => true.persist(sink),
        }
    }

    fn restore(source: &mut Source<H>) -> io::Result<Self> {
        Ok(if bool::restore(source)? {
            NoteUtxoType::Output
        } else {
            NoteUtxoType::Input
        })
    }
}
