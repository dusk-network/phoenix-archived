use crate::{
    crypto, rpc, utils, BlsScalar, Error, JubJubProjective, JubJubScalar, Nonce, Note,
    NoteGenerator, NoteType, PublicKey, ViewKey,
};

use std::convert::{TryFrom, TryInto};
use std::io::{self, Read, Write};
use std::{cmp, fmt};

use kelvin::{ByteHash, Content, Sink, Source};

/// Size of the encrypted value
pub const ENCRYPTED_VALUE_SIZE: usize = 24;
/// Size of the encrypted blinding factor
pub const ENCRYPTED_BLINDING_FACTOR_SIZE: usize = 48;

/// A note that hides its value and blinding factor
#[derive(Clone, Copy)]
pub struct ObfuscatedNote {
    value_commitment: BlsScalar,
    nonce: Nonce,
    R: JubJubProjective,
    pk_r: JubJubProjective,
    idx: u64,
    pub encrypted_value: [u8; ENCRYPTED_VALUE_SIZE],
    pub encrypted_blinding_factor: [u8; ENCRYPTED_BLINDING_FACTOR_SIZE],
}

impl fmt::Debug for ObfuscatedNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObfuscatedNote {{ nonce: {:?}, R: {:?}, pk_r: {:?}, idx: {:?}, value_commitment: {:?}, encrypted_value: {:?}, encrypted_blinding_factor: {:?} }}", self.nonce, self.R, self.pk_r, self.idx, self.value_commitment, &self.encrypted_value, &self.encrypted_blinding_factor[0..32])
    }
}

impl PartialEq for ObfuscatedNote {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}
impl Eq for ObfuscatedNote {}

impl Default for ObfuscatedNote {
    fn default() -> Self {
        ObfuscatedNote::output(&PublicKey::default(), 0).0
    }
}

impl ObfuscatedNote {
    /// [`ObfuscatedNote`] constructor
    pub fn new(
        value_commitment: BlsScalar,
        nonce: Nonce,
        R: JubJubProjective,
        pk_r: JubJubProjective,
        idx: u64,
        encrypted_value: [u8; ENCRYPTED_VALUE_SIZE],
        encrypted_blinding_factor: [u8; ENCRYPTED_BLINDING_FACTOR_SIZE],
    ) -> Self {
        ObfuscatedNote {
            value_commitment,
            nonce,
            R,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factor,
        }
    }
}

impl NoteGenerator for ObfuscatedNote {
    fn deterministic_output(
        r: &JubJubScalar,
        nonce: Nonce,
        pk: &PublicKey,
        value: u64,
        blinding_factor: BlsScalar,
    ) -> Self {
        let (R, pk_r) = Self::new_pk_r(r, pk);
        let value_commitment = BlsScalar::from(value);
        let value_commitment = crypto::hash_merkle(&[value_commitment, blinding_factor]);

        // Output notes have undefined idx
        let idx = 0;

        let encrypted_value = ObfuscatedNote::encrypt_value(&r, pk, &nonce, value);
        let encrypted_blinding_factor =
            ObfuscatedNote::encrypt_blinding_factor(&r, pk, &nonce, &blinding_factor);

        ObfuscatedNote::new(
            value_commitment,
            nonce,
            R,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factor,
        )
    }
}

impl Note for ObfuscatedNote {
    fn note(&self) -> NoteType {
        NoteType::Obfuscated
    }

    fn idx(&self) -> u64 {
        self.idx
    }

    fn set_idx(&mut self, idx: u64) {
        self.idx = idx;
    }

    fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    fn R(&self) -> &JubJubProjective {
        &self.R
    }

    fn pk_r(&self) -> &JubJubProjective {
        &self.pk_r
    }

    fn value(&self, vk: Option<&ViewKey>) -> u64 {
        let vk = vk.copied().unwrap_or_default();

        let decrypt_value = crypto::decrypt(&self.R, &vk, &self.nonce, &self.encrypted_value[..]);

        let mut v = [0x00u8; 8];
        let chunk = cmp::min(decrypt_value.len(), 8);
        (&mut v[0..chunk]).copy_from_slice(&decrypt_value.as_slice()[0..chunk]);

        u64::from_le_bytes(v)
    }

    fn encrypted_value(&self) -> Option<&[u8; ENCRYPTED_VALUE_SIZE]> {
        Some(&self.encrypted_value)
    }

    fn value_commitment(&self) -> &BlsScalar {
        &self.value_commitment
    }

    fn blinding_factor(&self, vk: Option<&ViewKey>) -> BlsScalar {
        let vk = vk.copied().unwrap_or_default();

        let blinding_factor = crypto::decrypt(
            &self.R,
            &vk,
            &self.nonce.increment_le(),
            &self.encrypted_blinding_factor[..],
        );

        utils::deserialize_bls_scalar(blinding_factor.as_slice())
            .unwrap_or(utils::gen_random_bls_scalar())
    }

    fn encrypted_blinding_factor(&self) -> &[u8; ENCRYPTED_BLINDING_FACTOR_SIZE] {
        &self.encrypted_blinding_factor
    }
}

impl From<ObfuscatedNote> for rpc::Note {
    fn from(note: ObfuscatedNote) -> rpc::Note {
        let note_type = rpc::NoteType::Obfuscated.into();
        let pos = note.idx.into();
        let nonce = Some(note.nonce.into());
        let r_g = Some(note.R.into());
        let pk_r = Some(note.pk_r.into());
        let value_commitment = Some(note.value_commitment.into());
        let value = Some(rpc::note::Value::EncryptedValue(
            note.encrypted_value.to_vec(),
        ));
        let blinding_factor = Some(rpc::note::BlindingFactor::EncryptedBlindingFactor(
            note.encrypted_value.to_vec(),
        ));

        rpc::Note {
            note_type,
            pos,
            nonce,
            r_g,
            pk_r,
            value_commitment,
            blinding_factor,
            value,
        }
    }
}

impl TryFrom<rpc::Note> for ObfuscatedNote {
    type Error = Error;

    fn try_from(note: rpc::Note) -> Result<Self, Self::Error> {
        if rpc::NoteType::try_from(note.note_type)? != NoteType::Obfuscated {
            return Err(Error::InvalidParameters);
        }

        let value_commitment = note
            .value_commitment
            .ok_or(Error::InvalidParameters)?
            .try_into()?;
        let nonce = note.nonce.ok_or(Error::InvalidParameters)?.try_into()?;
        let R = note.r_g.ok_or(Error::InvalidParameters)?.try_into()?;
        let pk_r = note.pk_r.ok_or(Error::InvalidParameters)?.try_into()?;
        let idx = note.pos;

        let encrypted_value = match note.value.ok_or(Error::InvalidParameters)? {
            rpc::note::Value::TransparentValue(_) => Err(Error::InvalidParameters),
            rpc::note::Value::EncryptedValue(v) => Ok(v),
        }?;
        let encrypted_value = utils::safe_24_chunk(encrypted_value.as_slice());

        let encrypted_blinding_factor =
            match note.blinding_factor.ok_or(Error::InvalidParameters)? {
                rpc::note::BlindingFactor::TransparentBlindingFactor(_) => {
                    Err(Error::InvalidParameters)
                }
                rpc::note::BlindingFactor::EncryptedBlindingFactor(b) => Ok(b),
            }?;
        let encrypted_blinding_factor = utils::safe_48_chunk(encrypted_blinding_factor.as_slice());

        Ok(ObfuscatedNote::new(
            value_commitment,
            nonce,
            R,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factor,
        ))
    }
}

impl TryFrom<rpc::DecryptedNote> for ObfuscatedNote {
    type Error = Error;

    fn try_from(note: rpc::DecryptedNote) -> Result<Self, Self::Error> {
        let value_commitment = note
            .value_commitment
            .ok_or(Error::InvalidParameters)?
            .try_into()?;
        let nonce = note.nonce.ok_or(Error::InvalidParameters)?.try_into()?;
        let R = note.r_g.ok_or(Error::InvalidParameters)?.try_into()?;
        let pk_r = note.pk_r.ok_or(Error::InvalidParameters)?.try_into()?;
        let idx = note.pos;

        let encrypted_value = match note.raw_value.ok_or(Error::InvalidParameters)? {
            rpc::decrypted_note::RawValue::EncryptedValue(v) => Ok(v),
            _ => Err(Error::InvalidParameters),
        }?;
        let encrypted_value = utils::safe_24_chunk(encrypted_value.as_slice());

        let encrypted_blinding_factor =
            match note.raw_blinding_factor.ok_or(Error::InvalidParameters)? {
                rpc::decrypted_note::RawBlindingFactor::TransparentBlindingFactor(_) => {
                    Err(Error::InvalidParameters)
                }
                rpc::decrypted_note::RawBlindingFactor::EncryptedBlindingFactor(b) => Ok(b),
            }?;
        let encrypted_blinding_factor = utils::safe_48_chunk(encrypted_blinding_factor.as_slice());

        Ok(ObfuscatedNote::new(
            value_commitment,
            nonce,
            R,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factor,
        ))
    }
}

impl<H: ByteHash> Content<H> for ObfuscatedNote {
    fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
        utils::bls_scalar_to_bytes(&self.value_commitment)
            .map_err::<io::Error, _>(|e| e.into())
            .and_then(|b| sink.write_all(&b))?;

        utils::projective_jubjub_to_bytes(&self.R)
            .map_err::<io::Error, _>(|e| e.into())
            .and_then(|b| sink.write_all(&b))?;

        utils::projective_jubjub_to_bytes(&self.pk_r)
            .map_err::<io::Error, _>(|e| e.into())
            .and_then(|b| sink.write_all(&b))?;

        self.nonce.0.persist(sink)?;
        self.idx.persist(sink)?;

        sink.write_all(&self.encrypted_value[..])?;
        sink.write_all(&self.encrypted_blinding_factor[..])?;

        Ok(())
    }

    fn restore(source: &mut Source<H>) -> io::Result<Self> {
        let value_commitment = utils::kelvin_source_to_bls_scalar(source)?;
        let R = utils::kelvin_source_to_jubjub_projective(source)?;
        let pk_r = utils::kelvin_source_to_jubjub_projective(source)?;

        let nonce = utils::kelvin_source_to_nonce(source)?;
        let idx = u64::restore(source)?;

        let mut encrypted_value = [0x00u8; ENCRYPTED_VALUE_SIZE];
        source.read_exact(&mut encrypted_value)?;

        let mut encrypted_blinding_factor = [0x00u8; ENCRYPTED_BLINDING_FACTOR_SIZE];
        source.read_exact(&mut encrypted_blinding_factor)?;

        Ok(ObfuscatedNote::new(
            value_commitment,
            nonce,
            R,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factor,
        ))
    }
}
