use crate::{
    crypto, rpc, utils, BlsScalar, JubJubProjective, Nonce, Note, NoteGenerator, NoteType,
    PublicKey, ViewKey,
};

use std::{cmp, fmt};

//use super::{Idx, Note, NoteGenerator, NoteUtxoType};
//use crate::{
//    crypto, rpc, utils, CompressedRistretto, Error, Nonce, NoteType, PublicKey, R1CSProof,
//    RistrettoPoint, Scalar, Value, ViewKey, NONCEBYTES,
//};
//
//use std::cmp;
//use std::convert::{TryFrom, TryInto};
//use std::fmt;
//use std::io::{self, Read, Write};
//
//use kelvin::{ByteHash, Content, Sink, Source};
//use sha2::{Digest, Sha512};
//
/// A note that hides its value and blinding factor
#[derive(Clone, Copy)]
pub struct ObfuscatedNote {
    value_commitment: BlsScalar,
    nonce: Nonce,
    R: JubJubProjective,
    pk_r: JubJubProjective,
    idx: u64,
    pub encrypted_value: [u8; 24],
    pub encrypted_blinding_factor: [u8; 48],
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
        encrypted_value: [u8; 24],
        encrypted_blinding_factor: [u8; 48],
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
    fn output(pk: &PublicKey, value: u64) -> (Self, BlsScalar) {
        let nonce = utils::gen_nonce();

        let (r, R, pk_r) = Self::generate_pk_r(pk);

        let blinding_factor = utils::gen_random_bls_scalar();
        let value_commitment = BlsScalar::from(value);
        let value_commitment = crypto::hash_merkle(&[value_commitment, blinding_factor]);

        // Output notes have undefined idx
        let idx = 0;

        let encrypted_value = ObfuscatedNote::encrypt_value(&r, pk, &nonce, value);
        let encrypted_blinding_factor =
            ObfuscatedNote::encrypt_blinding_factor(&r, pk, &nonce, &blinding_factor);

        let note = ObfuscatedNote::new(
            value_commitment,
            nonce,
            R,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factor,
        );

        (note, blinding_factor)
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

    fn encrypted_value(&self) -> Option<&[u8; 24]> {
        Some(&self.encrypted_value)
    }

    fn value_commitment(&self) -> &BlsScalar {
        &self.value_commitment
    }

    fn blinding_factor(&self, vk: &ViewKey) -> BlsScalar {
        let blinding_factor = crypto::decrypt(
            &self.R,
            vk,
            &self.nonce.increment_le(),
            &self.encrypted_blinding_factor[..],
        );

        utils::deserialize_bls_scalar(blinding_factor.as_slice())
            .unwrap_or(utils::gen_random_bls_scalar())
    }

    fn encrypted_blinding_factor(&self) -> &[u8; 48] {
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
                let commitment = unimplemented!(); // Some(note.value_commitment.into());
                let encrypted_blinding_factor = note.encrypted_blinding_factor.to_vec();
                let value = Some(rpc::note::Value::EncryptedValue(
                    note.encrypted_value.to_vec(),
                ));

                rpc::Note {
                    note_type,
                    pos,
                    nonce,
                    r_g,
                    pk_r,
                    commitment,
                    encrypted_blinding_factor,
                    value,
                }
    }
}
//
//impl TryFrom<rpc::Note> for ObfuscatedNote {
//    type Error = Error;
//
//    fn try_from(note: rpc::Note) -> Result<Self, Self::Error> {
//        if rpc::NoteType::try_from(note.note_type)? != NoteType::Obfuscated {
//            return Err(Error::InvalidParameters);
//        }
//
//        let utxo = rpc::InputOutput::try_from(note.io)?.into();
//        let nonce = note.nonce.ok_or(Error::InvalidParameters)?.try_into()?;
//        let r_g = note.r_g.ok_or(Error::InvalidParameters)?.try_into()?;
//        let pk_r = note.pk_r.ok_or(Error::InvalidParameters)?.try_into()?;
//        let idx = note.pos.ok_or(Error::InvalidParameters)?;
//        let commitment = note.commitment.ok_or(Error::InvalidParameters)?.into();
//
//        let encrypted_blinding_factor = note.encrypted_blinding_factor;
//        let encrypted_blinding_factor = utils::safe_48_chunk(encrypted_blinding_factor.as_slice());
//
//        let encrypted_value = match note.value.ok_or(Error::InvalidParameters)? {
//            rpc::note::Value::TransparentValue(_) => Err(Error::InvalidParameters),
//            rpc::note::Value::EncryptedValue(v) => Ok(v),
//        }?;
//        let encrypted_value = utils::safe_24_chunk(encrypted_value.as_slice());
//
//        Ok(ObfuscatedNote::new(
//            utxo,
//            commitment,
//            nonce,
//            r_g,
//            pk_r,
//            idx,
//            encrypted_value,
//            encrypted_blinding_factor,
//        ))
//    }
//}
//
//impl TryFrom<rpc::DecryptedNote> for ObfuscatedNote {
//    type Error = Error;
//
//    fn try_from(note: rpc::DecryptedNote) -> Result<Self, Self::Error> {
//        let utxo = NoteUtxoType::Output;
//        let commitment = note.commitment.ok_or(Error::InvalidParameters)?.into();
//        let nonce = note.nonce.ok_or(Error::InvalidParameters)?.try_into()?;
//        let r_g = note.r_g.ok_or(Error::InvalidParameters)?.try_into()?;
//        let pk_r = note.pk_r.ok_or(Error::InvalidParameters)?.try_into()?;
//        let idx = note.pos.ok_or(Error::InvalidParameters)?;
//
//        let encrypted_blinding_factor = note.encrypted_blinding_factor;
//        let encrypted_blinding_factor = utils::safe_48_chunk(encrypted_blinding_factor.as_slice());
//
//        let encrypted_value = match note.raw_value.ok_or(Error::InvalidParameters)? {
//            rpc::decrypted_note::RawValue::EncryptedValue(v) => Ok(v),
//            _ => Err(Error::InvalidParameters),
//        }?;
//        let encrypted_value = utils::safe_24_chunk(encrypted_value.as_slice());
//
//        Ok(ObfuscatedNote::new(
//            utxo,
//            commitment,
//            nonce,
//            r_g,
//            pk_r,
//            idx,
//            encrypted_value,
//            encrypted_blinding_factor,
//        ))
//    }
//}
//
//impl<H: ByteHash> Content<H> for ObfuscatedNote {
//    fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
//        self.utxo.persist(sink)?;
//        self.commitment.0.persist(sink)?;
//        self.nonce.0.persist(sink)?;
//
//        let r_g = self.r_g.compress();
//        sink.write_all(&r_g.0)?;
//
//        let pk_r = self.pk_r.compress();
//        sink.write_all(&pk_r.0)?;
//
//        self.idx.persist(sink)?;
//        self.encrypted_value.to_vec().persist(sink)?;
//        self.encrypted_blinding_factor.to_vec().persist(sink)
//    }
//
//    fn restore(source: &mut Source<H>) -> io::Result<Self> {
//        let utxo = NoteUtxoType::restore(source)?;
//
//        let mut commitment = CompressedRistretto::default();
//        source.read_exact(&mut commitment.0)?;
//
//        let mut nonce_bytes = [0u8; NONCEBYTES];
//        source.read_exact(&mut nonce_bytes)?;
//        let nonce = Nonce(nonce_bytes);
//
//        let mut r_g = CompressedRistretto::default();
//        source.read_exact(&mut r_g.0)?;
//        let r_g = if let Some(point) = r_g.decompress() {
//            point
//        } else {
//            return Err(io::Error::new(
//                io::ErrorKind::InvalidData,
//                "Invalid Compressed Ristretto Point encoding",
//            ));
//        };
//
//        let mut pk_r = CompressedRistretto::default();
//        source.read_exact(&mut pk_r.0)?;
//        let pk_r = if let Some(point) = pk_r.decompress() {
//            point
//        } else {
//            return Err(io::Error::new(
//                io::ErrorKind::InvalidData,
//                "Invalid Compressed Ristretto Point encoding",
//            ));
//        };
//
//        let idx = Idx::restore(source)?;
//
//        let encrypted_value = Vec::restore(source)?;
//        let encrypted_value = utils::safe_24_chunk(encrypted_value.as_slice());
//
//        let encrypted_blinding_factor = Vec::restore(source)?;
//        let encrypted_blinding_factor = utils::safe_48_chunk(encrypted_blinding_factor.as_slice());
//
//        Ok(ObfuscatedNote {
//            utxo,
//            commitment,
//            nonce,
//            r_g,
//            pk_r,
//            idx,
//            encrypted_value,
//            encrypted_blinding_factor,
//        })
//    }
//}
