use crate::{
    crypto, utils, BlsScalar, JubJubProjective, Nonce, Note, NoteGenerator, NoteType, PublicKey,
    ViewKey,
};

//use super::{Idx, Note, NoteGenerator, NoteUtxoType};
//use crate::{
//    crypto, rpc, utils, CompressedRistretto, Error, Nonce, NoteType, PublicKey, RistrettoPoint,
//    Scalar, Value, ViewKey, NONCEBYTES,
//};
//
//use kelvin::{ByteHash, Content, Sink, Source};
//use sha2::{Digest, Sha512};
//
//use std::convert::{TryFrom, TryInto};
//use std::fmt;
//use std::io::{self, Read, Write};
//
/// A note that does not encrypt its value
#[derive(Debug, Clone, Copy)]
pub struct TransparentNote {
    value_commitment: BlsScalar,
    nonce: Nonce,
    R: JubJubProjective,
    pk_r: JubJubProjective,
    idx: u64,
    pub value: u64,
    pub blinding_factor: BlsScalar,
}

impl PartialEq for TransparentNote {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}
impl Eq for TransparentNote {}

impl Default for TransparentNote {
    fn default() -> Self {
        TransparentNote::output(&PublicKey::default(), 0).0
    }
}

impl TransparentNote {
    /// [`TransparentNote`] constructor
    pub fn new(
        value_commitment: BlsScalar,
        nonce: Nonce,
        R: JubJubProjective,
        pk_r: JubJubProjective,
        idx: u64,
        value: u64,
        blinding_factor: BlsScalar,
    ) -> Self {
        Self {
            value_commitment,
            nonce,
            R,
            pk_r,
            idx,
            value,
            blinding_factor,
        }
    }
}

impl NoteGenerator for TransparentNote {
    fn output(pk: &PublicKey, value: u64) -> (Self, BlsScalar) {
        let nonce = utils::gen_nonce();

        let (_, R, pk_r) = Self::generate_pk_r(pk);

        let blinding_factor = utils::gen_random_bls_scalar();
        let value_commitment = BlsScalar::from(value);
        let value_commitment = crypto::hash_merkle(&[value_commitment, blinding_factor]);

        // Output notes have undefined idx
        let idx = 0;

        let note = TransparentNote::new(
            value_commitment,
            nonce,
            R,
            pk_r,
            idx,
            value,
            blinding_factor,
        );

        (note, blinding_factor)
    }
}

impl Note for TransparentNote {
    fn note(&self) -> NoteType {
        NoteType::Transparent
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

    fn value(&self, _vk: Option<&ViewKey>) -> u64 {
        self.value
    }

    fn encrypted_value(&self) -> Option<&[u8; 24]> {
        None
    }

    fn value_commitment(&self) -> &BlsScalar {
        &self.value_commitment
    }

    fn blinding_factor(&self, _vk: &ViewKey) -> BlsScalar {
        self.blinding_factor
    }

    fn encrypted_blinding_factor(&self) -> &[u8; 48] {
        &[0x00u8; 48]
    }
}

//impl From<TransparentNote> for rpc::Note {
//    fn from(note: TransparentNote) -> rpc::Note {
//        let note_type = rpc::NoteType::Transparent.into();
//        let pos = note.idx.into();
//        let io = rpc::InputOutput::from(note.utxo).into();
//        let nonce = Some(note.nonce.into());
//        let r_g = Some(note.r_g.into());
//        let pk_r = Some(note.pk_r.into());
//        let commitment = Some(note.commitment.into());
//        let encrypted_blinding_factor = note.encrypted_blinding_factor.to_vec();
//        let value = Some(rpc::note::Value::TransparentValue(note.value));
//
//        rpc::Note {
//            note_type,
//            pos,
//            io,
//            nonce,
//            r_g,
//            pk_r,
//            commitment,
//            encrypted_blinding_factor,
//            value,
//        }
//    }
//}
//
//impl TryFrom<rpc::Note> for TransparentNote {
//    type Error = Error;
//
//    fn try_from(note: rpc::Note) -> Result<Self, Self::Error> {
//        if rpc::NoteType::try_from(note.note_type)? != NoteType::Transparent {
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
//        let value = match note.value.ok_or(Error::InvalidParameters)? {
//            rpc::note::Value::TransparentValue(v) => Ok(v),
//            rpc::note::Value::EncryptedValue(_) => Err(Error::InvalidParameters),
//        }?;
//
//        Ok(Self::new(
//            utxo,
//            value,
//            nonce,
//            r_g,
//            pk_r,
//            idx,
//            commitment,
//            encrypted_blinding_factor,
//        ))
//    }
//}
//
//impl TryFrom<rpc::DecryptedNote> for TransparentNote {
//    type Error = Error;
//
//    fn try_from(note: rpc::DecryptedNote) -> Result<Self, Self::Error> {
//        let utxo = NoteUtxoType::Output;
//        let value = note.value;
//        let nonce = note.nonce.ok_or(Error::InvalidParameters)?.try_into()?;
//        let r_g = note.r_g.ok_or(Error::InvalidParameters)?.try_into()?;
//        let pk_r = note.pk_r.ok_or(Error::InvalidParameters)?.try_into()?;
//        let idx = note.pos.ok_or(Error::InvalidParameters)?;
//        let commitment = note.commitment.ok_or(Error::InvalidParameters)?.into();
//
//        let encrypted_blinding_factor = note.encrypted_blinding_factor;
//        let encrypted_blinding_factor = utils::safe_48_chunk(encrypted_blinding_factor.as_slice());
//
//        Ok(TransparentNote::new(
//            utxo,
//            value,
//            nonce,
//            r_g,
//            pk_r,
//            idx,
//            commitment,
//            encrypted_blinding_factor,
//        ))
//    }
//}
//
//impl<H: ByteHash> Content<H> for TransparentNote {
//    fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
//        self.utxo.persist(sink)?;
//        self.value.persist(sink)?;
//        self.nonce.0.persist(sink)?;
//
//        let r_g = self.r_g.compress();
//        sink.write_all(&r_g.0)?;
//
//        let pk_r = self.pk_r.compress();
//        sink.write_all(&pk_r.0)?;
//
//        self.idx.persist(sink)?;
//        self.commitment.0.persist(sink)?;
//        self.encrypted_blinding_factor.to_vec().persist(sink)
//    }
//
//    fn restore(source: &mut Source<H>) -> io::Result<Self> {
//        let utxo = NoteUtxoType::restore(source)?;
//        let value = u64::restore(source)?;
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
//        let mut commitment = CompressedRistretto::default();
//        source.read_exact(&mut commitment.0)?;
//
//        let encrypted_blinding_factor = Vec::restore(source)?;
//        let encrypted_blinding_factor = utils::safe_48_chunk(encrypted_blinding_factor.as_slice());
//
//        Ok(TransparentNote {
//            utxo,
//            value,
//            nonce,
//            r_g,
//            pk_r,
//            idx,
//            commitment,
//            encrypted_blinding_factor,
//        })
//    }
//}
