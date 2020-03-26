use crate::{
    crypto, rpc, utils, BlsScalar, Error, JubJubProjective, Nonce, Note, NoteGenerator, NoteType,
    PublicKey, ViewKey,
};

use std::convert::{TryFrom, TryInto};
use std::io::{self, Write};

use kelvin::{ByteHash, Content, Sink, Source};

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

    fn blinding_factor(&self, _vk: Option<&ViewKey>) -> BlsScalar {
        self.blinding_factor
    }

    fn encrypted_blinding_factor(&self) -> &[u8; 48] {
        &[0x00u8; 48]
    }
}

impl From<TransparentNote> for rpc::Note {
    fn from(note: TransparentNote) -> rpc::Note {
        let note_type = rpc::NoteType::Transparent.into();
        let pos = note.idx.into();
        let nonce = Some(note.nonce.into());
        let r_g = Some(note.R.into());
        let pk_r = Some(note.pk_r.into());
        let value_commitment = Some(note.value_commitment.into());
        let blinding_factor = Some(rpc::note::BlindingFactor::TransparentBlindingFactor(
            note.blinding_factor.into(),
        ));
        let value = Some(rpc::note::Value::TransparentValue(note.value));

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

impl TryFrom<rpc::Note> for TransparentNote {
    type Error = Error;

    fn try_from(note: rpc::Note) -> Result<Self, Self::Error> {
        if rpc::NoteType::try_from(note.note_type)? != NoteType::Transparent {
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

        let blinding_factor = match note.blinding_factor.ok_or(Error::InvalidParameters)? {
            rpc::note::BlindingFactor::TransparentBlindingFactor(b) => Ok(b),
            rpc::note::BlindingFactor::EncryptedBlindingFactor(_) => Err(Error::InvalidParameters),
        }?
        .try_into()?;

        let value = match note.value.ok_or(Error::InvalidParameters)? {
            rpc::note::Value::TransparentValue(v) => Ok(v),
            rpc::note::Value::EncryptedValue(_) => Err(Error::InvalidParameters),
        }?;

        Ok(Self::new(
            value_commitment,
            nonce,
            R,
            pk_r,
            idx,
            value,
            blinding_factor,
        ))
    }
}

impl TryFrom<rpc::DecryptedNote> for TransparentNote {
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
        let value = note.value;
        let blinding_factor = note
            .blinding_factor
            .ok_or(Error::InvalidParameters)?
            .try_into()?;

        Ok(Self::new(
            value_commitment,
            nonce,
            R,
            pk_r,
            idx,
            value,
            blinding_factor,
        ))
    }
}

impl<H: ByteHash> Content<H> for TransparentNote {
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
        self.value.persist(sink)?;

        utils::bls_scalar_to_bytes(&self.blinding_factor)
            .map_err::<io::Error, _>(|e| e.into())
            .and_then(|b| sink.write_all(&b))?;

        Ok(())
    }

    fn restore(source: &mut Source<H>) -> io::Result<Self> {
        let value_commitment = utils::kelvin_source_to_bls_scalar(source)?;
        let R = utils::kelvin_source_to_jubjub_projective(source)?;
        let pk_r = utils::kelvin_source_to_jubjub_projective(source)?;

        let nonce = utils::kelvin_source_to_nonce(source)?;
        let idx = u64::restore(source)?;
        let value = u64::restore(source)?;

        let blinding_factor = utils::kelvin_source_to_bls_scalar(source)?;

        Ok(TransparentNote::new(
            value_commitment,
            nonce,
            R,
            pk_r,
            idx,
            value,
            blinding_factor,
        ))
    }
}
