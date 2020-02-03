use super::{Idx, Note, NoteGenerator, NoteUtxoType};
use crate::{
    crypto, rpc, utils, CompressedRistretto, Db, EdwardsPoint, Error, Nonce, NoteType, PublicKey,
    Scalar, Value, ViewKey,
};

use std::convert::{TryFrom, TryInto};

use sha2::{Digest, Sha512};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentNote {
    utxo: NoteUtxoType,
    value: u64,
    nonce: Nonce,
    r_g: EdwardsPoint,
    pk_r: EdwardsPoint,
    idx: Idx,
    commitment: CompressedRistretto,
    pub(crate) encrypted_blinding_factor: Vec<u8>,
}

impl Default for TransparentNote {
    fn default() -> Self {
        TransparentNote::output(&PublicKey::default(), 0).0
    }
}

impl TransparentNote {
    pub fn new(
        utxo: NoteUtxoType,
        value: u64,
        nonce: Nonce,
        r_g: EdwardsPoint,
        pk_r: EdwardsPoint,
        idx: Idx,
        commitment: CompressedRistretto,
        encrypted_blinding_factor: Vec<u8>,
    ) -> Self {
        TransparentNote {
            utxo,
            value,
            nonce,
            r_g,
            pk_r,
            idx,
            commitment,
            encrypted_blinding_factor,
        }
    }
}

impl NoteGenerator for TransparentNote {
    fn input(db: &Db, idx: &Idx) -> Result<Self, Error> {
        db.fetch_note(idx)
    }

    fn output(pk: &PublicKey, value: u64) -> (Self, Scalar) {
        let nonce = utils::gen_nonce();
        let (r, r_g, pk_r) = Self::generate_pk_r(pk);

        let phoenix_value = Value::new(Scalar::from(value));

        let blinding_factor = *phoenix_value.blinding_factor();
        let commitment = *phoenix_value.commitment();

        let encrypted_blinding_factor =
            TransparentNote::encrypt_blinding_factor(&r, pk, &nonce, &blinding_factor);

        let note = TransparentNote::new(
            NoteUtxoType::Output,
            value,
            nonce,
            r_g,
            pk_r,
            Idx::default(),
            commitment,
            encrypted_blinding_factor,
        );

        (note, blinding_factor)
    }
}

impl Note for TransparentNote {
    fn hash(&self) -> Scalar {
        // TODO - Use poseidon sponge, when available
        let mut hasher = Sha512::default();

        hasher.input(&[self.utxo.into()]);
        hasher.input(self.value.to_le_bytes());
        hasher.input(&self.nonce);
        hasher.input(self.r_g.compress().as_bytes());
        hasher.input(self.pk_r.compress().as_bytes());
        hasher.input(&self.idx.clone().into_vec());
        hasher.input(&self.commitment.as_bytes());
        hasher.input(&self.encrypted_blinding_factor);

        Scalar::from_hash(hasher)
    }

    fn box_clone(&self) -> Box<dyn Note> {
        Box::new(self.clone())
    }

    fn utxo(&self) -> NoteUtxoType {
        self.utxo
    }

    fn set_utxo(&mut self, utxo: NoteUtxoType) {
        self.utxo = utxo;
    }

    fn note(&self) -> NoteType {
        NoteType::Transparent
    }

    fn idx(&self) -> &Idx {
        &self.idx
    }

    fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    fn r_g(&self) -> &EdwardsPoint {
        &self.r_g
    }

    fn pk_r(&self) -> &EdwardsPoint {
        &self.pk_r
    }

    fn set_idx(&mut self, idx: Idx) {
        self.idx = idx;
    }

    fn value(&self, _vk: Option<&ViewKey>) -> u64 {
        self.value
    }

    fn encrypted_value(&self) -> Option<&Vec<u8>> {
        None
    }

    fn commitment(&self) -> &CompressedRistretto {
        &self.commitment
    }

    fn blinding_factor(&self, vk: &ViewKey) -> Scalar {
        let blinding_factor = crypto::decrypt(
            &self.r_g,
            vk,
            &self.nonce.increment_le(),
            self.encrypted_blinding_factor.as_slice(),
        );

        Scalar::from_bits(utils::safe_32_chunk(blinding_factor.as_slice()))
    }

    fn encrypted_blinding_factor(&self) -> &Vec<u8> {
        &self.encrypted_blinding_factor
    }
}

impl From<TransparentNote> for rpc::Note {
    fn from(note: TransparentNote) -> rpc::Note {
        let note_type = rpc::NoteType::Transparent.into();
        let pos = note.idx.into();
        let io = rpc::InputOutput::from(note.utxo).into();
        let nonce = Some(note.nonce.into());
        let r_g = Some(note.r_g.into());
        let pk_r = Some(note.pk_r.into());
        let commitment = Some(note.commitment.into());
        let encrypted_blinding_factor = note.encrypted_blinding_factor;
        let value = Some(rpc::note::Value::TransparentValue(note.value));

        rpc::Note {
            note_type,
            pos,
            io,
            nonce,
            r_g,
            pk_r,
            commitment,
            encrypted_blinding_factor,
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

        let utxo = rpc::InputOutput::try_from(note.io)?.into();
        let nonce = note.nonce.ok_or(Error::InvalidParameters)?.try_into()?;
        let r_g = note.r_g.ok_or(Error::InvalidParameters)?.try_into()?;
        let pk_r = note.pk_r.ok_or(Error::InvalidParameters)?.try_into()?;
        let idx = note.pos.ok_or(Error::InvalidParameters)?;
        let commitment = note.commitment.ok_or(Error::InvalidParameters)?.into();
        let encrypted_blinding_factor = note.encrypted_blinding_factor;

        let value = match note.value.ok_or(Error::InvalidParameters)? {
            rpc::note::Value::TransparentValue(v) => Ok(v),
            rpc::note::Value::EncryptedValue(_) => Err(Error::InvalidParameters),
        }?;

        Ok(Self::new(
            utxo,
            value,
            nonce,
            r_g,
            pk_r,
            idx,
            commitment,
            encrypted_blinding_factor,
        ))
    }
}

impl TryFrom<rpc::DecryptedNote> for TransparentNote {
    type Error = Error;

    fn try_from(note: rpc::DecryptedNote) -> Result<Self, Self::Error> {
        let utxo = NoteUtxoType::Output;
        let value = note.value;
        let nonce = note.nonce.ok_or(Error::InvalidParameters)?.try_into()?;
        let r_g = note.r_g.ok_or(Error::InvalidParameters)?.try_into()?;
        let pk_r = note.pk_r.ok_or(Error::InvalidParameters)?.try_into()?;
        let idx = note.pos.ok_or(Error::InvalidParameters)?;
        let commitment = note.commitment.ok_or(Error::InvalidParameters)?.into();
        let encrypted_blinding_factor = note.encrypted_blinding_factor;

        Ok(TransparentNote::new(
            utxo,
            value,
            nonce,
            r_g,
            pk_r,
            idx,
            commitment,
            encrypted_blinding_factor,
        ))
    }
}
