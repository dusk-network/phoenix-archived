use super::{Idx, Note, NoteGenerator, NoteType, NoteUtxoType};
use crate::{
    utils, CompressedRistretto, Db, EdwardsPoint, Error, Nonce, PublicKey, Scalar, Value, ViewKey,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentNote {
    utxo: NoteUtxoType,
    value: u64,
    nonce: Nonce,
    r_g: EdwardsPoint,
    pk_r: EdwardsPoint,
    idx: Idx,
    commitment: CompressedRistretto,
    blinding_factor: Scalar,
}

impl Default for TransparentNote {
    fn default() -> Self {
        TransparentNote::output(&PublicKey::default(), 0)
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
        blinding_factor: Scalar,
    ) -> Self {
        TransparentNote {
            utxo,
            value,
            nonce,
            r_g,
            pk_r,
            idx,
            commitment,
            blinding_factor,
        }
    }
}

impl NoteGenerator for TransparentNote {
    fn input(db: &Db, idx: &Idx) -> Result<Self, Error> {
        db.fetch_note(idx)
    }

    fn output(pk: &PublicKey, value: u64) -> Self {
        let nonce = utils::gen_nonce();
        let (_, r_g, pk_r) = Self::generate_pk_r(pk);

        let idx = Idx::default();
        // TODO - Check if phoenix value should receive idx
        let phoenix_value = Value::new(idx, Scalar::from(value));
        let commitment = phoenix_value.commitment().clone();

        // The blinding factor of the transparent note should never be revealed because no r1cs
        // proof should ever be generated for it
        let blinding_factor = Scalar::one().reduce();

        TransparentNote::new(
            NoteUtxoType::Output,
            value,
            nonce,
            r_g,
            pk_r,
            Idx::default(),
            commitment,
            blinding_factor,
        )
    }
}

impl Note for TransparentNote {
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

    fn commitment(&self) -> &CompressedRistretto {
        &self.commitment
    }

    fn blinding_factor(&self, _vk: &ViewKey) -> Scalar {
        self.blinding_factor
    }
}
