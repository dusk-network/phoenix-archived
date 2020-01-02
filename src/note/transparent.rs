use super::{Idx, Note, NoteGenerator, NoteType, NoteUtxoType};
use crate::{
    crypto, utils, CompressedRistretto, Db, EdwardsPoint, Error, Nonce, PublicKey, Scalar, Value,
    ViewKey,
};

use std::cmp;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    fn output(pk: &PublicKey, value: u64) -> Self {
        let nonce = utils::gen_nonce();
        let (r, r_g, pk_r) = Self::generate_pk_r(pk);

        let idx = Idx::default();
        // TODO - Check if phoenix value should receive idx
        let phoenix_value = Value::new(idx, Scalar::from(value));
        let commitment = phoenix_value.commitment().clone();
        let encrypted_blinding_factor = TransparentNote::encrypt_blinding_factor(
            &r,
            pk,
            &nonce,
            phoenix_value.blinding_factor(),
        );

        TransparentNote::new(
            NoteUtxoType::Output,
            value,
            nonce,
            r_g,
            pk_r,
            Idx::default(),
            commitment,
            encrypted_blinding_factor,
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

    fn blinding_factor(&self, vk: &ViewKey) -> Scalar {
        let blinding_factor = crypto::decrypt(
            &self.r_g,
            vk,
            &self.nonce.increment_le(),
            self.encrypted_blinding_factor.as_slice(),
        );

        let mut s = [0x00u8; 32];
        let chunk = cmp::min(blinding_factor.len(), 32);
        (&mut s[0..chunk]).copy_from_slice(&blinding_factor[0..chunk]);

        Scalar::from_bits(s)
    }
}
