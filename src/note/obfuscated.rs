use super::{Idx, Note, NoteGenerator, NoteType, NoteUtxoType};
use crate::{
    crypto, utils, CompressedRistretto, Db, EdwardsPoint, Error, Nonce, PublicKey, R1CSProof,
    Scalar, Value, ViewKey,
};

use std::cmp;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObfuscatedNote {
    utxo: NoteUtxoType,
    pub(crate) commitment: CompressedRistretto,
    nonce: Nonce,
    r_g: EdwardsPoint,
    pk_r: EdwardsPoint,
    idx: Idx,
    pub(crate) encrypted_value: Vec<u8>,
    pub(crate) encrypted_blinding_factor: Vec<u8>,
}

impl ObfuscatedNote {
    pub fn new(
        utxo: NoteUtxoType,
        commitment: CompressedRistretto,
        nonce: Nonce,
        r_g: EdwardsPoint,
        pk_r: EdwardsPoint,
        idx: Idx,
        encrypted_value: Vec<u8>,
        encrypted_blinding_factor: Vec<u8>,
    ) -> Self {
        ObfuscatedNote {
            utxo,
            commitment,
            nonce,
            r_g,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factor,
        }
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

impl NoteGenerator for ObfuscatedNote {
    fn input(db: &Db, idx: &Idx) -> Result<Self, Error> {
        db.fetch_note(idx)
    }

    fn output(pk: &PublicKey, value: u64) -> Self {
        let nonce = utils::gen_nonce();

        let (r, r_g, pk_r) = Self::generate_pk_r(pk);

        let idx = Idx::default();
        let phoenix_value = Value::new(idx, Scalar::from(value));
        let commitment = phoenix_value.commitment().clone();

        let encrypted_value = ObfuscatedNote::encrypt_value(&r, pk, &nonce, value);
        let encrypted_blinding_factor = ObfuscatedNote::encrypt_blinding_factor(
            &r,
            pk,
            &nonce,
            phoenix_value.blinding_factor(),
        );

        ObfuscatedNote::new(
            NoteUtxoType::Output,
            commitment,
            nonce,
            r_g,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factor,
        )
    }
}

impl Note for ObfuscatedNote {
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
        NoteType::Obfuscated
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

    fn value(&self, vk: Option<&ViewKey>) -> u64 {
        let vk = vk.map(|k| *k).unwrap_or(ViewKey::default());
        let decrypt_value =
            crypto::decrypt(&self.r_g, &vk, &self.nonce, self.encrypted_value.as_slice());

        let mut v = [0x00u8; 8];
        let chunk = cmp::max(decrypt_value.len(), 8);
        (&mut v[0..chunk]).copy_from_slice(&decrypt_value.as_slice()[0..chunk]);

        u64::from_le_bytes(v)
    }

    fn blinding_factor(&self, vk: &ViewKey) -> Scalar {
        let blinding_factor = crypto::decrypt(
            &self.r_g,
            vk,
            &self.nonce.increment_le(),
            self.encrypted_blinding_factor.as_slice(),
        );

        let mut s = [0x00u8; 32];
        let chunk = cmp::max(blinding_factor.len(), 32);
        (&mut s[0..chunk]).copy_from_slice(&blinding_factor[0..chunk]);

        Scalar::from_bits(s)
    }

    fn prove_value(&self, vk: &ViewKey) -> Result<R1CSProof, Error> {
        let value = self.value(Some(vk));
        let blinding_factor = self.blinding_factor(vk);

        let phoenix_value = Value::with_blinding_factor(self.idx, value, blinding_factor);

        phoenix_value.prove(value).map_err(Error::generic)
    }

    fn verify_value(&self, proof: &R1CSProof) -> Result<(), Error> {
        Value::with_commitment(self.commitment.clone())
            .verify(proof)
            .map_err(Error::generic)
    }
}
