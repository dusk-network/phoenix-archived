use super::{Idx, Note, NoteGenerator, NoteType, NoteUtxoType};
use crate::{
    crypto, utils, CompressedRistretto, Db, EdwardsPoint, Error, Nonce, PublicKey, R1CSProof,
    Scalar, Value, ViewKey,
};

use std::cmp;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObfuscatedNote {
    utxo: NoteUtxoType,
    commitment: CompressedRistretto,
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
}

impl NoteGenerator for ObfuscatedNote {
    fn input(db: &Db, idx: &Idx) -> Result<Self, Error> {
        db.fetch_note(idx)
    }

    fn output(pk: &PublicKey, value: u64) -> (Self, Scalar) {
        let idx = Idx::default();
        let nonce = utils::gen_nonce();

        let (r, r_g, pk_r) = Self::generate_pk_r(pk);

        let phoenix_value = Value::new(Scalar::from(value));

        let blinding_factor = *phoenix_value.blinding_factor();
        let commitment = *phoenix_value.commitment();

        let encrypted_value = ObfuscatedNote::encrypt_value(&r, pk, &nonce, value);
        let encrypted_blinding_factor =
            ObfuscatedNote::encrypt_blinding_factor(&r, pk, &nonce, &blinding_factor);

        let note = ObfuscatedNote::new(
            NoteUtxoType::Output,
            commitment,
            nonce,
            r_g,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factor,
        );

        (note, blinding_factor)
    }
}

impl Note for ObfuscatedNote {
    fn hash(&self) -> Scalar {
        // TODO - Use poseidon sponge, when available
        let mut hasher = Sha512::default();

        hasher.input(&[self.utxo.into()]);
        hasher.input(self.commitment.as_bytes());
        hasher.input(&self.nonce);
        hasher.input(self.r_g.compress().as_bytes());
        hasher.input(self.pk_r.compress().as_bytes());
        hasher.input(self.idx.to_vec());
        hasher.input(&self.encrypted_value);
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
        let vk = vk.copied().unwrap_or_default();
        let decrypt_value =
            crypto::decrypt(&self.r_g, &vk, &self.nonce, self.encrypted_value.as_slice());

        let mut v = [0x00u8; 8];
        let chunk = cmp::min(decrypt_value.len(), 8);
        (&mut v[0..chunk]).copy_from_slice(&decrypt_value.as_slice()[0..chunk]);

        u64::from_le_bytes(v)
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

    fn prove_value(&self, vk: &ViewKey) -> Result<R1CSProof, Error> {
        let value = self.value(Some(vk));
        let blinding_factor = self.blinding_factor(vk);

        let phoenix_value = Value::with_blinding_factor(value, blinding_factor);

        phoenix_value.prove(value).map_err(Error::generic)
    }

    fn verify_value(&self, proof: &R1CSProof) -> Result<(), Error> {
        Value::with_commitment(*self.commitment())
            .verify(proof)
            .map_err(Error::generic)
    }
}
