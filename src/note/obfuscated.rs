use super::{Idx, Note, NoteGenerator, NoteType, NoteUtxoType};
use crate::{
    crypto, CompressedRistretto, Db, Error, PublicKey, R1CSProof, RistrettoPoint, Scalar,
    SecretKey, Value,
};
use std::cmp;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
// TODO - Serialization and deserialization should be based on compressed points
pub struct ObfuscatedNote {
    utxo: NoteUtxoType,
    pub(crate) commitments: Vec<CompressedRistretto>,
    r_p: RistrettoPoint,
    pk_r: RistrettoPoint,
    idx: Idx,
    pub(crate) encrypted_value: Vec<u8>,
    pub(crate) encrypted_blinding_factors: Vec<u8>,
}

impl ObfuscatedNote {
    pub fn new(
        utxo: NoteUtxoType,
        commitments: Vec<CompressedRistretto>,
        r_p: RistrettoPoint,
        pk_r: RistrettoPoint,
        idx: Idx,
        encrypted_value: Vec<u8>,
        encrypted_blinding_factors: Vec<u8>,
    ) -> Self {
        ObfuscatedNote {
            utxo,
            commitments,
            r_p,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factors,
        }
    }

    fn encrypt_value(pk_r: &RistrettoPoint, value: u64) -> Vec<u8> {
        crypto::encrypt(pk_r, &value.to_le_bytes()[..])
    }

    fn decrypt_value(&self, sk: &SecretKey) -> u64 {
        let decrypt_value = crypto::decrypt(&sk.r_p(&self.r_p), self.encrypted_value.as_slice());

        let mut v = [0x00u8; 8];
        let chunk = cmp::max(decrypt_value.len(), 8);
        (&mut v[0..chunk]).copy_from_slice(&decrypt_value.as_slice()[0..chunk]);

        u64::from_le_bytes(v)
    }

    fn encrypt_blinding_factors(pk_r: &RistrettoPoint, blinding_factors: &[Scalar]) -> Vec<u8> {
        let blinding_factors = blinding_factors
            .iter()
            .map(|s| &s.as_bytes()[..])
            .flatten()
            .map(|b| *b)
            .collect::<Vec<u8>>();

        crypto::encrypt(&pk_r, blinding_factors)
    }

    fn decrypt_blinding_factors(&self, sk: &SecretKey) -> Vec<Scalar> {
        crypto::decrypt(
            &sk.r_p(&self.r_p),
            self.encrypted_blinding_factors.as_slice(),
        )
        .as_slice()
        .chunks(32)
        .map(|b| {
            let mut s = [0x00u8; 32];
            let chunk = cmp::max(b.len(), 32);
            (&mut s[0..chunk]).copy_from_slice(&b[0..chunk]);
            Scalar::from_bits(s)
        })
        .collect()
    }
}

impl NoteGenerator for ObfuscatedNote {
    fn input(db: &Db, idx: &Idx) -> Result<Self, Error> {
        db.fetch_note(idx)
    }

    fn output(pk: &PublicKey, value: u64) -> Self {
        let (r_p, pk_r) = Self::generate_pk_r(pk);

        let idx = Idx::default();
        let phoenix_value = Value::new(idx, Scalar::from(value));
        let commitments = phoenix_value.commitments().clone();

        let encrypted_value = ObfuscatedNote::encrypt_value(&pk_r, value);
        let encrypted_blinding_factors =
            ObfuscatedNote::encrypt_blinding_factors(&pk_r, phoenix_value.blinding_factors());

        ObfuscatedNote::new(
            NoteUtxoType::Output,
            commitments,
            r_p,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factors,
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

    fn r_p(&self) -> &RistrettoPoint {
        &self.r_p
    }

    fn pk_r(&self) -> &RistrettoPoint {
        &self.pk_r
    }

    fn set_idx(&mut self, idx: Idx) {
        self.idx = idx;
    }

    fn prove_value(&self, sk_r: &SecretKey) -> Result<R1CSProof, Error> {
        let value = self.decrypt_value(sk_r);
        let blinding_factors = self.decrypt_blinding_factors(sk_r);

        let phoenix_value = Value::with_blinding_factors(self.idx, value, blinding_factors);

        phoenix_value.prove(value).map_err(Error::generic)
    }

    fn verify_value(&self, proof: &R1CSProof) -> Result<(), Error> {
        Value::with_commitments(self.commitments.clone())
            .verify(proof)
            .map_err(Error::generic)
    }
}
