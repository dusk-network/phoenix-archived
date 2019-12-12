use super::{NoteType, NoteUtxoType, PhoenixNote};
use crate::{CompressedRistretto, Error, PublicKey};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscatedNote<K: Default> {
    utxo: NoteUtxoType,
    commitments: Vec<CompressedRistretto>,
    r_p: CompressedRistretto,
    pk_r: CompressedRistretto,
    idx: K,
    encrypted_value: Vec<u8>,
    encrypted_blinding_factors: Vec<u8>,
}

impl<K: Default> PhoenixNote for ObfuscatedNote<K> {
    fn utxo(&self) -> NoteUtxoType {
        self.utxo
    }

    fn note(&self) -> NoteType {
        NoteType::Obfuscated
    }

    fn output(_pk: &PublicKey, _value: u64) -> Result<Self, Error> {
        unimplemented!()
    }
}
