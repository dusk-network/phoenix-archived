use super::{NoteType, NoteUtxoType, PhoenixIdx, PhoenixNote};
use crate::{hash, utils, PublicKey, RistrettoPoint};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
// TODO - Serialization and deserialization should be based on compressed points
pub struct TransparentNote {
    utxo: NoteUtxoType,
    value: u64,
    r_p: RistrettoPoint,
    pk_r: RistrettoPoint,
    idx: PhoenixIdx,
}

impl TransparentNote {
    pub fn new(
        utxo: NoteUtxoType,
        value: u64,
        r_p: RistrettoPoint,
        pk_r: RistrettoPoint,
        idx: PhoenixIdx,
    ) -> Self {
        TransparentNote {
            utxo,
            value,
            r_p,
            pk_r,
            idx,
        }
    }

    pub fn value(&self) -> u64 {
        self.value
    }
}

impl PhoenixNote for TransparentNote {
    fn utxo(&self) -> NoteUtxoType {
        self.utxo
    }

    fn note(&self) -> NoteType {
        NoteType::Transparent
    }

    fn idx(&self) -> &PhoenixIdx {
        &self.idx
    }

    fn output(pk: &PublicKey, value: u64) -> Self {
        // TODO - Grant r is in Fp
        let r = utils::gen_random_scalar();
        let r_p = utils::scalar_to_field(&r);
        let a_p = pk.a_p;
        let b_p = pk.b_p;
        let pk_r = hash::hash_in_p(&r * &a_p) + b_p;

        TransparentNote::new(
            NoteUtxoType::Output,
            value,
            r_p,
            pk_r,
            PhoenixIdx::default(),
        )
    }

    fn set_idx(mut self, idx: PhoenixIdx) -> Self {
        self.idx = idx;
        self
    }
}
