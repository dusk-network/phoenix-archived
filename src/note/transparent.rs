use super::{Idx, Note, NoteGenerator, NoteType, NoteUtxoType};
use crate::{hash, utils, PublicKey, RistrettoPoint};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
// TODO - Serialization and deserialization should be based on compressed points
pub struct TransparentNote {
    utxo: NoteUtxoType,
    value: u64,
    r_p: RistrettoPoint,
    pk_r: RistrettoPoint,
    idx: Idx,
}

impl TransparentNote {
    pub fn new(
        utxo: NoteUtxoType,
        value: u64,
        r_p: RistrettoPoint,
        pk_r: RistrettoPoint,
        idx: Idx,
    ) -> Self {
        TransparentNote {
            utxo,
            value,
            r_p,
            pk_r,
            idx,
        }
    }
}

impl NoteGenerator for TransparentNote {
    fn input(_idx: &Idx) -> Self {
        unimplemented!()
    }

    fn output(pk: &PublicKey, value: u64) -> Self {
        // TODO - Grant r is in Fp
        let r = utils::gen_random_scalar();
        let r_p = utils::mul_by_basepoint(&r);
        let a_p = pk.a_p;
        let b_p = pk.b_p;
        let pk_r = hash::hash_in_p(&r * &a_p) + b_p;

        TransparentNote::new(NoteUtxoType::Output, value, r_p, pk_r, Idx::default())
    }
}

impl Note for TransparentNote {
    fn box_clone(&self) -> Box<dyn Note> {
        Box::new(self.clone())
    }

    fn utxo(&self) -> NoteUtxoType {
        self.utxo
    }

    fn note(&self) -> NoteType {
        NoteType::Transparent
    }

    fn idx(&self) -> &Idx {
        &self.idx
    }

    fn set_idx(&mut self, idx: Idx) {
        self.idx = idx;
    }

    fn value(&self) -> u64 {
        self.value
    }
}
