use super::{NoteType, NoteUtxoType, PhoenixIdx, PhoenixNote};
use crate::{hash, utils, CompressedRistretto, PublicKey};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TransparentNote {
    utxo: NoteUtxoType,
    value: u64,
    r_p: CompressedRistretto,
    pk_r: CompressedRistretto,
    idx: PhoenixIdx,
}

impl TransparentNote {
    pub fn new(
        utxo: NoteUtxoType,
        value: u64,
        r_p: CompressedRistretto,
        pk_r: CompressedRistretto,
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
}

impl PhoenixNote for TransparentNote {
    fn utxo(&self) -> NoteUtxoType {
        self.utxo
    }

    fn note(&self) -> NoteType {
        NoteType::Transparent
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
            r_p.compress(),
            pk_r.compress(),
            PhoenixIdx::default(),
        )
    }
}
