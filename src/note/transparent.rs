use super::{Idx, Note, NoteGenerator, NoteType, NoteUtxoType};
use crate::{Db, Error, PublicKey, RistrettoPoint};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    fn input(db: &Db, idx: &Idx) -> Result<Self, Error> {
        db.fetch_note(idx)
    }

    fn output(pk: &PublicKey, value: u64) -> Self {
        let (r_p, pk_r) = Self::generate_pk_r(pk);

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

    fn set_utxo(&mut self, utxo: NoteUtxoType) {
        self.utxo = utxo;
    }

    fn note(&self) -> NoteType {
        NoteType::Transparent
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

    fn value(&self) -> u64 {
        self.value
    }
}
