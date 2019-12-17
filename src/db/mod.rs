use crate::{Error, Idx, Note, NoteUtxoType, Nullifier, Transaction};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

lazy_static::lazy_static! {
    static ref DB: Db = Db::new().expect("Failed to create the database!");
}

#[cfg(test)]
mod tests;

pub struct Db {
    // TODO - HashMap and HashSet implementation to emulate KVS. Use Kelvin?
    notes: Arc<Mutex<HashMap<Idx, Box<dyn Note>>>>,
    nullifiers: Arc<Mutex<HashSet<Nullifier>>>,
}

impl Db {
    pub fn new() -> Result<Self, Error> {
        Ok(Db {
            notes: Arc::new(Mutex::new(HashMap::new())),
            nullifiers: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub fn data() -> &'static Db {
        &*DB
    }

    pub fn store(&self, transaction: &Transaction) -> Result<Vec<Idx>, Error> {
        // TODO - Should be able to rollback state in case of failure
        let fee = transaction.fee().ok_or(Error::TransactionNotPrepared)?;

        let fee_idx = self.store_note(fee.note(), None)?.ok_or(Error::FeeOutput)?;
        let notes = vec![fee_idx];

        transaction.items().iter().try_fold(notes, |mut v, i| {
            let idx = self.store_note(i.note(), i.nullifier().cloned())?;
            if let Some(idx_inserted) = idx {
                v.push(idx_inserted);
            }

            Ok(v)
        })
    }

    /// Attempt to store the note.
    ///
    /// If it is an input note, only the nullifier will be stored and no new Idx will be returned.
    ///
    /// If it is an output note, only the note will be stored and the new Idx will be returned.
    pub fn store_note(
        &self,
        note: Box<dyn Note>,
        nullifier: Option<Nullifier>,
    ) -> Result<Option<Idx>, Error> {
        if note.utxo() == NoteUtxoType::Input {
            let nullifier = nullifier.ok_or(Error::Generic)?;

            note.validate_nullifier(&nullifier)?;
            let mut nullifiers = self.nullifiers.try_lock()?;
            nullifiers.insert(nullifier.clone());

            Ok(None)
        } else {
            self.store_unspent_note(note).map(|idx| Some(idx))
        }
    }

    pub fn store_unspent_note(&self, mut note: Box<dyn Note>) -> Result<Idx, Error> {
        let mut notes = self.notes.try_lock()?;

        let idx = Idx(notes.len() as u64);
        note.set_idx(idx);
        notes.insert(idx, note);

        Ok(idx)
    }

    pub fn fetch_note<N: Note>(&self, idx: &Idx) -> Result<N, Error> {
        let notes = self.notes.try_lock()?;
        let note = notes
            .get(idx)
            .map(|n| n.box_clone())
            .ok_or(Error::Generic)?;

        // TODO - As a temporary solution until Kelvin is implemented, using very unsafe code
        unsafe { Ok(Box::into_raw(note).cast::<N>().read()) }
    }

    pub fn fetch_nullifier(&self, nullifier: &Nullifier) -> Result<Option<()>, Error> {
        let nullifiers = self.nullifiers.try_lock()?;
        Ok(if nullifiers.contains(nullifier) {
            Some(())
        } else {
            None
        })
    }
}
