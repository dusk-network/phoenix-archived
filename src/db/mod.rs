use crate::{Error, Idx, Note, Nullifier, Transaction};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

pub struct Db {
    // TODO - HashMap and HashSet implementation to emulate KVS. Use Kelvin?
    notes: Arc<Mutex<HashMap<Idx, Box<dyn Note>>>>,
    nullifiers: Arc<Mutex<HashSet<Nullifier>>>,
}

impl Db {
    pub fn store(&self, transaction: &Transaction) -> Result<Vec<Box<dyn Note>>, Error> {
        // TODO - Should be able to rollback state in case of failure
        transaction.items().iter().try_fold(vec![], |mut v, i| {
            v.push(self.store_note(i.note(), i.nullifier())?);

            Ok(v)
        })
    }

    pub fn store_note(
        &self,
        note: Box<dyn Note>,
        nullifier: Nullifier,
    ) -> Result<Box<dyn Note>, Error> {
        // TODO - Should be able to rollback state in case of failure
        note.validate_nullifier(&nullifier)?;

        let note = {
            let mut notes = self.notes.try_lock()?;
            let mut note = note.box_clone();

            let idx = Idx((notes.len() as u64) + 1);
            note.set_idx(idx);

            notes.insert(idx, note.box_clone());

            note
        };

        {
            let mut nullifiers = self.nullifiers.try_lock()?;
            nullifiers.insert(nullifier.clone());
        }

        Ok(note)
    }

    pub fn fetch_note(&self, idx: &Idx) -> Result<Box<dyn Note>, Error> {
        let notes = self.notes.try_lock()?;
        notes.get(idx).map(|n| n.box_clone()).ok_or(Error::Generic)
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
