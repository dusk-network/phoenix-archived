use crate::{
    crypto, BlsScalar, Error, MerkleProofProvider, Note, NoteVariant, Nullifier, Transaction,
    TransactionItem, MAX_NOTES_PER_TRANSACTION,
};

use std::io;

use bytehash::ByteHash;
use kelvin::annotations::Count;
use kelvin::{Blake2b, Content, Sink, Source};
use kelvin_hamt::CountingHAMTMap as HAMTMap;
use kelvin_radix::DefaultRadixMap as RadixMap;
use tracing::trace;

/// Type used for notes storage
pub type NotesDb = Db<Blake2b>;
/// Type used for notes iterator
pub type NotesIter = DbNotesIterator<Blake2b>;

#[cfg(test)]
mod tests;

/// Database structure for the notes and nullifiers storage
#[derive(Clone)]
pub struct Db<H: ByteHash> {
    notes: HAMTMap<u64, NoteVariant, H>,
    nullifiers: RadixMap<Nullifier, (), H>,
}

impl<H: ByteHash> Default for Db<H> {
    fn default() -> Self {
        Db {
            notes: HAMTMap::default(),
            nullifiers: RadixMap::default(),
        }
    }
}

impl<H: ByteHash> Content<H> for Db<H> {
    fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
        self.notes.persist(sink)?;
        self.nullifiers.persist(sink)
    }

    fn restore(source: &mut Source<H>) -> io::Result<Self> {
        Ok(Db {
            notes: HAMTMap::restore(source)?,
            nullifiers: RadixMap::restore(source)?,
        })
    }
}

impl<H: ByteHash> crypto::MerkleProofProvider for Db<H> {
    fn query_level(
        &self,
        _depth: u32,
        _idx: usize,
    ) -> Result<[Option<BlsScalar>; crypto::ARITY], Error> {
        // TODO - Implement
        let mut rng = rand::thread_rng();

        let mut leaves = [None; crypto::ARITY];
        leaves
            .iter_mut()
            .for_each(|l| *l = Some(BlsScalar::random(&mut rng)));

        Ok(leaves)
    }

    fn root(&self) -> Result<BlsScalar, Error> {
        // TODO - Implement
        Ok(BlsScalar::random(&mut rand::thread_rng()))
    }
}

/// Generate a [`MerkleProof`] provided a note and a db path
pub fn merkle_opening(
    note: &NoteVariant,
    state: &Db<Blake2b>,
) -> Result<crypto::MerkleProof, Error> {
    state.opening(note)
}

/// Store a provided [`Transaction`]. Return the position of the note on the tree.
pub fn store(
    state: &mut Db<Blake2b>,
    transaction: &Transaction,
) -> Result<[Option<u64>; MAX_NOTES_PER_TRANSACTION], Error> {
    let v = state.store_transaction(transaction)?;

    Ok(v)
}

impl<H: ByteHash> Db<H> {
    pub fn new() -> Db<H> {
        Default::default()
    }

    pub fn store_transaction(
        &mut self,
        transaction: &Transaction,
    ) -> Result<[Option<u64>; MAX_NOTES_PER_TRANSACTION], Error> {
        transaction
            .inputs()
            .iter()
            .try_fold::<_, _, Result<_, Error>>(None, |_, i| {
                let n = *i.nullifier();

                self.fetch_nullifier(&n)?
                    .map(|_| Err(Error::DoubleSpending))
                    .unwrap_or(Ok(()))?;

                self.nullifiers.insert(n, ()).map_err(|e| e.into())
            })?;

        let mut idx = [None; MAX_NOTES_PER_TRANSACTION];

        let mut idx_iter = idx.iter_mut();

        let fee = transaction.fee();
        let fee = self.store_unspent_note(fee.note().clone())?;
        idx_iter.next().map(|i| i.replace(fee));

        transaction
            .outputs()
            .iter()
            .zip(idx_iter)
            .map(|(o, i)| {
                self.store_unspent_note(o.note().clone())
                    .map(|idx| i.replace(idx))?;

                Ok(())
            })
            .collect::<Result<_, Error>>()?;

        Ok(idx)
    }

    /// Store a set of [`Transaction`]. Return a set of positions of the included notes.
    pub fn store_bulk_transactions(
        &mut self,
        transactions: &[Transaction],
    ) -> Result<Vec<u64>, Error> {
        let mut idx = vec![];

        for t in transactions {
            trace!("Storing tx {}", t);
            self.store_transaction(t)?
                .iter()
                .filter_map(|i| i.as_ref())
                .for_each(|i| idx.push(*i));
        }

        Ok(idx)
    }

    /// Store a note. Return the position of the stored note on the tree.
    pub fn store_unspent_note(&mut self, mut note: NoteVariant) -> Result<u64, Error> {
        let idx = self.notes.count() as u64;

        note.set_idx(idx.clone());
        self.notes.insert(idx.clone(), note)?;

        Ok(idx)
    }

    /// Provided a position, return a strong typed note from the database
    pub fn fetch_note(&self, idx: u64) -> Result<NoteVariant, Error> {
        self.notes
            .get(&idx)?
            .map(|n| n.clone())
            .ok_or(Error::NotFound)
    }

    /// Verify the existence of a provided nullifier on the set
    pub fn fetch_nullifier(&self, nullifier: &Nullifier) -> Result<Option<()>, Error> {
        self.nullifiers
            .get(nullifier)
            .map(|n| n.map(|_| ()))
            .map_err(|e| e.into())
    }

    pub fn notes(self) -> HAMTMap<u64, NoteVariant, H> {
        self.notes
    }
}

// TODO - Very naive implementation, optimize to Kelvin
pub struct DbNotesIterator<H: ByteHash> {
    notes: HAMTMap<u64, NoteVariant, H>,
    cur: u64,
}

impl<H: ByteHash> From<&Db<H>> for DbNotesIterator<H> {
    fn from(db: &Db<H>) -> Self {
        let notes = db.notes.clone();
        let cur = 0;

        DbNotesIterator { notes, cur }
    }
}

impl<H: ByteHash> Iterator for DbNotesIterator<H> {
    type Item = NoteVariant;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.cur;
        self.cur += 1;

        match self.notes.get(&idx) {
            Ok(n) => n.map(|n| n.clone()),
            // TODO - Report error
            Err(_) => None,
        }
    }
}
