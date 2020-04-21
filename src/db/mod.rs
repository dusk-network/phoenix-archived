use crate::{
    crypto, crypto::MerkleProofProvider, BlsScalar, Error, Note, NoteVariant, Nullifier,
    Transaction, TransactionItem, MAX_NOTES_PER_TRANSACTION,
};

use std::convert::TryFrom;
use std::io;
use std::path::{Path, PathBuf};

use bytehash::ByteHash;
use kelvin::annotations::Count;
use kelvin::{Blake2b, Content, Root, Sink, Source};
use kelvin_hamt::CountingHAMTMap as HAMTMap;
use kelvin_radix::DefaultRadixMap as RadixMap;
use rand::Rng;
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
        leaves.iter_mut().for_each(|l| *l = rng.gen());

        Ok(leaves)
    }

    fn root(&self) -> Result<BlsScalar, Error> {
        // TODO - Implement
        Ok((&mut rand::thread_rng()).gen())
    }
}

/// Generate a [`MerkleProof`] provided a note and a db path
pub fn merkle_opening<P: AsRef<Path>>(
    path: P,
    note: &NoteVariant,
) -> Result<crypto::MerkleProof, Error> {
    let root = Root::<_, Blake2b>::new(path.as_ref())?;
    let state: Db<_> = root.restore()?;

    state.opening(note)
}

/// Store a provided [`Transaction`]. Return the position of the note on the tree.
pub fn store<P: AsRef<Path>>(
    path: P,
    transaction: &Transaction,
) -> Result<[Option<u64>; MAX_NOTES_PER_TRANSACTION], Error> {
    let mut root = Root::<_, Blake2b>::new(path.as_ref())?;
    let mut state: Db<_> = root.restore()?;

    let v = state.store_transaction(transaction)?;
    root.set_root(&mut state)?;

    Ok(v)
}

/// Store a set of [`Transaction`]. Return a set of positions of the included notes.
pub fn store_bulk_transactions<P: AsRef<Path>>(
    path: P,
    transactions: &[Transaction],
) -> Result<Vec<u64>, Error> {
    let mut root = Root::<_, Blake2b>::new(path.as_ref())?;
    let mut state: Db<_> = root.restore()?;
    let mut idx = vec![];

    for t in transactions {
        trace!("Storing tx {}", t);
        state
            .store_transaction(t)?
            .iter()
            .filter_map(|i| i.as_ref())
            .for_each(|i| idx.push(*i));
    }

    root.set_root(&mut state)?;

    Ok(idx)
}

/// Store a note. Return the position of the stored note on the tree.
pub fn store_unspent_note<P: AsRef<Path>>(path: P, note: NoteVariant) -> Result<u64, Error> {
    let mut root = Root::<_, Blake2b>::new(path.as_ref())?;
    let mut state: Db<_> = root.restore()?;

    let idx = state.store_unspent_note(note)?;

    root.set_root(&mut state)?;

    Ok(idx)
}

// TODO: for the following two functions, i needed to clone the
// data structure in question in order to be able to take the value
// out of this function without the compiler yelling at me.
// will need to investigate if this is the most optimal strategy.
/// Provided a position, return a strong typed note from the database
pub fn fetch_note<P: AsRef<Path>>(path: P, idx: u64) -> Result<NoteVariant, Error> {
    let root = Root::<_, Blake2b>::new(path.as_ref())?;
    let state: Db<_> = root.restore()?;

    state.fetch_note(idx)
}

/// Verify the existence of a provided nullifier on the set
pub fn fetch_nullifier<P: AsRef<Path>>(
    path: P,
    nullifier: &Nullifier,
) -> Result<Option<()>, Error> {
    let root = Root::<_, Blake2b>::new(path.as_ref())?;
    let state: Db<_> = root.restore()?;

    state.fetch_nullifier(nullifier)
}

/// Return the merkle root of the current state
pub fn root<P: AsRef<Path>>(path: P) -> Result<BlsScalar, Error> {
    let root = Root::<_, Blake2b>::new(path.as_ref())?;
    let state: Db<_> = root.restore()?;

    state.root()
}

impl<H: ByteHash> Db<H> {
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Db<H>, Error> {
        Ok(Root::<_, _>::new(db_path.as_ref()).and_then(|root| root.restore())?)
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

impl<H: ByteHash> TryFrom<PathBuf> for DbNotesIterator<H> {
    type Error = Error;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        let root = Root::<_, H>::new(&path)?;
        let state: Db<H> = root.restore()?;

        let notes = state.notes.clone();
        let cur = 0;

        Ok(DbNotesIterator { notes, cur })
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
