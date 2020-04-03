use crate::{
    crypto, BlsScalar, Error, Note, NoteVariant, Nullifier, Transaction, TransactionItem,
    MAX_NOTES_PER_TRANSACTION,
};

use std::io;
use std::path::Path;

use bytehash::ByteHash;
use kelvin::annotations::Count;
use kelvin::{Blake2b, Content, Map as _, Root, Sink, Source};
use kelvin_hamt::CountingHAMTMap as HAMTMap;
use kelvin_radix::DefaultRadixMap as RadixMap;
use rand::Rng;
use tracing::trace;

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
    fn query_level(&self, _depth: u32, _idx: usize) -> [Option<BlsScalar>; crypto::ARITY] {
        // TODO - Implement
        let mut rng = rand::thread_rng();

        let mut leaves = [None; crypto::ARITY];
        leaves.iter_mut().for_each(|l| *l = rng.gen());

        leaves
    }
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

// TODO: for the following two functions, i needed to clone the
// data structure in question in order to be able to take the value
// out of this function without the compiler yelling at me.
// will need to investigate if this is the most optimal strategy.
/// Provided a position, return a strong typed note from the database
pub fn fetch_note<P: AsRef<Path>>(path: P, idx: u64) -> Result<NoteVariant, Error> {
    let root = Root::<_, Blake2b>::new(path.as_ref())?;
    let state: Db<_> = root.restore()?;

    state
        .notes
        .clone()
        .get(&idx)?
        .map(|n| n.clone())
        .ok_or(Error::Generic)
}

/// Verify the existence of a provided nullifier on the set
pub fn fetch_nullifier<P: AsRef<Path>>(
    path: P,
    nullifier: &Nullifier,
) -> Result<Option<()>, Error> {
    let root = Root::<_, Blake2b>::new(path.as_ref())?;
    let state: Db<_> = root.restore()?;

    state
        .nullifiers
        .clone()
        .get(nullifier)
        .map(|_| Some(()))
        .map_err(|e| e.into())
}

impl<H: ByteHash> Db<H> {
    pub fn store_transaction(
        &mut self,
        transaction: &Transaction,
    ) -> Result<[Option<u64>; MAX_NOTES_PER_TRANSACTION], Error> {
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
            .ok_or(Error::Generic)
    }

    /// Verify the existence of a provided nullifier on the set
    pub fn fetch_nullifier(self, nullifier: &Nullifier) -> Result<Option<()>, Error> {
        self.nullifiers
            .get(nullifier)
            .map(|_| Some(()))
            .map_err(|e| e.into())
    }
}
