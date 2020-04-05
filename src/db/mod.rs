use crate::{
    Error, Idx, Note, NoteUtxoType, NoteVariant, Nullifier, Scalar, Transaction, TransactionItem,
};
use std::io;
use std::path::Path;

use bytehash::ByteHash;
use kelvin::{annotations::Count, Blake2b, Content, Map as _, Root, Sink, Source};
use kelvin_hamt::CountingHAMTMap as HAMTMap;
use kelvin_radix::DefaultRadixMap as RadixMap;

use tracing::trace;

#[cfg(test)]
mod tests;

/// Database structure for the notes and nullifiers storage
#[derive(Clone)]
pub struct Db<H: ByteHash> {
    notes: HAMTMap<Idx, NoteVariant, H>,
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

/// Store a provided [`Transaction`]. Return the position of the note on the tree.
pub fn store<P: AsRef<Path>>(path: P, transaction: &Transaction) -> Result<Vec<Idx>, Error> {
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
) -> Result<Vec<Idx>, Error> {
    let mut root = Root::<_, Blake2b>::new(path.as_ref())?;
    let mut state: Db<_> = root.restore()?;
    let mut idx = vec![];

    for t in transactions {
        trace!("Storing tx {}", hex::encode(t.hash().as_bytes()));
        idx.extend(state.store_transaction(t)?);
    }

    root.set_root(&mut state)?;
    Ok(idx)
}

// TODO: for the following two functions, i needed to clone the
// data structure in question in order to be able to take the value
// out of this function without the compiler yelling at me.
// will need to investigate if this is the most optimal strategy.
#[allow(clippy::trivially_copy_pass_by_ref)] // Idx
/// Provided a position, return a strong typed note from the database
pub fn fetch_note<P: AsRef<Path>>(path: P, idx: &Idx) -> Result<NoteVariant, Error> {
    let root = Root::<_, Blake2b>::new(path.as_ref())?;
    let state: Db<_> = root.restore()?;
    state
        .notes
        .clone()
        .get(idx)?
        .map(|n| n.clone())
        .ok_or(Error::Generic)
}

#[allow(clippy::trivially_copy_pass_by_ref)] // Nullifier
/// Verify the existence of a provided nullifier on the set
pub fn fetch_nullifier<P: AsRef<Path>>(
    path: P,
    nullifier: &Nullifier,
) -> Result<Option<()>, Error> {
    let root = Root::<_, Blake2b>::new(path.as_ref())?;
    let state: Db<_> = root.restore()?;
    Ok(state.nullifiers.clone().get(nullifier)?.map(|d| *d))
}

impl<H: ByteHash> Db<H> {
    pub fn store_transaction(&mut self, transaction: &Transaction) -> Result<Vec<Idx>, Error> {
        let fee = transaction.fee();
        let fee_idx = self.store_transaction_item(fee)?.ok_or(Error::FeeOutput)?;
        let notes = vec![fee_idx];

        transaction.items().iter().try_fold(notes, |mut v, i| {
            let idx = self.store_transaction_item(i)?;
            if let Some(idx_inserted) = idx {
                v.push(idx_inserted);
            }

            Ok(v)
        })
    }

    /// Return the current merkle root
    pub fn root(&self) -> Scalar {
        // TODO - Fetch the merkle root of the current db state
        Scalar::default()
    }

    /// Attempt to store a given transaction item.
    ///
    /// If its an unspent output, will return the idx of the stored note.
    pub fn store_transaction_item(&mut self, item: &TransactionItem) -> Result<Option<Idx>, Error> {
        if item.utxo() == NoteUtxoType::Input {
            let nullifier = *item.nullifier();
            item.note().validate_nullifier(&nullifier)?;

            self.nullifiers.insert(nullifier, ())?;

            Ok(None)
        } else {
            self.store_unspent_note(item.note().clone()).map(Some)
        }
    }

    /// Store a note. Return the position of the stored note on the tree.
    pub fn store_unspent_note(&mut self, mut note: NoteVariant) -> Result<Idx, Error> {
        let idx: Idx = (self.notes.count() as u64).into();
        note.set_idx(idx.clone());
        self.notes.insert(idx.clone(), note)?;

        Ok(idx)
    }

    #[allow(clippy::trivially_copy_pass_by_ref)] // Idx
    /// Provided a position, return a strong typed note from the database
    pub fn fetch_note(&self, idx: &Idx) -> Result<NoteVariant, Error> {
        self.notes
            .get(idx)?
            .map(|n| n.clone())
            .ok_or(Error::Generic)
    }

    #[allow(clippy::trivially_copy_pass_by_ref)] // Nullifier
    /// Verify the existence of a provided nullifier on the set
    pub fn fetch_nullifier(self, nullifier: &Nullifier) -> Result<Option<()>, Error> {
        Ok(self.nullifiers.get(nullifier)?.map(|d| *d))
    }

    pub fn notes(self) -> HAMTMap<Idx, NoteVariant, H> {
        self.notes
    }
}
