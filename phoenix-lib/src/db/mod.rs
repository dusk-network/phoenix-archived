use crate::{
    Error, Idx, Note, NoteUtxoType, NoteVariant, Nullifier, Scalar, Transaction, TransactionItem,
};

use kelvin::{annotations::Count, Blake2b, Map as _};
use kelvin_hamt::CountingHAMTMap as HAMTMap;
use kelvin_radix::DefaultRadixMap as RadixMap;

use tracing::trace;

#[cfg(test)]
mod tests;

/// Database structure for the notes and nullifiers storage
pub struct Db {
    // TODO - HashMap and HashSet implementation to emulate KVS. Use Kelvin?
    notes: HAMTMap<Idx, NoteVariant, Blake2b>,
    nullifiers: RadixMap<Nullifier, (), Blake2b>,
}

impl Db {
    /// [`Db`] constructor
    pub fn new() -> Result<Self, Error> {
        Ok(Db {
            notes: HAMTMap::new(),
            nullifiers: RadixMap::new(),
        })
    }

    // TODO - Should be able to rollback state in case of failure
    /// Store a provided [`Transaction`]. Return the position of the note on the tree.
    pub fn store(&mut self, transaction: &Transaction) -> Result<Vec<Idx>, Error> {
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

    // TODO - Should be able to rollback state in case of failure
    /// Store a set of [`Transaction`]. Return a set of positions of the included notes.
    pub fn store_bulk_transactions(
        &mut self,
        transactions: &[Transaction],
    ) -> Result<Vec<Idx>, Error> {
        let mut idx = vec![];

        for t in transactions {
            trace!("Storing tx {}", hex::encode(t.hash().as_bytes()));
            idx.extend(self.store(t)?);
        }

        Ok(idx)
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
    pub fn fetch_nullifier(&self, nullifier: &Nullifier) -> Result<Option<()>, Error> {
        Ok(self.nullifiers.get(nullifier)?.map(|d| *d))
    }

    pub fn notes(&self) -> &HAMTMap<Idx, NoteVariant, Blake2b> {
        &self.notes
    }
}
