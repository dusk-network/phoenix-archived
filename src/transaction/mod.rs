use crate::{Db, Error, Note, NoteGenerator, NoteUtxoType, Nullifier, PublicKey, TransparentNote};

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct TransactionItem {
    note: Box<dyn Note>,
    nullifier: Option<Nullifier>,
}

impl TransactionItem {
    pub fn new<N: Note>(note: N, nullifier: Option<Nullifier>) -> Self {
        TransactionItem {
            note: note.box_clone(),
            nullifier,
        }
    }

    pub fn value(&self) -> u64 {
        self.note.value()
    }

    pub fn utxo(&self) -> NoteUtxoType {
        self.note.utxo()
    }

    pub fn note(&self) -> Box<dyn Note> {
        self.note.box_clone()
    }

    pub fn nullifier(&self) -> Option<&Nullifier> {
        self.nullifier.as_ref()
    }
}

#[derive(Debug)]
pub struct Transaction {
    fee: Option<TransactionItem>,
    items: Vec<TransactionItem>,
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            fee: None,
            items: vec![],
        }
    }
}

impl Transaction {
    pub fn push(&mut self, item: TransactionItem) {
        self.items.push(item);
    }

    pub fn calculate_fee(&mut self, miner_pk: &PublicKey) {
        // TODO - Generate the proper fee value
        let fee = TransparentNote::output(miner_pk, 1);
        self.fee = Some(TransactionItem::new(fee, None));
    }

    pub fn fee(&self) -> Option<&TransactionItem> {
        self.fee.as_ref()
    }

    pub fn items(&self) -> &Vec<TransactionItem> {
        &self.items
    }

    pub fn prepare(&mut self, db: &Db) -> Result<(), Error> {
        let fee = match &self.fee {
            Some(f) => f,
            None => return Err(Error::FeeOutput),
        };

        // Grant no nullifier exists for the inputs
        self.items.iter().try_fold((), |_, i| {
            if i.utxo() == NoteUtxoType::Input {
                let nullifier = i.nullifier().ok_or(Error::Generic)?;
                if db.fetch_nullifier(nullifier)?.is_some() {
                    return Err(Error::Generic);
                }
            }

            Ok(())
        })?;

        let mut sum = (0, fee.value());
        self.items.iter().for_each(|i| match i.utxo() {
            NoteUtxoType::Input => sum.0 += i.value(),
            NoteUtxoType::Output => {
                sum.1 += i.value();
            }
        });
        let (input, output) = sum;

        // TODO - Apply a homomorphic sum from input to obfuscated input values
        // TODO - Apply a homomorphic sum from output to obfuscated output values
        //
        if output > input {
            // TODO - Use the homomorphic sums instead
            return Err(Error::Generic);
        }

        // TODO - Generate an output with the remainer input - output

        Ok(())
    }
}
