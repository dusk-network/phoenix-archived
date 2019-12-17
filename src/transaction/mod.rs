use crate::{Db, Error, Note, NoteGenerator, NoteUtxoType, Nullifier, PublicKey, TransparentNote};

#[derive(Debug)]
pub struct TransactionItem {
    utxo: NoteUtxoType,
    note: Box<dyn Note>,
    nullifier: Nullifier,
}

impl TransactionItem {
    pub fn new<N: Note>(utxo: NoteUtxoType, note: N, nullifier: Nullifier) -> Self {
        TransactionItem {
            utxo,
            note: note.box_clone(),
            nullifier,
        }
    }

    pub fn value(&self) -> u64 {
        self.note.value()
    }

    pub fn note(&self) -> Box<dyn Note> {
        self.note.box_clone()
    }

    pub fn nullifier(&self) -> Nullifier {
        self.nullifier.clone()
    }
}

#[derive(Debug)]
pub struct Transaction {
    fee: Option<TransactionItem>,
    items: Vec<TransactionItem>,
}

impl Transaction {
    pub fn push(&mut self, item: TransactionItem) {
        self.items.push(item);
    }

    pub fn fee(&self) -> Option<&TransactionItem> {
        self.fee.as_ref()
    }

    pub fn items(&self) -> &Vec<TransactionItem> {
        &self.items
    }

    pub fn prepare(&mut self, db: &Db, miner_pk: &PublicKey) -> Result<(), Error> {
        // TODO - Generate the proper fee value
        let fee = TransparentNote::output(miner_pk, 1);
        self.fee = Some(TransactionItem::new(
            NoteUtxoType::Output,
            fee,
            Nullifier::default(),
        ));

        // Grant no nullifier exists for the inputs
        self.items.iter().try_fold((), |_, i| {
            if i.utxo == NoteUtxoType::Input {
                if db.fetch_nullifier(&i.nullifier)?.is_some() {
                    return Err(Error::Generic);
                }
            }

            Ok(())
        })?;

        let mut sum = (0, 0);
        self.items.iter().for_each(|i| match i.utxo {
            NoteUtxoType::Input => sum.0 += i.value(),
            NoteUtxoType::Output => sum.1 += i.value(),
        });
        let (_input, _output) = sum;

        // TODO - Apply a homomorphic sum from input to obfuscated input values
        // TODO - Apply a homomorphic sum from output to obfuscated output values
        // TODO - Return Error::Generic if input != output

        Ok(())
    }
}
