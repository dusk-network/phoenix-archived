use crate::{Error, Note, NoteUtxoType, ObfuscatedNote, PublicKey, TransparentNote};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Transaction {
    // TODO - Maybe use dyn implementation?
    input_transparent: Vec<TransparentNote>,
    input_obfuscated: Vec<ObfuscatedNote>,
    output_transparent: Vec<TransparentNote>,
    output_obfuscated: Vec<ObfuscatedNote>,
}

impl Transaction {
    pub fn push_transparent<N: Note>(&mut self, note: TransparentNote) {
        match note.utxo() {
            NoteUtxoType::Input => self.input_transparent.push(note),
            NoteUtxoType::Output => self.output_transparent.push(note),
        }
    }

    pub fn push_obfuscated<N: Note>(&mut self, note: ObfuscatedNote) {
        match note.utxo() {
            NoteUtxoType::Input => self.input_obfuscated.push(note),
            NoteUtxoType::Output => self.output_obfuscated.push(note),
        }
    }

    pub fn prepare(mut self, miner_pk: &PublicKey) -> Self {
        // TODO - Write the logic to create the transaction fee / gas cost
        self.output_transparent
            .push(TransparentNote::output(miner_pk, 1));
        self
    }

    pub fn validate(self) -> Result<Self, Error> {
        // TODO - Grant no nullifier exists for input_transparent
        // TODO - Grant no nullifier exists for input_obfuscated

        let _input: u64 = self.input_transparent.iter().map(|n| n.value()).sum();
        let _output: u64 = self.output_transparent.iter().map(|n| n.value()).sum();

        // TODO - Apply a homomorphic sum from input to input_obfuscated
        // TODO - Apply a homomorphic sum from output to output_obfuscated
        // TODO - Grant the sum input_obfuscated = output_obfuscated

        Ok(self)
    }

    pub fn execute(self) -> Result<(), Error> {
        // TODO - Write all notes to the chain
        // TODO - Write the nullifiers to the storage
        Ok(())
    }
}
