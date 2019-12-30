use crate::{
    utils, zk::gadgets, zk::value::gen_cs_transcript, CompressedRistretto, Db, Error, Note,
    NoteGenerator, NoteUtxoType, Nullifier, Prover, PublicKey, R1CSProof, TransparentNote,
    Variable, Verifier,
};

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct TransactionItem {
    note: Box<dyn Note>,
    nullifier: Option<Nullifier>,
    value: Option<u64>,
}

impl TransactionItem {
    pub fn new<N: Note>(note: N, nullifier: Option<Nullifier>, value: Option<u64>) -> Self {
        TransactionItem {
            note: note.box_clone(),
            nullifier,
            value,
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
        self.fee = Some(TransparentNote::output(miner_pk, 1).to_transaction_output(1));
    }

    pub fn fee(&self) -> Option<&TransactionItem> {
        self.fee.as_ref()
    }

    pub fn items(&self) -> &Vec<TransactionItem> {
        &self.items
    }

    // TODO - Generate a proper structure for the proofs
    pub fn prove(&mut self) -> Result<(R1CSProof, Vec<CompressedRistretto>), Error> {
        let (pc_gens, bp_gens, mut transcript) = gen_cs_transcript();
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        // Commit and constrain the pre-image of the notes
        let commitments: Vec<CompressedRistretto> = self
            .items()
            .iter()
            .map(|item| {
                let (y, x) = item.note().zk_preimage();
                let (c, v) = prover.commit(y, utils::gen_random_scalar());
                gadgets::note_preimage(&mut prover, v.into(), x.into());
                c
            })
            .collect();

        let proof = prover.prove(&bp_gens).map_err(Error::from)?;

        Ok((proof, commitments))
    }

    pub fn verify(
        &self,
        proof: &R1CSProof,
        commitments: &Vec<CompressedRistretto>,
    ) -> Result<(), Error> {
        let (pc_gens, bp_gens, mut transcript) = gen_cs_transcript();
        let mut verifier = Verifier::new(&mut transcript);

        let mut commits = commitments.iter();
        self.items().iter().for_each(|item| {
            let var = commits
                .next()
                .map(|point| verifier.commit(*point))
                .unwrap_or(Variable::One());

            let (_, x) = item.note().zk_preimage();
            gadgets::note_preimage(&mut verifier, var.into(), x.into());
        });

        verifier
            .verify(&proof, &pc_gens, &bp_gens)
            .map_err(Error::from)
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
            NoteUtxoType::Output => sum.1 += i.value(),
        });
        let (input, output) = sum;

        // TODO - Apply a homomorphic sum from input to obfuscated input values
        // TODO - Apply a homomorphic sum from output to obfuscated output values
        if output > input {
            // TODO - Use the homomorphic sums instead
            return Err(Error::Generic);
        }

        // TODO - Generate an output with the remainer input - output

        Ok(())
    }
}
