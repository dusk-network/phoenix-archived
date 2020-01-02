use crate::{
    utils, zk::gadgets, zk::value::gen_cs_transcript, CompressedRistretto, ConstraintSystem, Db,
    Error, LinearCombination, Note, NoteGenerator, NoteUtxoType, Nullifier, Prover, R1CSProof,
    Scalar, SecretKey, TransparentNote, Variable, Verifier, ViewKey,
};

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct TransactionItem {
    note: Box<dyn Note>,
    vk: ViewKey,
    nullifier: Option<Nullifier>,
}

impl Default for TransactionItem {
    fn default() -> Self {
        let note = TransparentNote::default();
        let vk = ViewKey::default();

        TransactionItem::new(note, vk, None)
    }
}

impl TransactionItem {
    pub fn new<N: Note>(note: N, vk: ViewKey, nullifier: Option<Nullifier>) -> Self {
        TransactionItem {
            note: note.box_clone(),
            vk,
            nullifier,
        }
    }

    pub fn value(&self) -> u64 {
        self.note.value(Some(&self.vk))
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

    pub fn calculate_fee(&mut self, miner_vk: &ViewKey) {
        // TODO - Generate the proper fee value
        self.fee = Some(
            TransparentNote::output(&miner_vk.public_key(), 1).to_transaction_output(*miner_vk),
        );
    }

    pub fn fee(&self) -> Option<&TransactionItem> {
        self.fee.as_ref()
    }

    pub fn items(&self) -> &Vec<TransactionItem> {
        &self.items
    }

    // TODO - Generate a proper structure for the proof + commitments
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

        // Set transaction fee to the difference between the sums
        let (input, output) = self
            .items()
            .iter()
            .fold((0, 0), |(mut input, mut output), item| {
                let utxo = item.note().utxo();

                match utxo {
                    NoteUtxoType::Input => input += item.note().value(Some(&item.vk)),
                    NoteUtxoType::Output => output += item.note().value(Some(&item.vk)),
                };

                (input, output)
            });
        if output > input {
            return Err(Error::FeeOutput);
        }
        let fee_value = input - output;
        // The miner spending key will be defined later by the block generator
        let sk = SecretKey::default();
        // TODO - Miner rewards should always be transparent?
        let fee = TransparentNote::output(&sk.public_key(), fee_value);
        let fee = fee.to_transaction_output(sk.view_key());
        self.fee.replace(fee);
        let output: LinearCombination = Scalar::from(fee_value).into();

        let (input, output) = self.items().iter().fold(
            (LinearCombination::default(), output),
            |(mut input, mut output), item| {
                let value = item.note().value(Some(&item.vk));
                let utxo = item.note().utxo();

                let (_, var) = match utxo {
                    NoteUtxoType::Input => {
                        prover.commit(Scalar::from(value), utils::gen_random_scalar())
                    }
                    NoteUtxoType::Output => prover.commit(
                        Scalar::from(value),
                        // TODO - Obfuscated notes produce only one commitment point, should not be
                        // Vec
                        item.note().blinding_factors(&item.vk)[0],
                    ),
                };

                let var: LinearCombination = var.into();

                // TODO - Very inneficient, maybe redo lc operator handlers in bulletproofs
                match utxo {
                    NoteUtxoType::Input => input = input.clone() + var,
                    NoteUtxoType::Output => output = input.clone() + var,
                };

                (input, output)
            },
        );

        prover.constrain(input - output);

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

        let fee = self.fee.as_ref().map(|f| f.value()).unwrap_or(0);
        let output: LinearCombination = Scalar::from(fee).into();

        /*
        let (input, output) = self.items().iter().fold(
            (LinearCombination::default(), output),
            |(mut input, mut output), item| {
                let value = item.note().value(Some(&item.vk));
                let utxo = item.note().utxo();

                let (_, var) = match utxo {
                    NoteUtxoType::Input => {
                        prover.commit(Scalar::from(value), utils::gen_random_scalar())
                    }
                    NoteUtxoType::Output => prover.commit(
                        Scalar::from(value),
                        item.note().blinding_factors(&item.vk)[0],
                    ),
                };

                let var: LinearCombination = var.into();

                // TODO - Very inneficient, maybe redo lc operator handlers in bulletproofs
                match utxo {
                    NoteUtxoType::Input => input = input.clone() + var,
                    NoteUtxoType::Output => output = input.clone() + var,
                };

                (input, output)
            },
        );
        */

        verifier
            .verify(&proof, &pc_gens, &bp_gens)
            .map_err(Error::from)
    }

    pub fn prepare(&mut self, db: &Db) -> Result<(), Error> {
        let _fee = match &self.fee {
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

        Ok(())
    }
}
