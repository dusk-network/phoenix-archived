use crate::{
    rpc, utils, zk::gadgets, zk::value::gen_cs_transcript, CompressedRistretto, ConstraintSystem,
    Db, Error, LinearCombination, NoteGenerator, NoteUtxoType, Prover, PublicKey, R1CSProof,
    Scalar, SecretKey, TransparentNote, Variable, Verifier,
};

use std::convert::TryFrom;

pub use item::TransactionItem;

pub mod item;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Default)]
pub struct Transaction {
    fee: TransactionItem,
    items: Vec<TransactionItem>,
}

impl Transaction {
    pub fn push(&mut self, item: TransactionItem) {
        self.items.push(item);
    }

    pub fn fee(&self) -> &TransactionItem {
        &self.fee
    }

    pub fn set_fee(&mut self, fee: TransactionItem) {
        self.fee = fee;
    }

    pub fn set_fee_pk(&mut self, _pk: &PublicKey) {
        // TODO - Set the PK of the miner
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
                    NoteUtxoType::Input => input += item.value(),
                    NoteUtxoType::Output => output += item.value(),
                };

                (input, output)
            });
        if output > input {
            return Err(Error::FeeOutput);
        }
        let fee_value = input - output;
        // The miner spending key will be defined later by the block generator
        let sk = SecretKey::default();
        let pk = sk.public_key();
        let (fee, blinding_factor) = TransparentNote::output(&sk.public_key(), fee_value);
        let fee = fee.to_transaction_output(fee_value, blinding_factor, pk);

        // Commit the fee to the circuit
        let (_, var) = prover.commit(
            Scalar::from(fee_value),
            fee.note().blinding_factor(&sk.view_key()),
        );
        let output: LinearCombination = var.into();
        self.fee = fee;

        // TODO - Refactor into gadgets
        let (input, output) = self.items().iter().fold(
            (LinearCombination::default(), output),
            |(mut input, mut output), item| {
                let value = item.value();
                let value = Scalar::from(value);
                let utxo = item.note().utxo();
                let blinding_factor = *item.blinding_factor();

                let (_, var) = prover.commit(value, blinding_factor);
                let lc: LinearCombination = var.into();

                match utxo {
                    NoteUtxoType::Input => {
                        let total = input.clone();
                        input = input.clone() + lc.clone();
                        prover.constrain(input.clone() - (total + lc));
                    }
                    NoteUtxoType::Output => {
                        let total = output.clone();
                        output = output.clone() + lc.clone();
                        prover.constrain(output.clone() - (total + lc));
                    }
                }

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
        commitments: &[CompressedRistretto],
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

        let output: LinearCombination = verifier.commit(*self.fee.note().commitment()).into();

        // TODO - Refactor into gadgets
        let (input, output) = self.items().iter().fold(
            (LinearCombination::default(), output),
            |(mut input, mut output), item| {
                let commitment = *item.note().commitment();
                let utxo = item.note().utxo();

                let var = verifier.commit(commitment);
                let lc: LinearCombination = var.into();

                match utxo {
                    NoteUtxoType::Input => {
                        let total = input.clone();
                        input = input.clone() + lc.clone();
                        verifier.constrain(input.clone() - (total + lc));
                    }
                    NoteUtxoType::Output => {
                        let total = output.clone();
                        output = output.clone() + lc.clone();
                        verifier.constrain(output.clone() - (total + lc));
                    }
                }

                (input, output)
            },
        );

        verifier.constrain(input - output);

        verifier
            .verify(&proof, &pc_gens, &bp_gens)
            .map_err(Error::from)
    }

    pub fn prepare(&mut self, db: &Db) -> Result<(), Error> {
        // Grant no nullifier exists for the inputs
        self.items.iter().try_fold((), |_, i| {
            if i.utxo() == NoteUtxoType::Input {
                let nullifier = i.nullifier();
                if db.fetch_nullifier(nullifier)?.is_some() {
                    return Err(Error::Generic);
                }
            }

            Ok(())
        })?;

        Ok(())
    }

    pub fn try_from_rpc_transaction(db: &Db, tx: rpc::Transaction) -> Result<Self, Error> {
        let mut transaction = Transaction::default();

        transaction.set_fee(TransactionItem::try_from(tx.fee.unwrap_or_default())?);

        for i in tx.inputs {
            transaction.push(TransactionItem::try_from_rpc_transaction_input(db, i)?);
        }
        for o in tx.outputs {
            transaction.push(TransactionItem::try_from(o)?);
        }

        Ok(transaction)
    }
}

impl Into<rpc::Transaction> for Transaction {
    fn into(self) -> rpc::Transaction {
        let mut inputs = vec![];
        let mut outputs = vec![];
        let fee = Some(self.fee.into());

        self.items.into_iter().for_each(|item| match item.utxo() {
            NoteUtxoType::Input => inputs.push(item.into()),
            NoteUtxoType::Output => outputs.push(item.into()),
        });

        rpc::Transaction {
            inputs,
            outputs,
            fee,
        }
    }
}
