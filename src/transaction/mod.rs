use crate::{
    rpc, utils, zk::gadgets, zk::value::gen_cs_transcript, CompressedRistretto, Error,
    LinearCombination, Note, NoteGenerator, NoteUtxoType, Prover, PublicKey, R1CSProof, Scalar,
    SecretKey, TransparentNote, Variable, Verifier, MAX_NOTES_PER_TRANSACTION,
};

use std::convert::TryFrom;

use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use tracing::trace;

pub use item::TransactionItem;

/// Transaction item definitions
pub mod item;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Default)]
/// A phoenix transaction
pub struct Transaction {
    fee: TransactionItem,
    items: Vec<TransactionItem>,
    r1cs: Option<R1CSProof>,
    commitments: Vec<CompressedRistretto>,
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        self.fee == other.fee
            && self.items == other.items
            && self.commitments == other.commitments
            && self.r1cs.as_ref().map(|r| r.to_bytes()).unwrap_or_default()
                == other
                    .r1cs
                    .as_ref()
                    .map(|r| r.to_bytes())
                    .unwrap_or_default()
    }
}
impl Eq for Transaction {}

impl Transaction {
    /// Hash the transaction to a [`Scalar`]
    pub fn hash(&self) -> Scalar {
        let mut hasher = Sha512::default();

        hasher.input(&self.fee.value().to_le_bytes()[..]);

        self.items
            .iter()
            .for_each(|i| hasher.input(i.hash().as_bytes()));
        (self.items.len()..MAX_NOTES_PER_TRANSACTION)
            .for_each(|_| hasher.input(Scalar::one().as_bytes()));

        if let Some(proof) = self.r1cs.as_ref() {
            hasher.input(proof.to_bytes());
        } else {
            hasher.input(Scalar::one().as_bytes());
        }

        self.commitments
            .iter()
            .for_each(|c| hasher.input(c.as_bytes()));
        (self.commitments.len()..MAX_NOTES_PER_TRANSACTION)
            .for_each(|_| hasher.input(Scalar::one().as_bytes()));

        Scalar::from_hash(hasher)
    }

    /// Append a transaction item to the transaction.
    ///
    /// No validation is performed
    pub fn push(&mut self, item: TransactionItem) {
        self.items.push(item);
    }

    /// Return the fee value.
    ///
    /// A transaction is created with a random public key for the fee. The pre-image of the fee
    /// note is not validated on the r1cs circuit, so the public key can later be changed by a
    /// block generator
    pub fn fee(&self) -> &TransactionItem {
        &self.fee
    }

    /// Set the fee value.
    pub fn set_fee(&mut self, fee: TransactionItem) {
        self.fee = fee;
    }

    /// Set the public key of a block generator. This will not affect the r1cs proof
    pub fn set_fee_pk(&mut self, _pk: &PublicKey) {
        // TODO - Set the PK of the miner
    }

    /// Reference to the transaction items
    pub fn items(&self) -> &Vec<TransactionItem> {
        &self.items
    }

    /// Remove a specific item from the transaction. Internally calls the `Vec::remove` method
    pub fn remove_item(&mut self, index: usize) {
        if index < self.items.len() {
            self.items.remove(index);
        }
    }

    /// R1cs proof circuit. The circuit is created with [`Transaction::prove`], and depends on the
    /// correct secrets set on the transaction items.
    ///
    /// These secrets are obfuscate on propagation
    pub fn r1cs(&self) -> Option<&R1CSProof> {
        self.r1cs.as_ref()
    }

    /// Replace the r1cs proof circuit
    pub fn set_r1cs(&mut self, r1cs: R1CSProof) {
        self.r1cs.replace(r1cs);
    }

    /// Commitment points of the proved transaction. Created by [`Transaction::prove`]
    pub fn commitments(&self) -> &Vec<CompressedRistretto> {
        &self.commitments
    }

    /// Commitment points of the r1cs circuit
    pub fn set_commitments(&mut self, commitments: Vec<CompressedRistretto>) {
        self.commitments = commitments;
    }

    /// Perform the zk proof, and save internally the created r1cs circuit and the commitment
    /// points.
    ///
    /// Depends on the secret data of the transaction items
    ///
    /// The transaction items will be sorted for verification correctness
    pub fn prove(&mut self) -> Result<(), Error> {
        if self.items().len() > MAX_NOTES_PER_TRANSACTION {
            return Err(Error::MaximumNotes);
        }

        self.items.sort();

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

        let items_with_value_commitments = self
            .items()
            .iter()
            .map(|item| {
                let value = item.value();
                let value = Scalar::from(value);
                let blinding_factor = *item.blinding_factor();

                let (_, var) = prover.commit(value, blinding_factor);
                let lc: LinearCombination = var.into();

                (item, lc)
            })
            .collect::<Vec<(&TransactionItem, LinearCombination)>>();

        gadgets::transaction_balance(&mut prover, items_with_value_commitments, output);

        let proof = prover.prove(&bp_gens).map_err(Error::from)?;

        self.r1cs = Some(proof);
        self.commitments = commitments;

        Ok(())
    }

    /// Verify a previously proven transaction with [`Transaction::prove`].
    ///
    /// Doesn't depend on the transaction items secret data. Depends only on the constructed
    /// circuit and commitment points.
    ///
    /// The transaction items will be sorted for verification correctness
    pub fn verify(&mut self) -> Result<(), Error> {
        let proof = self.r1cs.as_ref().ok_or(Error::TransactionNotPrepared)?;

        self.items.sort();

        let (pc_gens, bp_gens, mut transcript) = gen_cs_transcript();
        let mut verifier = Verifier::new(&mut transcript);

        let mut commits = self.commitments.iter();
        self.items().iter().for_each(|item| {
            let var = commits
                .next()
                .map(|point| verifier.commit(*point))
                .unwrap_or(Variable::One());

            let (_, x) = item.note().zk_preimage();
            gadgets::note_preimage(&mut verifier, var.into(), x.into());
        });

        let output: LinearCombination = verifier.commit(*self.fee.note().commitment()).into();

        let items_with_value_commitments = self
            .items()
            .iter()
            .map(|item| {
                let commitment = *item.note().commitment();

                let var = verifier.commit(commitment);
                let lc: LinearCombination = var.into();

                (item, lc)
            })
            .collect::<Vec<(&TransactionItem, LinearCombination)>>();

        gadgets::transaction_balance(&mut verifier, items_with_value_commitments, output);

        verifier
            .verify(proof, &pc_gens, &bp_gens, &mut OsRng)
            .map_err(Error::from)
    }

    /// Create a new transaction from a set of inputs/outputs defined by a rpc source.
    ///
    /// Will prove and verify the created transaction.
    pub fn try_from_rpc_io(
        db_path: &'static str,
        fee_value: u64,
        inputs: Vec<rpc::TransactionInput>,
        outputs: Vec<rpc::TransactionOutput>,
    ) -> Result<Self, Error> {
        let mut transaction = Transaction::default();

        for i in inputs {
            let input = TransactionItem::try_from_rpc_transaction_input(db_path, i)?;
            trace!("Pushing {} dusk as input to the transaction", input.value());
            transaction.push(input);
        }
        for o in outputs {
            let output = TransactionItem::try_from(o)?;
            trace!(
                "Pushing {} dusk as output to the transaction",
                output.value()
            );
            transaction.push(output);
        }

        let pk = PublicKey::default();
        trace!("Pushing {} dusk as fee to the transaction", fee_value);
        let (fee, blinding_factor) = TransparentNote::output(&PublicKey::default(), fee_value);
        let fee = fee.to_transaction_output(fee_value, blinding_factor, pk);
        transaction.set_fee(fee);

        transaction.prove()?;
        transaction.verify()?;

        Ok(transaction)
    }

    /// Attempt to create a transaction from a rpc request.
    ///
    /// If there is a r1cs proof present on the request, will attempt to verify it against the
    /// proof.
    pub fn try_from_rpc_transaction(
        db_path: &'static str,
        tx: rpc::Transaction,
    ) -> Result<Self, Error> {
        let mut transaction = Transaction::default();

        if let Some(f) = tx.fee {
            transaction.set_fee(TransactionItem::try_from(f)?);
        }

        for i in tx.inputs {
            transaction.push(TransactionItem::try_from_rpc_transaction_input(db_path, i)?);
        }
        for o in tx.outputs {
            transaction.push(TransactionItem::try_from(o)?);
        }

        transaction.commitments = tx.commitments.into_iter().map(|p| p.into()).collect();
        transaction.r1cs = if tx.r1cs.is_empty() {
            None
        } else {
            Some(R1CSProof::from_bytes(tx.r1cs.as_slice())?)
        };

        trace!(
            "Transaction {} parsed",
            hex::encode(transaction.hash().as_bytes())
        );

        if transaction.r1cs.is_some() {
            transaction.verify()?;
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

        let r1cs = self.r1cs.map(|p| p.to_bytes()).unwrap_or_default();
        let commitments = self.commitments.iter().map(|p| (*p).into()).collect();

        rpc::Transaction {
            inputs,
            outputs,
            fee,
            r1cs,
            commitments,
        }
    }
}
