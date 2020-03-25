use crate::{
    crypto, rpc, utils, BlsScalar, Error, Note, NoteGenerator, PublicKey, TransparentNote,
    MAX_NOTES_PER_TRANSACTION,
};

use std::{fmt, ptr};

use num_traits::Zero;

//use crate::{
//    rpc, utils, zk::gadgets, zk::value::gen_cs_transcript, CompressedRistretto, Error,
//    LinearCombination, Note, NoteGenerator, NoteUtxoType, Prover, PublicKey, R1CSProof, Scalar,
//    SecretKey, TransparentNote, Variable, Verifier, MAX_NOTES_PER_TRANSACTION,
//};
//
//use std::convert::TryFrom;
//use std::path::Path;
//
//use rand::rngs::OsRng;
//use sha2::{Digest, Sha512};
//use tracing::trace;
//
pub use item::{TransactionInput, TransactionItem, TransactionOutput};
//
/// Transaction item definitions
pub mod item;
//
//#[cfg(test)]
//mod tests;
//
/// A phoenix transaction
#[derive(Debug, Clone, Default)]
pub struct Transaction {
    fee: TransactionOutput,
    idx_inputs: usize,
    inputs: [TransactionInput; MAX_NOTES_PER_TRANSACTION],
    idx_outputs: usize,
    outputs: [TransactionOutput; MAX_NOTES_PER_TRANSACTION],
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash().eq(&other.hash())
    }
}
impl Eq for Transaction {}

impl Transaction {
    /// Perform a hash of the inputs, outputs and fee
    pub fn hash(&self) -> BlsScalar {
        // TODO - Maybe improve?

        let mut hash = [BlsScalar::zero(); 2 * MAX_NOTES_PER_TRANSACTION + 1];
        let mut i = 1;

        hash[0] = self.fee.hash();

        let mut items = [TransactionInput::default(); MAX_NOTES_PER_TRANSACTION];

        let max_idx = self.idx_inputs;
        if max_idx > 0 {
            items.copy_from_slice(&self.inputs);
            (&mut items[0..max_idx]).sort();

            items[0..max_idx]
                .iter()
                .map(|item| item.note().hash())
                .for_each(|h| {
                    hash[i] = h;
                    i += 1;
                });
        }

        let mut items = [TransactionOutput::default(); MAX_NOTES_PER_TRANSACTION];

        let max_idx = self.idx_outputs;
        if max_idx > 0 {
            items.copy_from_slice(&self.outputs);
            (&mut items[0..max_idx]).sort();

            items[0..max_idx]
                .iter()
                .map(|item| item.note().hash())
                .for_each(|h| {
                    hash[i] = h;
                    i += 1;
                });
        }

        crypto::sponge_hash(&hash[0..i])
    }
    //    /// Hash the transaction to a [`Scalar`]
    //    pub fn hash(&self) -> Scalar {
    //        let mut hasher = Sha512::default();
    //
    //        hasher.input(&self.fee.value().to_le_bytes()[..]);
    //
    //        self.items
    //            .iter()
    //            .for_each(|i| hasher.input(i.hash().as_bytes()));
    //        (self.items.len()..MAX_NOTES_PER_TRANSACTION)
    //            .for_each(|_| hasher.input(Scalar::one().as_bytes()));
    //
    //        if let Some(proof) = self.r1cs.as_ref() {
    //            hasher.input(proof.to_bytes());
    //        } else {
    //            hasher.input(Scalar::one().as_bytes());
    //        }
    //
    //        self.commitments
    //            .iter()
    //            .for_each(|c| hasher.input(c.as_bytes()));
    //        (self.commitments.len()..MAX_NOTES_PER_TRANSACTION)
    //            .for_each(|_| hasher.input(Scalar::one().as_bytes()));
    //
    //        Scalar::from_hash(hasher)
    //    }
    //
    //    /// Append a transaction item to the transaction.
    //    ///
    //    /// No validation is performed
    //    pub fn push(&mut self, item: TransactionItem) {
    //        self.items.push(item);
    //    }

    /// Append an input to the transaction
    pub fn push_input(&mut self, item: TransactionInput) -> Result<(), Error> {
        if self.idx_inputs + self.idx_outputs > MAX_NOTES_PER_TRANSACTION - 2 {
            return Err(Error::MaximumNotes);
        }

        self.inputs[self.idx_inputs] = item;
        self.idx_inputs += 1;

        Ok(())
    }

    /// Append an output to the transaction
    pub fn push_output(&mut self, item: TransactionOutput) -> Result<(), Error> {
        if self.idx_inputs + self.idx_outputs > MAX_NOTES_PER_TRANSACTION - 2 {
            return Err(Error::MaximumNotes);
        }

        self.outputs[self.idx_outputs] = item;
        self.idx_outputs += 1;

        Ok(())
    }

    /// Return the fee value.
    ///
    /// A transaction is created with a random public key for the fee. The pre-image of the fee
    /// note is not validated on the r1cs circuit, so the public key can later be changed by a
    /// block generator
    pub fn fee(&self) -> &TransactionOutput {
        &self.fee
    }

    /// Set the fee value.
    pub fn set_fee(&mut self, fee: TransactionOutput) {
        self.fee = fee;
    }

    /// Set the public key of a block generator. This will not affect the r1cs proof
    pub fn set_fee_pk(&mut self, pk: PublicKey) {
        let value = self.fee.value();
        let (note, blinding_factor) = TransparentNote::output(&pk, value);

        self.fee = note.to_transaction_output(value, blinding_factor, pk);
    }

    /// Transaction inputs
    pub fn inputs(&self) -> &[TransactionInput] {
        &self.inputs[0..self.idx_inputs]
    }

    /// Transaction outputs
    pub fn outputs(&self) -> &[TransactionOutput] {
        &self.outputs[0..self.idx_outputs]
    }

    /// Remove a specified transaction input and return it, if present
    pub fn remove_input(&mut self, idx: usize) -> Option<TransactionInput> {
        if self.idx_inputs == 0 || idx >= self.idx_inputs {
            return None;
        } else if self.idx_inputs == 1 {
            self.idx_inputs = 0;
            return Some(self.inputs[0]);
        }

        self.idx_inputs -= 1;
        let src = (&mut self.inputs[self.idx_inputs]) as *mut TransactionInput;
        let dst = (&mut self.inputs[idx]) as *mut TransactionInput;
        unsafe {
            ptr::swap(src, dst);
        }

        Some(self.inputs[self.idx_inputs])
    }

    /// Remove a specified transaction output and return it, if present
    pub fn remove_output(&mut self, idx: usize) -> Option<TransactionOutput> {
        if self.idx_outputs == 0 || idx >= self.idx_outputs {
            return None;
        } else if self.idx_outputs == 1 {
            self.idx_outputs = 0;
            return Some(self.outputs[0]);
        }

        self.idx_outputs -= 1;
        let src = (&mut self.outputs[self.idx_outputs]) as *mut TransactionOutput;
        let dst = (&mut self.outputs[idx]) as *mut TransactionOutput;
        unsafe {
            ptr::swap(src, dst);
        }

        Some(self.outputs[self.idx_outputs])
    }

    //
    //    /// Reference to the transaction items
    //    pub fn items(&self) -> &Vec<TransactionItem> {
    //        &self.items
    //    }
    //
    //    /// Remove a specific item from the transaction. Internally calls the `Vec::remove` method
    //    pub fn remove_item(&mut self, index: usize) {
    //        if index < self.items.len() {
    //            self.items.remove(index);
    //        }
    //    }
    //
    //    /// R1cs proof circuit. The circuit is created with [`Transaction::prove`], and depends on the
    //    /// correct secrets set on the transaction items.
    //    ///
    //    /// These secrets are obfuscate on propagation
    //    pub fn r1cs(&self) -> Option<&R1CSProof> {
    //        self.r1cs.as_ref()
    //    }
    //
    //    /// Replace the r1cs proof circuit
    //    pub fn set_r1cs(&mut self, r1cs: R1CSProof) {
    //        self.r1cs.replace(r1cs);
    //    }
    //
    //    /// Commitment points of the proved transaction. Created by [`Transaction::prove`]
    //    pub fn commitments(&self) -> &Vec<CompressedRistretto> {
    //        &self.commitments
    //    }
    //
    //    /// Commitment points of the r1cs circuit
    //    pub fn set_commitments(&mut self, commitments: Vec<CompressedRistretto>) {
    //        self.commitments = commitments;
    //    }
    //

    /// Sort the inputs and outputs
    pub fn sort_items(&mut self) {
        if self.idx_inputs > 0 {
            (&mut self.inputs[0..self.idx_inputs]).sort();
        }

        if self.idx_outputs > 0 {
            (&mut self.outputs[0..self.idx_outputs]).sort();
        }
    }

    /// Perform the zk proof, and save internally the created r1cs circuit and the commitment
    /// points.
    ///
    /// Depends on the secret data of the transaction items
    ///
    /// The transaction items will be sorted for verification correctness
    pub fn prove(&mut self) -> Result<(), Error> {
        if self.idx_inputs + self.idx_outputs + 1 > MAX_NOTES_PER_TRANSACTION {
            return Err(Error::MaximumNotes);
        }

        self.sort_items();

        Ok(())

        //        let (pc_gens, bp_gens, mut transcript) = gen_cs_transcript();
        //        let mut prover = Prover::new(&pc_gens, &mut transcript);
        //
        //        // Commit and constrain the pre-image of the notes
        //        let commitments: Vec<CompressedRistretto> = self
        //            .items()
        //            .iter()
        //            .map(|item| {
        //                let (y, x) = item.note().zk_preimage();
        //                let (c, v) = prover.commit(y, utils::gen_random_scalar());
        //
        //                gadgets::note_preimage(&mut prover, v.into(), x.into());
        //
        //                c
        //            })
        //            .collect();
        //
        //        // Set transaction fee to the difference between the sums
        //        let (input, output) = self
        //            .items()
        //            .iter()
        //            .fold((0, 0), |(mut input, mut output), item| {
        //                let utxo = item.note().utxo();
        //
        //                match utxo {
        //                    NoteUtxoType::Input => input += item.value(),
        //                    NoteUtxoType::Output => output += item.value(),
        //                };
        //
        //                (input, output)
        //            });
        //        if output > input {
        //            return Err(Error::FeeOutput);
        //        }
        //        let fee_value = input - output;
        //        // The miner spending key will be defined later by the block generator
        //        let sk = SecretKey::default();
        //        let pk = sk.public_key();
        //        let (fee, blinding_factor) = TransparentNote::output(&sk.public_key(), fee_value);
        //        let fee = fee.to_transaction_output(fee_value, blinding_factor, pk);
        //
        //        // Commit the fee to the circuit
        //        let (_, var) = prover.commit(
        //            Scalar::from(fee_value),
        //            fee.note().blinding_factor(&sk.view_key()),
        //        );
        //        let output: LinearCombination = var.into();
        //        self.fee = fee;
        //
        //        let items_with_value_commitments = self
        //            .items()
        //            .iter()
        //            .map(|item| {
        //                let value = item.value();
        //                let value = Scalar::from(value);
        //                let blinding_factor = *item.blinding_factor();
        //
        //                let (_, var) = prover.commit(value, blinding_factor);
        //                let lc: LinearCombination = var.into();
        //
        //                (item, lc)
        //            })
        //            .collect::<Vec<(&TransactionItem, LinearCombination)>>();
        //
        //        gadgets::transaction_balance(&mut prover, items_with_value_commitments, output);
        //
        //        let proof = prover.prove(&bp_gens).map_err(Error::from)?;
        //
        //        self.r1cs = Some(proof);
        //        self.commitments = commitments;
        //
    }

    /// Verify a previously proven transaction with [`Transaction::prove`].
    ///
    /// Doesn't depend on the transaction items secret data. Depends only on the constructed
    /// circuit and commitment points.
    ///
    /// The transaction items will be sorted for verification correctness
    pub fn verify(&mut self) -> Result<(), Error> {
        Ok(())
        //        let proof = self.r1cs.as_ref().ok_or(Error::TransactionNotPrepared)?;
        //
        //        self.items.sort();
        //
        //        let (pc_gens, bp_gens, mut transcript) = gen_cs_transcript();
        //        let mut verifier = Verifier::new(&mut transcript);
        //
        //        let mut commits = self.commitments.iter();
        //        self.items().iter().for_each(|item| {
        //            let var = commits
        //                .next()
        //                .map(|point| verifier.commit(*point))
        //                .unwrap_or(Variable::One());
        //
        //            let (_, x) = item.note().zk_preimage();
        //            gadgets::note_preimage(&mut verifier, var.into(), x.into());
        //        });
        //
        //        let output: LinearCombination = verifier.commit(*self.fee.note().commitment()).into();
        //
        //        let items_with_value_commitments = self
        //            .items()
        //            .iter()
        //            .map(|item| {
        //                let commitment = *item.note().commitment();
        //
        //                let var = verifier.commit(commitment);
        //                let lc: LinearCombination = var.into();
        //
        //                (item, lc)
        //            })
        //            .collect::<Vec<(&TransactionItem, LinearCombination)>>();
        //
        //        gadgets::transaction_balance(&mut verifier, items_with_value_commitments, output);
        //
        //        verifier
        //            .verify(proof, &pc_gens, &bp_gens, &mut OsRng)
        //            .map_err(Error::from)
    }

    //
    //    /// Create a new transaction from a set of inputs/outputs defined by a rpc source.
    //    ///
    //    /// Will prove and verify the created transaction.
    //    pub fn try_from_rpc_io<P: AsRef<Path>>(
    //        db_path: P,
    //        fee_value: u64,
    //        inputs: Vec<rpc::TransactionInput>,
    //        outputs: Vec<rpc::TransactionOutput>,
    //    ) -> Result<Self, Error> {
    //        let mut transaction = Transaction::default();
    //
    //        for i in inputs {
    //            let input = TransactionItem::try_from_rpc_transaction_input(db_path.as_ref(), i)?;
    //            trace!("Pushing {} dusk as input to the transaction", input.value());
    //            transaction.push(input);
    //        }
    //        for o in outputs {
    //            let output = TransactionItem::try_from(o)?;
    //            trace!(
    //                "Pushing {} dusk as output to the transaction",
    //                output.value()
    //            );
    //            transaction.push(output);
    //        }
    //
    //        let pk = PublicKey::default();
    //        trace!("Pushing {} dusk as fee to the transaction", fee_value);
    //        let (fee, blinding_factor) = TransparentNote::output(&PublicKey::default(), fee_value);
    //        let fee = fee.to_transaction_output(fee_value, blinding_factor, pk);
    //        transaction.set_fee(fee);
    //
    //        transaction.prove()?;
    //        transaction.verify()?;
    //
    //        Ok(transaction)
    //    }
    //
    //    /// Attempt to create a transaction from a rpc request.
    //    ///
    //    /// If there is a r1cs proof present on the request, will attempt to verify it against the
    //    /// proof.
    //    pub fn try_from_rpc_transaction<P: AsRef<Path>>(
    //        db_path: P,
    //        tx: rpc::Transaction,
    //    ) -> Result<Self, Error> {
    //        let mut transaction = Transaction::default();
    //
    //        if let Some(f) = tx.fee {
    //            transaction.set_fee(TransactionItem::try_from(f)?);
    //        }
    //
    //        for i in tx.inputs {
    //            transaction.push(TransactionItem::try_from_rpc_transaction_input(
    //                db_path.as_ref(),
    //                i,
    //            )?);
    //        }
    //        for o in tx.outputs {
    //            transaction.push(TransactionItem::try_from(o)?);
    //        }
    //
    //        transaction.commitments = tx.commitments.into_iter().map(|p| p.into()).collect();
    //        transaction.r1cs = if tx.r1cs.is_empty() {
    //            None
    //        } else {
    //            Some(R1CSProof::from_bytes(tx.r1cs.as_slice())?)
    //        };
    //
    //        trace!(
    //            "Transaction {} parsed",
    //            hex::encode(transaction.hash().as_bytes())
    //        );
    //
    //        if transaction.r1cs.is_some() {
    //            transaction.verify()?;
    //        }
    //
    //        Ok(transaction)
    //    }
}

impl From<Transaction> for rpc::Transaction {
    fn from(tx: Transaction) -> rpc::Transaction {
        let inputs = tx.inputs.iter().map(|i| (*i).into()).collect();
        let outputs = tx.outputs.iter().map(|o| (*o).into()).collect();
        let fee = Some(tx.fee.into());

        // TODO - Replace for plonk proof
        let r1cs = b"Not implemented proof".to_vec();
        let commitments = vec![];

        rpc::Transaction {
            inputs,
            outputs,
            fee,
            r1cs,
            commitments,
        }
    }
}

impl fmt::LowerHex for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(utils::scalar_as_slice(&self.hash().0)))
    }
}

impl fmt::UpperHex for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            hex::encode_upper(utils::scalar_as_slice(&self.hash().0))
        )
    }
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}
