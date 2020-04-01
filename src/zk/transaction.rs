use crate::{
    zk, BlsScalar, Note, Transaction, TransactionItem, MAX_INPUT_NOTES_PER_TRANSACTION,
    MAX_OUTPUT_NOTES_PER_TRANSACTION,
};

use std::mem;

use algebra::curves::ProjectiveCurve;

/// Structure reflecting a [`Transaction`] committed to a circuit
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ZkTransaction {
    pub inputs: [ZkTransactionInput; MAX_INPUT_NOTES_PER_TRANSACTION],
    pub outputs: [ZkTransactionOutput; MAX_OUTPUT_NOTES_PER_TRANSACTION],
    pub fee: ZkTransactionOutput,
}

impl ZkTransaction {
    pub fn new(
        inputs: [ZkTransactionInput; MAX_INPUT_NOTES_PER_TRANSACTION],
        outputs: [ZkTransactionOutput; MAX_OUTPUT_NOTES_PER_TRANSACTION],
        fee: ZkTransactionOutput,
    ) -> Self {
        Self {
            inputs,
            outputs,
            fee,
        }
    }

    pub fn from_tx(composer: &mut zk::Composer, tx: &Transaction) -> Self {
        let mut inputs = [unsafe { mem::zeroed() }; MAX_INPUT_NOTES_PER_TRANSACTION];
        let mut outputs = [unsafe { mem::zeroed() }; MAX_OUTPUT_NOTES_PER_TRANSACTION];

        tx.all_inputs()
            .iter()
            .zip(inputs.iter_mut())
            .for_each(|(tx_input, i)| {
                *i = ZkTransactionInput::from_tx_item(composer, tx_input);
            });

        tx.all_outputs()
            .iter()
            .zip(outputs.iter_mut())
            .for_each(|(tx_output, o)| {
                *o = ZkTransactionOutput::from_tx_item(composer, tx_output);
            });

        let fee = ZkTransactionOutput::from_tx_item(composer, tx.fee());

        Self::new(inputs, outputs, fee)
    }
}

/// Set of [`zk::Variable`] that represents a tx item in a circuit
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ZkTransactionInput {
    pub value: zk::Variable,
    pub blinding_factor: zk::Variable,
    pub value_commitment: zk::Variable,
    pub idx: zk::Variable,
    pub R_affine_x: zk::Variable,
    pub R_affine_y: zk::Variable,
    pub pk_r_affine_x: zk::Variable,
    pub pk_r_affine_y: zk::Variable,

    pub note_hash_scalar: BlsScalar,
    pub note_hash: zk::Variable,
}

impl ZkTransactionInput {
    pub fn new(
        value: zk::Variable,
        blinding_factor: zk::Variable,
        value_commitment: zk::Variable,
        idx: zk::Variable,
        R_affine_x: zk::Variable,
        R_affine_y: zk::Variable,
        pk_r_affine_x: zk::Variable,
        pk_r_affine_y: zk::Variable,

        note_hash_scalar: BlsScalar,
        note_hash: zk::Variable,
    ) -> Self {
        Self {
            value,
            blinding_factor,
            value_commitment,
            idx,
            R_affine_x,
            R_affine_y,
            pk_r_affine_x,
            pk_r_affine_y,

            note_hash_scalar,
            note_hash,
        }
    }

    pub fn from_tx_item<I: TransactionItem>(composer: &mut zk::Composer, item: &I) -> Self {
        let value = BlsScalar::from(item.value());
        let value = composer.add_input(value);

        let blinding_factor = composer.add_input(*item.blinding_factor());
        let value_commitment = composer.add_input(*item.note().value_commitment());

        let idx = item.note().idx();
        let idx = BlsScalar::from(idx);
        let idx = composer.add_input(idx);

        let R_affine = item.note().R().into_affine();
        let R_affine_x = composer.add_input(R_affine.x);
        let R_affine_y = composer.add_input(R_affine.y);

        let pk_r_affine = item.note().pk_r().into_affine();
        let pk_r_affine_x = composer.add_input(pk_r_affine.x);
        let pk_r_affine_y = composer.add_input(pk_r_affine.y);

        let note_hash_scalar = item.note().hash();
        let note_hash = composer.add_input(note_hash_scalar);

        Self::new(
            value,
            blinding_factor,
            value_commitment,
            idx,
            R_affine_x,
            R_affine_y,
            pk_r_affine_x,
            pk_r_affine_y,
            note_hash_scalar,
            note_hash,
        )
    }
}

/// Set of [`zk::Variable`] that represents a tx item in a circuit
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ZkTransactionOutput {
    pub value: zk::Variable,
    pub blinding_factor: zk::Variable,
    pub value_commitment: zk::Variable,
    pub idx: zk::Variable,
    pub R_affine_x: zk::Variable,
    pub R_affine_y: zk::Variable,
    pub pk_r_affine_x: zk::Variable,
    pub pk_r_affine_y: zk::Variable,
    pub note_hash_scalar: BlsScalar,
    pub note_hash: zk::Variable,
}

impl ZkTransactionOutput {
    pub fn new(
        value: zk::Variable,
        blinding_factor: zk::Variable,
        value_commitment: zk::Variable,
        idx: zk::Variable,
        R_affine_x: zk::Variable,
        R_affine_y: zk::Variable,
        pk_r_affine_x: zk::Variable,
        pk_r_affine_y: zk::Variable,
        note_hash_scalar: BlsScalar,
        note_hash: zk::Variable,
    ) -> Self {
        Self {
            value,
            blinding_factor,
            value_commitment,
            idx,
            R_affine_x,
            R_affine_y,
            pk_r_affine_x,
            pk_r_affine_y,
            note_hash_scalar,
            note_hash,
        }
    }

    pub fn from_tx_item<I: TransactionItem>(composer: &mut zk::Composer, item: &I) -> Self {
        let value = BlsScalar::from(item.value());
        let value = composer.add_input(value);

        let blinding_factor = composer.add_input(*item.blinding_factor());
        let value_commitment = composer.add_input(*item.note().value_commitment());

        let idx = item.note().idx();
        let idx = BlsScalar::from(idx);
        let idx = composer.add_input(idx);

        let R_affine = item.note().R().into_affine();
        let R_affine_x = composer.add_input(R_affine.x);
        let R_affine_y = composer.add_input(R_affine.y);

        let pk_r_affine = item.note().pk_r().into_affine();
        let pk_r_affine_x = composer.add_input(pk_r_affine.x);
        let pk_r_affine_y = composer.add_input(pk_r_affine.y);

        let note_hash_scalar = item.note().hash();
        let note_hash = composer.add_input(note_hash_scalar);

        Self::new(
            value,
            blinding_factor,
            value_commitment,
            idx,
            R_affine_x,
            R_affine_y,
            pk_r_affine_x,
            pk_r_affine_y,
            note_hash_scalar,
            note_hash,
        )
    }
}
