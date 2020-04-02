use crate::{
    utils, zk, BlsScalar, Note, Transaction, TransactionInput, TransactionItem,
    MAX_INPUT_NOTES_PER_TRANSACTION, MAX_OUTPUT_NOTES_PER_TRANSACTION,
};

use std::mem;

use algebra::curves::{AffineCurve, ProjectiveCurve};

/// Structure reflecting a [`Transaction`] committed to a circuit
#[derive(Clone, Copy)]
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
                *i = ZkTransactionInput::from_tx_input(composer, tx_input);
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
#[derive(Clone, Copy)]
pub struct ZkTransactionInput {
    pub value: zk::Variable,
    pub blinding_factor: zk::Variable,
    pub value_commitment: zk::Variable,
    pub idx: zk::Variable,
    pub R_projective_x: zk::Variable,
    pub R_projective_y: zk::Variable,
    pub R_projective_z: zk::Variable,
    pub R_projective_t: zk::Variable,
    pub pk_r_projective_x: zk::Variable,
    pub pk_r_projective_y: zk::Variable,
    pub pk_r_projective_z: zk::Variable,
    pub pk_r_projective_t: zk::Variable,

    pub note_hash_scalar: BlsScalar,
    pub note_hash: zk::Variable,

    pub sk_a: [zk::Variable; 256],
    pub sk_b: [zk::Variable; 256],
    pub nullifier: zk::Variable,
}

impl ZkTransactionInput {
    pub fn new(
        value: zk::Variable,
        blinding_factor: zk::Variable,
        value_commitment: zk::Variable,
        idx: zk::Variable,
        R_projective_x: zk::Variable,
        R_projective_y: zk::Variable,
        R_projective_z: zk::Variable,
        R_projective_t: zk::Variable,
        pk_r_projective_x: zk::Variable,
        pk_r_projective_y: zk::Variable,
        pk_r_projective_z: zk::Variable,
        pk_r_projective_t: zk::Variable,

        note_hash_scalar: BlsScalar,
        note_hash: zk::Variable,

        sk_a: [zk::Variable; 256],
        sk_b: [zk::Variable; 256],
        nullifier: zk::Variable,
    ) -> Self {
        Self {
            value,
            blinding_factor,
            value_commitment,
            idx,
            R_projective_x,
            R_projective_y,
            R_projective_z,
            R_projective_t,
            pk_r_projective_x,
            pk_r_projective_y,
            pk_r_projective_z,
            pk_r_projective_t,

            note_hash_scalar,
            note_hash,

            sk_a,
            sk_b,
            nullifier,
        }
    }

    pub fn from_tx_input(composer: &mut zk::Composer, item: &TransactionInput) -> Self {
        let value = BlsScalar::from(item.value());
        let value = composer.add_input(value);

        let blinding_factor = composer.add_input(*item.blinding_factor());
        let value_commitment = composer.add_input(*item.note().value_commitment());

        let idx = item.note().idx();
        let idx = BlsScalar::from(idx);
        let idx = composer.add_input(idx);

        let R_projective = item.note().R().into_affine().into_projective();
        let R_projective_x = composer.add_input(R_projective.x);
        let R_projective_y = composer.add_input(R_projective.y);
        let R_projective_z = composer.add_input(R_projective.z);
        let R_projective_t = composer.add_input(R_projective.t);

        let pk_r_projective = item.note().pk_r().into_affine().into_projective();
        let pk_r_projective_x = composer.add_input(pk_r_projective.x);
        let pk_r_projective_y = composer.add_input(pk_r_projective.y);
        let pk_r_projective_z = composer.add_input(pk_r_projective.z);
        let pk_r_projective_t = composer.add_input(pk_r_projective.t);

        let note_hash_scalar = item.note().hash();
        let note_hash = composer.add_input(note_hash_scalar);

        let mut sk_a = [unsafe { mem::zeroed() }; 256];
        utils::jubjub_scalar_to_bls_bits(&item.sk.a)
            .iter()
            .zip(sk_a.iter_mut())
            .for_each(|(bit, s)| {
                *s = composer.add_input(*bit);
            });

        let mut sk_b = [unsafe { mem::zeroed() }; 256];
        utils::jubjub_scalar_to_bls_bits(&item.sk.b)
            .iter()
            .zip(sk_b.iter_mut())
            .for_each(|(bit, s)| {
                *s = composer.add_input(*bit);
            });

        let nullifier = composer.add_input(item.nullifier.into());

        Self::new(
            value,
            blinding_factor,
            value_commitment,
            idx,
            R_projective_x,
            R_projective_y,
            R_projective_z,
            R_projective_t,
            pk_r_projective_x,
            pk_r_projective_y,
            pk_r_projective_z,
            pk_r_projective_t,
            note_hash_scalar,
            note_hash,
            sk_a,
            sk_b,
            nullifier,
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
    pub R_projective_x: zk::Variable,
    pub R_projective_y: zk::Variable,
    pub R_projective_z: zk::Variable,
    pub R_projective_t: zk::Variable,
    pub pk_r_projective_x: zk::Variable,
    pub pk_r_projective_y: zk::Variable,
    pub pk_r_projective_z: zk::Variable,
    pub pk_r_projective_t: zk::Variable,
    pub note_hash_scalar: BlsScalar,
    pub note_hash: zk::Variable,
}

impl ZkTransactionOutput {
    pub fn new(
        value: zk::Variable,
        blinding_factor: zk::Variable,
        value_commitment: zk::Variable,
        idx: zk::Variable,
        R_projective_x: zk::Variable,
        R_projective_y: zk::Variable,
        R_projective_z: zk::Variable,
        R_projective_t: zk::Variable,
        pk_r_projective_x: zk::Variable,
        pk_r_projective_y: zk::Variable,
        pk_r_projective_z: zk::Variable,
        pk_r_projective_t: zk::Variable,
        note_hash_scalar: BlsScalar,
        note_hash: zk::Variable,
    ) -> Self {
        Self {
            value,
            blinding_factor,
            value_commitment,
            idx,
            R_projective_x,
            R_projective_y,
            R_projective_z,
            R_projective_t,
            pk_r_projective_x,
            pk_r_projective_y,
            pk_r_projective_z,
            pk_r_projective_t,

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

        let R_projective = item.note().R().into_affine().into_projective();
        let R_projective_x = composer.add_input(R_projective.x);
        let R_projective_y = composer.add_input(R_projective.y);
        let R_projective_z = composer.add_input(R_projective.z);
        let R_projective_t = composer.add_input(R_projective.t);

        let pk_r_projective = item.note().pk_r().into_affine().into_projective();
        let pk_r_projective_x = composer.add_input(pk_r_projective.x);
        let pk_r_projective_y = composer.add_input(pk_r_projective.y);
        let pk_r_projective_z = composer.add_input(pk_r_projective.z);
        let pk_r_projective_t = composer.add_input(pk_r_projective.t);

        let note_hash_scalar = item.note().hash();
        let note_hash = composer.add_input(note_hash_scalar);

        Self::new(
            value,
            blinding_factor,
            value_commitment,
            idx,
            R_projective_x,
            R_projective_y,
            R_projective_z,
            R_projective_t,
            pk_r_projective_x,
            pk_r_projective_y,
            pk_r_projective_z,
            pk_r_projective_t,
            note_hash_scalar,
            note_hash,
        )
    }
}
