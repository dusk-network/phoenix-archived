use crate::{
    utils, zk, BlsScalar, JubJubAffine, Note, Transaction, TransactionInput, TransactionItem,
    MAX_INPUT_NOTES_PER_TRANSACTION, MAX_OUTPUT_NOTES_PER_TRANSACTION,
};

use std::mem;

use jubjub::GENERATOR;

use unprolix::{Constructor, Getters, Setters};

/// Structure reflecting a [`Transaction`] committed to a circuit
#[derive(Clone, Copy, Constructor, Getters, Setters)]
pub struct ZkTransaction {
    inputs: [ZkTransactionInput; MAX_INPUT_NOTES_PER_TRANSACTION],
    outputs: [ZkTransactionOutput; MAX_OUTPUT_NOTES_PER_TRANSACTION],
    fee: ZkTransactionOutput,

    basepoint_affine_x: zk::Variable,
    basepoint_affine_y: zk::Variable,
    basepoint_affine_xy: zk::Variable,

    zero: zk::Variable,
    one: zk::Variable,
    two: zk::Variable,
    three: zk::Variable,
    fifteen: zk::Variable,
}

impl ZkTransaction {
    pub fn from_tx(composer: &mut zk::Composer, tx: &Transaction) -> Self {
        let zero = composer.add_input(BlsScalar::zero());
        let one = composer.add_input(BlsScalar::one());
        let two = composer.add_input(BlsScalar::from(2u64));
        let three = composer.add_input(BlsScalar::from(3u64));
        let fifteen = composer.add_input(BlsScalar::from(15u64));

        let basepoint = GENERATOR;
        let basepoint_affine_x = composer.add_input(basepoint.get_x());
        let basepoint_affine_y = composer.add_input(basepoint.get_y());
        let basepoint_affine_xy = composer.add_input(basepoint.get_x() * basepoint.get_y());

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

        Self::new(
            inputs,
            outputs,
            fee,
            basepoint_affine_x,
            basepoint_affine_y,
            basepoint_affine_xy,
            zero,
            one,
            two,
            three,
            fifteen,
        )
    }
}

/// Set of [`zk::Variable`] that represents a tx item in a circuit
#[derive(Clone, Copy, Constructor, Getters, Setters)]
pub struct ZkTransactionInput {
    value: zk::Variable,
    blinding_factor: zk::Variable,
    value_commitment: zk::Variable,
    idx: zk::Variable,

    pk_r_affine_x: zk::Variable,
    pk_r_affine_y: zk::Variable,
    pk_r_affine_xy: zk::Variable,

    note_hash_scalar: BlsScalar,
    note_hash: zk::Variable,

    sk_r: [zk::Variable; 256],
    nullifier: BlsScalar,

    merkle: zk::ZkMerkleProof,
    merkle_root: BlsScalar,
}

impl ZkTransactionInput {
    pub fn from_tx_input(composer: &mut zk::Composer, item: &TransactionInput) -> Self {
        let value = BlsScalar::from(item.value());
        let value = composer.add_input(value);

        let blinding_factor = composer.add_input(*item.blinding_factor());
        let value_commitment = composer.add_input(*item.note().value_commitment());

        let idx = item.note().idx();
        let idx = BlsScalar::from(idx);
        let idx = composer.add_input(idx);

        let pk_r_affine = JubJubAffine::from(item.note().pk_r());
        let pk_r_affine_x = composer.add_input(pk_r_affine.get_x());
        let pk_r_affine_y = composer.add_input(pk_r_affine.get_y());

        let pk_r_affine_xy = pk_r_affine.get_x() * pk_r_affine.get_y();
        let pk_r_affine_xy = composer.add_input(pk_r_affine_xy);

        let note_hash_scalar = item.note().hash();
        let note_hash = composer.add_input(note_hash_scalar);

        let mut sk_r = [unsafe { mem::zeroed() }; 256];
        utils::jubjub_scalar_to_bls_bits(&item.note().sk_r(&item.sk))
            .iter()
            .zip(sk_r.iter_mut())
            .for_each(|(bit, s)| {
                *s = composer.add_input(*bit);
            });

        let nullifier = item.nullifier.into();

        let merkle = zk::ZkMerkleProof::new(composer, &item.merkle_opening);
        let merkle_root = *item.merkle_opening.root();

        Self::new(
            value,
            blinding_factor,
            value_commitment,
            idx,
            pk_r_affine_x,
            pk_r_affine_y,
            pk_r_affine_xy,
            note_hash_scalar,
            note_hash,
            sk_r,
            nullifier,
            merkle,
            merkle_root,
        )
    }
}

/// Set of [`zk::Variable`] that represents a tx item in a circuit
#[derive(Debug, Clone, Copy, Eq, PartialEq, Constructor, Getters, Setters)]
pub struct ZkTransactionOutput {
    value: zk::Variable,
    blinding_factor: zk::Variable,
    value_commitment: zk::Variable,
    value_commitment_scalar: BlsScalar,
    idx: zk::Variable,

    pk_r_affine_x: zk::Variable,
    pk_r_affine_x_scalar: BlsScalar,

    note_hash_scalar: BlsScalar,
    note_hash: zk::Variable,
}

impl ZkTransactionOutput {
    pub fn from_tx_item<I: TransactionItem>(composer: &mut zk::Composer, item: &I) -> Self {
        let value = BlsScalar::from(item.value());
        let value = composer.add_input(value);

        let blinding_factor = composer.add_input(*item.blinding_factor());
        let value_commitment_scalar = *item.note().value_commitment();
        let value_commitment = composer.add_input(value_commitment_scalar);

        let idx = item.note().idx();
        let idx = BlsScalar::from(idx);
        let idx = composer.add_input(idx);

        let pk_r_affine = JubJubAffine::from(item.note().pk_r());
        let pk_r_affine_x_scalar = pk_r_affine.get_x();
        let pk_r_affine_x = composer.add_input(pk_r_affine_x_scalar);

        let note_hash_scalar = item.note().hash();
        let note_hash = composer.add_input(note_hash_scalar);

        Self::new(
            value,
            blinding_factor,
            value_commitment,
            value_commitment_scalar,
            idx,
            pk_r_affine_x,
            pk_r_affine_x_scalar,
            note_hash_scalar,
            note_hash,
        )
    }
}
