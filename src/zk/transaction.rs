use crate::{
    crypto, utils, zk, BlsScalar, Note, Transaction, TransactionInput, TransactionItem,
    MAX_INPUT_NOTES_PER_TRANSACTION, MAX_OUTPUT_NOTES_PER_TRANSACTION,
};

use std::mem;

use algebra::curves::ProjectiveCurve;
use num_traits::{One, Zero};

/// Structure reflecting a [`Transaction`] committed to a circuit
#[derive(Clone, Copy)]
pub struct ZkTransaction {
    pub inputs: [ZkTransactionInput; MAX_INPUT_NOTES_PER_TRANSACTION],
    pub outputs: [ZkTransactionOutput; MAX_OUTPUT_NOTES_PER_TRANSACTION],
    pub fee: ZkTransactionOutput,

    pub basepoint_affine_x: zk::Variable,
    pub basepoint_affine_y: zk::Variable,
    pub basepoint_affine_xy: zk::Variable,

    pub zero: zk::Variable,
    pub one: zk::Variable,
    pub two: zk::Variable,
    pub three: zk::Variable,
    pub fifteen: zk::Variable,
}

impl ZkTransaction {
    pub fn new(
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
    ) -> Self {
        Self {
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
        }
    }

    pub fn from_tx<T: crypto::MerkleProofProvider>(
        composer: &mut zk::Composer,
        tx: &Transaction,
        tree: &T,
    ) -> Self {
        let zero = composer.add_input(BlsScalar::zero());
        let one = composer.add_input(BlsScalar::one());
        let two = composer.add_input(BlsScalar::from(2u8));
        let three = composer.add_input(BlsScalar::from(3u8));
        let fifteen = composer.add_input(BlsScalar::from(15u8));

        let basepoint = utils::jubjub_projective_basepoint().into_affine();
        let basepoint_affine_x = composer.add_input(basepoint.x);
        let basepoint_affine_y = composer.add_input(basepoint.y);
        let basepoint_affine_xy = composer.add_input(basepoint.x * basepoint.y);

        let mut inputs = [unsafe { mem::zeroed() }; MAX_INPUT_NOTES_PER_TRANSACTION];
        let mut outputs = [unsafe { mem::zeroed() }; MAX_OUTPUT_NOTES_PER_TRANSACTION];

        tx.all_inputs()
            .iter()
            .zip(inputs.iter_mut())
            .for_each(|(tx_input, i)| {
                *i = ZkTransactionInput::from_tx_input(composer, tx_input, tree);
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
#[derive(Clone, Copy)]
pub struct ZkTransactionInput {
    pub value: zk::Variable,
    pub blinding_factor: zk::Variable,
    pub value_commitment: zk::Variable,
    pub idx: zk::Variable,

    pub pk_r_affine_x: zk::Variable,
    pub pk_r_affine_y: zk::Variable,
    pub pk_r_affine_xy: zk::Variable,

    pub note_hash_scalar: BlsScalar,
    pub note_hash: zk::Variable,

    pub sk_r: [zk::Variable; 256],
    pub nullifier: BlsScalar,

    pub merkle: zk::ZkMerkleProof,
    pub merkle_root: BlsScalar,
}

impl ZkTransactionInput {
    pub fn new(
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
    ) -> Self {
        Self {
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
        }
    }

    pub fn from_tx_input<T: crypto::MerkleProofProvider>(
        composer: &mut zk::Composer,
        item: &TransactionInput,
        tree: &T,
    ) -> Self {
        let value = BlsScalar::from(item.value());
        let value = composer.add_input(value);

        let blinding_factor = composer.add_input(*item.blinding_factor());
        let value_commitment = composer.add_input(*item.note().value_commitment());

        let idx = item.note().idx();
        let idx = BlsScalar::from(idx);
        let idx = composer.add_input(idx);

        let pk_r_affine = item.note().pk_r().into_affine();
        let pk_r_affine_x = composer.add_input(pk_r_affine.x);
        let pk_r_affine_y = composer.add_input(pk_r_affine.y);

        let pk_r_affine_xy = pk_r_affine.x * pk_r_affine.y;
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

        let merkle = crypto::MerkleProof::new(tree, item.note());
        let merkle_root = merkle.levels[crypto::TREE_HEIGHT - 1].data[1];
        let merkle = zk::ZkMerkleProof::new(composer, &merkle);

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
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ZkTransactionOutput {
    pub value: zk::Variable,
    pub blinding_factor: zk::Variable,
    pub value_commitment: zk::Variable,
    pub value_commitment_scalar: BlsScalar,
    pub idx: zk::Variable,

    pub pk_r_affine_x: zk::Variable,
    pub pk_r_affine_x_scalar: BlsScalar,

    pub note_hash_scalar: BlsScalar,
    pub note_hash: zk::Variable,
}

impl ZkTransactionOutput {
    pub fn new(
        value: zk::Variable,
        blinding_factor: zk::Variable,
        value_commitment: zk::Variable,
        value_commitment_scalar: BlsScalar,
        idx: zk::Variable,

        pk_r_affine_x: zk::Variable,
        pk_r_affine_x_scalar: BlsScalar,

        note_hash_scalar: BlsScalar,
        note_hash: zk::Variable,
    ) -> Self {
        Self {
            value,
            blinding_factor,
            value_commitment,
            value_commitment_scalar,
            idx,

            pk_r_affine_x,
            pk_r_affine_x_scalar,

            note_hash_scalar,
            note_hash,
        }
    }

    pub fn from_tx_item<I: TransactionItem>(composer: &mut zk::Composer, item: &I) -> Self {
        let value = BlsScalar::from(item.value());
        let value = composer.add_input(value);

        let blinding_factor = composer.add_input(*item.blinding_factor());
        let value_commitment_scalar = *item.note().value_commitment();
        let value_commitment = composer.add_input(value_commitment_scalar);

        let idx = item.note().idx();
        let idx = BlsScalar::from(idx);
        let idx = composer.add_input(idx);

        let pk_r_affine = item.note().pk_r().into_affine();
        let pk_r_affine_x_scalar = pk_r_affine.x;
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
