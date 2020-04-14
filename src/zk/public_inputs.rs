use crate::{
    utils, zk, BlsScalar, Error, Note, Nullifier, Transaction, TransactionItem,
    MAX_INPUT_NOTES_PER_TRANSACTION, MAX_OUTPUT_NOTES_PER_TRANSACTION,
};

use std::io::{self, Read, Write};

use algebra::curves::ProjectiveCurve;
use num_traits::Zero;
use unprolix::{Constructor, Getters, Setters};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Constructor, Getters, Setters)]
pub struct ZkPublicInputs {
    fee_value_commitment: BlsScalar,
    merkle_roots: [BlsScalar; MAX_INPUT_NOTES_PER_TRANSACTION],
    nullifiers: [Nullifier; MAX_INPUT_NOTES_PER_TRANSACTION],
    outputs_value_commitments: [BlsScalar; MAX_OUTPUT_NOTES_PER_TRANSACTION],
    outputs_pk_r_affine_x: [BlsScalar; MAX_OUTPUT_NOTES_PER_TRANSACTION],
}

impl ZkPublicInputs {
    pub fn generate_pi(&self) -> Vec<BlsScalar> {
        // TODO - Structure should be updated according to the set features
        let mut pi = zk::public_inputs().clone();

        self.merkle_roots
            .iter()
            .enumerate()
            .for_each(|(i, merkle)| pi[(i + 1) * 29894] = *merkle);

        self.nullifiers
            .iter()
            .enumerate()
            .for_each(|(i, nullifier)| pi[(i + 1) * 41347] = nullifier.0);

        self.outputs_pk_r_affine_x
            .iter()
            .enumerate()
            .for_each(|(i, pk_r_affine_x)| pi[i + 31632] = *pk_r_affine_x);

        self.outputs_value_commitments
            .iter()
            .enumerate()
            .for_each(|(i, value_commitment)| pi[36847 + i * 1738] = *value_commitment);

        pi[35109] = self.fee_value_commitment;

        pi
    }
}

impl Write for ZkPublicInputs {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut chunk = buf.chunks(utils::BLS_SCALAR_SERIALIZED_SIZE);
        let mut n = 0;

        self.fee_value_commitment = chunk
            .next()
            .ok_or(Error::InvalidParameters)
            .and_then(utils::deserialize_bls_scalar)
            .map_err::<io::Error, _>(|e| e.into())?;
        n += utils::BLS_SCALAR_SERIALIZED_SIZE;

        for i in 0..MAX_INPUT_NOTES_PER_TRANSACTION {
            self.merkle_roots[i] = chunk
                .next()
                .ok_or(Error::InvalidParameters)
                .and_then(utils::deserialize_bls_scalar)
                .map_err::<io::Error, _>(|e| e.into())?;
            n += utils::BLS_SCALAR_SERIALIZED_SIZE;

            self.nullifiers[i] = chunk
                .next()
                .ok_or(Error::InvalidParameters)
                .and_then(utils::deserialize_bls_scalar)
                .map_err::<io::Error, _>(|e| e.into())?
                .into();
            n += utils::BLS_SCALAR_SERIALIZED_SIZE;
        }

        for i in 0..MAX_OUTPUT_NOTES_PER_TRANSACTION {
            self.outputs_value_commitments[i] = chunk
                .next()
                .ok_or(Error::InvalidParameters)
                .and_then(utils::deserialize_bls_scalar)
                .map_err::<io::Error, _>(|e| e.into())?;
            n += utils::BLS_SCALAR_SERIALIZED_SIZE;

            self.outputs_pk_r_affine_x[i] = chunk
                .next()
                .ok_or(Error::InvalidParameters)
                .and_then(utils::deserialize_bls_scalar)
                .map_err::<io::Error, _>(|e| e.into())?;
            n += utils::BLS_SCALAR_SERIALIZED_SIZE;
        }

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for ZkPublicInputs {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut chunk = buf.chunks_mut(utils::BLS_SCALAR_SERIALIZED_SIZE);
        let mut n = 0;

        chunk
            .next()
            .ok_or(Error::InvalidParameters)
            .and_then(|c| utils::serialize_bls_scalar(&self.fee_value_commitment, c))
            .map_err::<io::Error, _>(|e| e.into())?;
        n += utils::BLS_SCALAR_SERIALIZED_SIZE;

        for i in 0..MAX_INPUT_NOTES_PER_TRANSACTION {
            chunk
                .next()
                .ok_or(Error::InvalidParameters)
                .and_then(|c| utils::serialize_bls_scalar(&self.merkle_roots[i], c))
                .map_err::<io::Error, _>(|e| e.into())?;
            n += utils::BLS_SCALAR_SERIALIZED_SIZE;

            chunk
                .next()
                .ok_or(Error::InvalidParameters)
                .and_then(|c| utils::serialize_bls_scalar(&self.nullifiers[i].0, c))
                .map_err::<io::Error, _>(|e| e.into())?;
            n += utils::BLS_SCALAR_SERIALIZED_SIZE;
        }

        for i in 0..MAX_OUTPUT_NOTES_PER_TRANSACTION {
            chunk
                .next()
                .ok_or(Error::InvalidParameters)
                .and_then(|c| utils::serialize_bls_scalar(&self.outputs_value_commitments[i], c))
                .map_err::<io::Error, _>(|e| e.into())?;
            n += utils::BLS_SCALAR_SERIALIZED_SIZE;

            chunk
                .next()
                .ok_or(Error::InvalidParameters)
                .and_then(|c| utils::serialize_bls_scalar(&self.outputs_pk_r_affine_x[i], c))
                .map_err::<io::Error, _>(|e| e.into())?;
            n += utils::BLS_SCALAR_SERIALIZED_SIZE;
        }

        Ok(n)
    }
}

impl From<&Transaction> for ZkPublicInputs {
    fn from(tx: &Transaction) -> Self {
        let fee_value_commitment = *tx.fee().note().value_commitment();

        let mut merkle_roots = [BlsScalar::zero(); MAX_INPUT_NOTES_PER_TRANSACTION];
        let mut nullifiers = [Nullifier::default(); MAX_INPUT_NOTES_PER_TRANSACTION];

        tx.inputs()
            .iter()
            .zip(merkle_roots.iter_mut().zip(nullifiers.iter_mut()))
            .for_each(|(i, (r, n))| {
                *r = i.merkle_root;
                *n = *i.nullifier();
            });

        let mut outputs_value_commitments = [BlsScalar::zero(); MAX_OUTPUT_NOTES_PER_TRANSACTION];
        let mut outputs_pk_r_affine_x = [BlsScalar::zero(); MAX_OUTPUT_NOTES_PER_TRANSACTION];

        tx.outputs()
            .iter()
            .zip(
                outputs_value_commitments
                    .iter_mut()
                    .zip(outputs_pk_r_affine_x.iter_mut()),
            )
            .for_each(|(o, (c, x))| {
                *c = *o.note().value_commitment();
                *x = o.note().pk_r().into_affine().x;
            });

        ZkPublicInputs::new(
            fee_value_commitment,
            merkle_roots,
            nullifiers,
            outputs_value_commitments,
            outputs_pk_r_affine_x,
        )
    }
}
