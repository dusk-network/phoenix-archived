use crate::{
    utils, BlsScalar, Error, JubJubAffine, Note, Nullifier, Transaction, TransactionItem,
    MAX_INPUT_NOTES_PER_TRANSACTION, MAX_OUTPUT_NOTES_PER_TRANSACTION,
};

use std::io::{self, Read, Write};

use unprolix::{Constructor, Getters, Setters};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Constructor, Getters, Setters)]
pub struct ZkPublicInputs {
    fee_value_commitment: BlsScalar,
    merkle_roots: [BlsScalar; MAX_INPUT_NOTES_PER_TRANSACTION],
    nullifiers: [Nullifier; MAX_INPUT_NOTES_PER_TRANSACTION],
    outputs_value_commitments: [BlsScalar; MAX_OUTPUT_NOTES_PER_TRANSACTION],
    outputs_pk_r_affine_x: [BlsScalar; MAX_OUTPUT_NOTES_PER_TRANSACTION],
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
            .and_then(|c| Ok(c.copy_from_slice(&self.fee_value_commitment.to_bytes()[..])))
            .map_err::<io::Error, _>(|e| e.into())?;
        n += utils::BLS_SCALAR_SERIALIZED_SIZE;

        for i in 0..MAX_INPUT_NOTES_PER_TRANSACTION {
            chunk
                .next()
                .ok_or(Error::InvalidParameters)
                .and_then(|c| Ok(c.copy_from_slice(&self.merkle_roots[i].to_bytes()[..])))
                .map_err::<io::Error, _>(|e| e.into())?;
            n += utils::BLS_SCALAR_SERIALIZED_SIZE;

            chunk
                .next()
                .ok_or(Error::InvalidParameters)
                .and_then(|c| Ok(c.copy_from_slice(&self.nullifiers[i].s().to_bytes()[..])))
                .map_err::<io::Error, _>(|e| e.into())?;
            n += utils::BLS_SCALAR_SERIALIZED_SIZE;
        }

        for i in 0..MAX_OUTPUT_NOTES_PER_TRANSACTION {
            chunk
                .next()
                .ok_or(Error::InvalidParameters)
                .and_then(|c| {
                    Ok(c.copy_from_slice(&self.outputs_value_commitments[i].to_bytes()[..]))
                })
                .map_err::<io::Error, _>(|e| e.into())?;
            n += utils::BLS_SCALAR_SERIALIZED_SIZE;

            chunk
                .next()
                .ok_or(Error::InvalidParameters)
                .and_then(|c| Ok(c.copy_from_slice(&self.outputs_pk_r_affine_x[i].to_bytes()[..])))
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
                *x = JubJubAffine::from(o.note().pk_r()).get_x();
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
