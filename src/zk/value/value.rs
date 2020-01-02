use super::gen_cs_transcript;
use crate::{utils, CompressedRistretto, Error, Idx, Prover, R1CSProof, Scalar, Verifier};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Value {
    commitment: CompressedRistretto,
    blinding_factor: Scalar,
}

impl Value {
    pub fn new<S: Into<Scalar>>(idx: Idx, value: S) -> Self {
        Value::with_blinding_factor(idx, value, utils::gen_random_scalar())
    }

    pub fn with_blinding_factor<S: Into<Scalar>>(
        _idx: Idx,
        value: S,
        blinding_factor: Scalar,
    ) -> Self {
        let (pc_gens, _, mut transcript) = gen_cs_transcript();
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let value: Scalar = value.into();
        let commitment = prover.commit(value, blinding_factor).0;

        Value::with_commitment_and_blinding_factor(commitment, blinding_factor)
    }

    pub fn with_commitment(commitment: CompressedRistretto) -> Self {
        Value::with_commitment_and_blinding_factor(commitment, Scalar::one())
    }

    pub fn with_commitment_and_blinding_factor(
        commitment: CompressedRistretto,
        blinding_factor: Scalar,
    ) -> Self {
        Value {
            commitment,
            blinding_factor,
        }
    }

    pub fn prove<S: Into<Scalar>>(&self, value: S) -> Result<R1CSProof, Error> {
        let value: Scalar = value.into();

        let (pc_gens, bp_gens, mut transcript) = gen_cs_transcript();
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        prover.commit(value, self.blinding_factor);

        prover.prove(&bp_gens).map_err(Error::from)
    }

    pub fn verify(&self, proof: &R1CSProof) -> Result<(), Error> {
        let (pc_gens, bp_gens, mut transcript) = gen_cs_transcript();
        let mut verifier = Verifier::new(&mut transcript);

        verifier.commit(self.commitment);

        verifier
            .verify(&proof, &pc_gens, &bp_gens)
            .map_err(Error::from)
    }

    pub fn commitment(&self) -> &CompressedRistretto {
        &self.commitment
    }

    pub fn blinding_factor(&self) -> &Scalar {
        &self.blinding_factor
    }
}
