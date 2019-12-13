use super::gen_cs_transcript;
use crate::{utils, CompressedRistretto, Error, PhoenixIdx, Scalar};

use bulletproofs::r1cs::{Prover, R1CSProof, Verifier};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhoenixValue {
    commitments: Vec<CompressedRistretto>,
    blinding_factors: Vec<Scalar>,
}

impl PhoenixValue {
    pub fn new(idx: PhoenixIdx, value: Scalar) -> Self {
        PhoenixValue::with_blinding_factors(idx, value, vec![utils::gen_random_scalar()])
    }

    pub fn with_blinding_factors(
        _idx: PhoenixIdx,
        value: Scalar,
        blinding_factors: Vec<Scalar>,
    ) -> Self {
        let (pc_gens, _, mut transcript) = gen_cs_transcript();
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let commitments = blinding_factors
            .iter()
            .map(|b| prover.commit(value, *b).0)
            .collect();

        PhoenixValue::with_commitments_and_blinding_factors(commitments, blinding_factors)
    }

    pub fn with_commitments(commitments: Vec<CompressedRistretto>) -> Self {
        PhoenixValue::with_commitments_and_blinding_factors(commitments, vec![])
    }

    pub fn with_commitments_and_blinding_factors(
        commitments: Vec<CompressedRistretto>,
        blinding_factors: Vec<Scalar>,
    ) -> Self {
        PhoenixValue {
            commitments,
            blinding_factors,
        }
    }

    pub fn prove(&self, value: &Scalar) -> Result<R1CSProof, Error> {
        let (pc_gens, bp_gens, mut transcript) = gen_cs_transcript();
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        self.blinding_factors.iter().for_each(|b| {
            prover.commit(*value, *b).0;
        });

        prover.prove(&bp_gens).map_err(Error::from)
    }

    pub fn verify(&self, proof: &R1CSProof) -> Result<(), Error> {
        let (pc_gens, bp_gens, mut transcript) = gen_cs_transcript();
        let mut verifier = Verifier::new(&mut transcript);

        self.commitments.iter().for_each(|c| {
            verifier.commit(*c);
        });

        verifier
            .verify(&proof, &pc_gens, &bp_gens)
            .map_err(Error::from)
    }

    pub fn commitments(&self) -> &Vec<CompressedRistretto> {
        &self.commitments
    }

    pub fn blinding_factors(&self) -> &Vec<Scalar> {
        &self.blinding_factors
    }
}
