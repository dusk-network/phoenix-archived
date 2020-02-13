use super::gen_cs_transcript;
use crate::{utils, CompressedRistretto, Error, Prover, R1CSProof, Scalar, Verifier};

use rand::rngs::OsRng;

#[derive(Debug, Clone)]
/// A phoenix zero-knowledge value corresponding to a blinding factor and a commitment point
pub struct Value {
    commitment: CompressedRistretto,
    blinding_factor: Scalar,
}

impl Value {
    /// [`Value`] constructor
    pub fn new<S: Into<Scalar>>(value: S) -> Self {
        Value::with_blinding_factor(value, utils::gen_random_clamped_scalar())
    }

    /// Deterministically create a new zk value provided the value and a blinding factor
    pub fn with_blinding_factor<S: Into<Scalar>>(value: S, blinding_factor: Scalar) -> Self {
        let (pc_gens, _, mut transcript) = gen_cs_transcript();
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let value: Scalar = value.into();
        let commitment = prover.commit(value, blinding_factor).0;

        Value::with_commitment_and_blinding_factor(commitment, blinding_factor)
    }

    /// Deterministically create a new zk value from a commitment point. The value will have a
    /// masked blinding factor
    pub fn with_commitment(commitment: CompressedRistretto) -> Self {
        Value::with_commitment_and_blinding_factor(commitment, Scalar::one())
    }

    /// Deterministically create a new zk value from a commitment point and blinding factor
    pub fn with_commitment_and_blinding_factor(
        commitment: CompressedRistretto,
        blinding_factor: Scalar,
    ) -> Self {
        Value {
            commitment,
            blinding_factor,
        }
    }

    /// Prove the knowledge of the value
    pub fn prove<S: Into<Scalar>>(&self, value: S) -> Result<R1CSProof, Error> {
        let value: Scalar = value.into();

        let (pc_gens, bp_gens, mut transcript) = gen_cs_transcript();
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        prover.commit(value, self.blinding_factor);

        prover.prove(&bp_gens).map_err(Error::from)
    }

    /// Verify the inner commitment point and blinding factor against an expected value
    pub fn verify(&self, proof: &R1CSProof) -> Result<(), Error> {
        let (pc_gens, bp_gens, mut transcript) = gen_cs_transcript();
        let mut verifier = Verifier::new(&mut transcript);

        verifier.commit(self.commitment);

        verifier
            .verify(&proof, &pc_gens, &bp_gens, &mut OsRng)
            .map_err(Error::from)
    }

    /// Zk commitment point
    pub fn commitment(&self) -> &CompressedRistretto {
        &self.commitment
    }

    /// Blinding factor used to create the commitment point.
    ///
    /// Warning: its trivial to reconstruct the value provided the blinding factor and a commitment
    /// point
    pub fn blinding_factor(&self) -> &Scalar {
        &self.blinding_factor
    }
}
