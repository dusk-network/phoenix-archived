use crate::{BlsScalar, Transaction};

use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
pub use dusk_plonk::constraint_system::{StandardComposer, Variable};
use dusk_plonk::fft::EvaluationDomain;
pub use dusk_plonk::proof_system::{PreProcessedCircuit, Proof};
use merlin::Transcript;

pub const CAPACITY: usize = 8192 * 8;

pub const SERIALIZED_PROOF_SIZE: usize = 1097;

mod circuits;

/// Circuit gadgets
pub mod gadgets;

mod public_inputs;
pub use public_inputs::ZkPublicInputs;

/// Generate a new transaction zk proof
pub fn prove(tx: &mut Transaction) -> Proof {
    let mut composer = StandardComposer::with_expected_size(CAPACITY);

    // TODO: use actual circuit
    composer.add_dummy_constraints();
    composer.add_dummy_constraints();

    let pub_params = PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
    let (ck, vk) = pub_params.trim(1 << 16).unwrap();
    let mut transcript = Transcript::new(b"dusk-phoenix");

    let circuit = composer.preprocess(
        &ck,
        &mut transcript,
        &EvaluationDomain::new(composer.circuit_size()).unwrap(),
    );

    composer.prove(&ck, &circuit, &mut transcript.clone())
}

/// Verify a proof with a pre-generated circuit
pub fn verify(proof: &Proof, pi: &[BlsScalar]) -> bool {
    // let mut transcript = TRANSCRIPT.clone();
    // let preprocessed_circuit = circuit();

    // proof.verify(preprocessed_circuit, &mut transcript, &*VK, &pi.to_vec())
    true
}
