// use crate::{
//     crypto, utils, BlsScalar, Transaction, MAX_INPUT_NOTES_PER_TRANSACTION,
//     MAX_OUTPUT_NOTES_PER_TRANSACTION,
// };

// use std::mem::{self, MaybeUninit};

// use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
// use dusk_plonk::commitment_scheme::kzg10::{ProverKey, VerifierKey};
// pub use dusk_plonk::constraint_system::composer::StandardComposer as Composer;
// use dusk_plonk::fft::EvaluationDomain;
// use merlin::Transcript;

pub use dusk_plonk::constraint_system::Variable;
pub use dusk_plonk::proof_system::{PreProcessedCircuit, Proof};

pub const CAPACITY: usize = 8192 * 8;

pub const SERIALIZED_PROOF_SIZE: usize = 1097;

/// Circuit gadgets
pub mod gadgets;

mod public_inputs;
pub use public_inputs::ZkPublicInputs;

// /// Generate a new transaction zk proof
// pub fn prove(tx: &mut Transaction) -> Proof {
//     let composer = Composer::with_expected_size(CAPACITY);
//     let mut pi = public_inputs().clone();

//     let mut composer = inner_circuit(composer, tx, pi.iter_mut());

//     let mut transcript = TRANSCRIPT.clone();
//     let preprocessed_circuit = circuit();

//     composer.prove(&*CK, preprocessed_circuit, &mut transcript)
// }

// /// Verify a proof with a pre-generated circuit
// pub fn verify(proof: &Proof, pi: &[BlsScalar]) -> bool {
//     let mut transcript = TRANSCRIPT.clone();
//     let preprocessed_circuit = circuit();

//     proof.verify(preprocessed_circuit, &mut transcript, &*VK, &pi.to_vec())
// }
