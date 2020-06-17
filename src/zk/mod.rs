use crate::{
    crypto, utils, BlsScalar, Transaction, MAX_INPUT_NOTES_PER_TRANSACTION,
    MAX_OUTPUT_NOTES_PER_TRANSACTION,
};

use std::mem::{self, MaybeUninit};

use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
use dusk_plonk::commitment_scheme::kzg10::{ProverKey, VerifierKey};
pub use dusk_plonk::constraint_system::composer::StandardComposer as Composer;
use dusk_plonk::fft::EvaluationDomain;
use merlin::Transcript;

pub use dusk_plonk::constraint_system::Variable;
pub use dusk_plonk::proof_system::{PreProcessedCircuit, Proof};

/// [`ZkMerkleProof`] definition
pub mod merkle;
/// [`ZkPublicInputs`] defintion
pub mod public_inputs;
/// [`ZkTransaction`] definition
pub mod transaction;

pub use merkle::ZkMerkleProof;
pub use public_inputs::ZkPublicInputs;
pub use transaction::{ZkTransaction, ZkTransactionInput, ZkTransactionOutput};

pub const CAPACITY: usize = 8192 * 8;

/// Length of the public inputs
#[rustfmt::skip]
pub const PI_LEN: usize = {

    const HADES_SIZE: usize = hades252::strategies::gadget::PI_SIZE;
    const MAX_NOTES: usize = MAX_INPUT_NOTES_PER_TRANSACTION + MAX_OUTPUT_NOTES_PER_TRANSACTION;
    const MAX_NOTES_FEE: usize = MAX_NOTES + 1;

    // Notes preimage
    (HADES_SIZE * 3 + 1) * MAX_NOTES +

    // Tx balance
    (HADES_SIZE + 2) * MAX_NOTES_FEE + 1 +

    // Nullifier
    (HADES_SIZE + 1) * MAX_INPUT_NOTES_PER_TRANSACTION +

    // Merkle
    MAX_INPUT_NOTES_PER_TRANSACTION * crypto::TREE_HEIGHT * (5 * crypto::ARITY + 3 + HADES_SIZE)
};

lazy_static::lazy_static! {
    static ref DOMAIN: EvaluationDomain = unsafe { mem::zeroed() };
    static ref CK: ProverKey = unsafe { mem::zeroed() };
    static ref VK: VerifierKey = unsafe { mem::zeroed() };
    static ref TRANSCRIPT: Transcript = unsafe { mem::zeroed() };
    static ref PREPROCESSED_CIRCUIT: MaybeUninit<PreProcessedCircuit> =
        MaybeUninit::uninit();
    static ref PUBLIC_INPUTS: MaybeUninit<Vec<BlsScalar>> =
        MaybeUninit::uninit();
}

pub const SERIALIZED_PROOF_SIZE: usize = 1097;

/// Circuit gadgets
pub mod gadgets;

#[cfg(test)]
mod tests;

/// Initialize the ZK static data
pub fn init() {
    let public_parameters = PublicParameters::setup(
        CAPACITY,
        &mut utils::generate_rng(b"phoenix-plonk-PublicParameters"),
    )
    .unwrap();
    let (ck, vk) = PublicParameters::trim(&public_parameters, CAPACITY).unwrap();
    let domain: EvaluationDomain = EvaluationDomain::new(CAPACITY).unwrap();

    unsafe {
        utils::lazy_static_write(&*DOMAIN, domain);
        utils::lazy_static_write(&*CK, ck);
        utils::lazy_static_write(&*VK, vk);
    }

    let mut tx = Transaction::default();
    let mut pi = vec![BlsScalar::zero(); 54220];

    let composer = Composer::with_expected_size(CAPACITY);
    let mut composer = inner_circuit(composer, &mut tx, pi.iter_mut());

    let mut transcript = gen_transcript();
    let circuit = composer.preprocess(&*CK, &mut transcript, &*DOMAIN);

    unsafe {
        utils::lazy_static_write(&*TRANSCRIPT, transcript);
        utils::lazy_static_maybeuninit_write(&*PREPROCESSED_CIRCUIT, circuit);
        utils::lazy_static_maybeuninit_write(&*PUBLIC_INPUTS, pi);
    }
}

/// Full transaction circuit
pub fn circuit() -> &'static PreProcessedCircuit {
    unsafe { &*PREPROCESSED_CIRCUIT.as_ptr() }
}

/// Base public inputs vector
pub fn public_inputs() -> &'static Vec<BlsScalar> {
    unsafe { &*PUBLIC_INPUTS.as_ptr() }
}

fn inner_circuit<'a, P> (composer: Composer, _tx: &Transaction, _pi: P) -> Composer
where 
    P: Iterator<Item = &'a mut BlsScalar>,
{ /*
    
    let tx_zk = ZkTransaction::from_tx(&mut composer, tx);

    #[cfg(feature = "circuit-sanity")]
    let (_, pi) = gadgets::sanity(composer, &tx_zk, pi);

    #[cfg(feature = "circuit-merkle")]
    let (_, pi) = gadgets::merkle(composer, &tx_zk, pi);

    #[cfg(feature = "circuit-preimage")]
    let (_, pi) = gadgets::preimage(composer, &tx_zk, pi);

    #[cfg(feature = "circuit-balance")]
    let (_, pi) = gadgets::balance(composer, &tx_zk, pi);

    #[cfg(feature = "circuit-nullifier")]
    let (_, pi) = gadgets::nullifier(composer, &tx_zk, pi);

    #[cfg(feature = "circuit-skr")]
    let _ = gadgets::sk_r(composer, &tx_zk);

    let _ = tx_zk;
    let _ = pi;

    (0..composer.circuit_size()).for_each(|_| {
        composer.add_dummy_constraints();
    });
    
    */
    composer
}

fn gen_transcript() -> Transcript {
    Transcript::new(b"dusk-phoenix-plonk")
}

/// Generate a new transaction zk proof
pub fn prove(tx: &mut Transaction) -> Proof {
    let composer = Composer::with_expected_size(CAPACITY);
    let mut pi = public_inputs().clone();

    let mut composer = inner_circuit(composer, tx, pi.iter_mut());

    let mut transcript = TRANSCRIPT.clone();
    let preprocessed_circuit = circuit();

    composer.prove(&*CK, preprocessed_circuit, &mut transcript)
}

/// Verify a proof with a pre-generated circuit
pub fn verify(proof: &Proof, pi: &[BlsScalar]) -> bool {
    let mut transcript = TRANSCRIPT.clone();
    let preprocessed_circuit = circuit();

    proof.verify(preprocessed_circuit, &mut transcript, &*VK, &pi.to_vec())
}
