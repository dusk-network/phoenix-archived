use crate::{
    crypto, utils, BlsScalar, Db, Error, Transaction, MAX_INPUT_NOTES_PER_TRANSACTION,
    MAX_OUTPUT_NOTES_PER_TRANSACTION,
};

use std::mem::{self, MaybeUninit};

use algebra::bytes::{FromBytes, ToBytes};
use algebra::curves::bls12_381::Bls12_381;
use algebra::curves::bls12_381::G1Affine;
use ff_fft::EvaluationDomain;
use kelvin::Blake2b;
use merlin::Transcript;
use num_traits::Zero;
use plonk::cs::composer::StandardComposer;
use plonk::cs::{proof::Proof as PlonkProof, Composer as _, PreProcessedCircuit};
use plonk::srs;
use poly_commit::kzg10::{Commitment, Powers, VerifierKey};

pub use plonk::cs::constraint_system::Variable;

/// [`ZkTransaction`] definition
pub mod transaction;

pub use transaction::{ZkTransaction, ZkTransactionInput, ZkTransactionOutput};

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
    crypto::TREE_HEIGHT * (5 * crypto::ARITY + 2 + HADES_SIZE)
};

lazy_static::lazy_static! {
    static ref DOMAIN: EvaluationDomain<BlsScalar> = unsafe { mem::zeroed() };
    static ref CK: Powers<'static, Bls12_381> = unsafe { mem::zeroed() };
    static ref VK: VerifierKey<Bls12_381> = unsafe { mem::zeroed() };
    static ref TRANSCRIPT: Transcript = unsafe { mem::zeroed() };
    static ref PREPROCESSED_CIRCUIT: MaybeUninit<Circuit> =
        MaybeUninit::uninit();
}

pub type Circuit = PreProcessedCircuit<Bls12_381>;
pub type Composer = StandardComposer<Bls12_381>;
pub type Proof = PlonkProof<Bls12_381>;

pub const SERIALIZED_PROOF_SIZE: usize = 1097;

/// Circuit gadgets
pub mod gadgets;

#[cfg(test)]
mod tests;

/// Serialize a proof into bytes
pub fn proof_to_bytes(proof: &Proof) -> Result<[u8; SERIALIZED_PROOF_SIZE], Error> {
    let mut bytes = [0xf5u8; SERIALIZED_PROOF_SIZE];

    let mut bytes_commitments = bytes.chunks_mut(97);

    proof
        .a_comm
        .write(bytes_commitments.next().ok_or(Error::InvalidParameters)?)?;
    proof
        .b_comm
        .write(bytes_commitments.next().ok_or(Error::InvalidParameters)?)?;
    proof
        .c_comm
        .write(bytes_commitments.next().ok_or(Error::InvalidParameters)?)?;
    proof
        .z_comm
        .write(bytes_commitments.next().ok_or(Error::InvalidParameters)?)?;
    proof
        .t_lo_comm
        .write(bytes_commitments.next().ok_or(Error::InvalidParameters)?)?;
    proof
        .t_mid_comm
        .write(bytes_commitments.next().ok_or(Error::InvalidParameters)?)?;
    proof
        .t_hi_comm
        .write(bytes_commitments.next().ok_or(Error::InvalidParameters)?)?;
    proof
        .w_z_comm
        .write(bytes_commitments.next().ok_or(Error::InvalidParameters)?)?;
    proof
        .w_zw_comm
        .write(bytes_commitments.next().ok_or(Error::InvalidParameters)?)?;

    let mut bytes_scalars = (&mut bytes[9 * 97..]).chunks_mut(32);

    proof
        .a_eval
        .write(bytes_scalars.next().ok_or(Error::InvalidParameters)?)?;
    proof
        .b_eval
        .write(bytes_scalars.next().ok_or(Error::InvalidParameters)?)?;
    proof
        .c_eval
        .write(bytes_scalars.next().ok_or(Error::InvalidParameters)?)?;
    proof
        .left_sigma_eval
        .write(bytes_scalars.next().ok_or(Error::InvalidParameters)?)?;
    proof
        .right_sigma_eval
        .write(bytes_scalars.next().ok_or(Error::InvalidParameters)?)?;
    proof
        .lin_poly_eval
        .write(bytes_scalars.next().ok_or(Error::InvalidParameters)?)?;
    proof
        .z_hat_eval
        .write(bytes_scalars.next().ok_or(Error::InvalidParameters)?)?;

    Ok(bytes)
}

/// Deserialize a [`Proof`] from a slice with up to 1097 bytes
pub fn bytes_to_proof(bytes: &[u8]) -> Result<Proof, Error> {
    let mut bytes_commitments = bytes.chunks(97);

    let a_comm = Commitment(G1Affine::read(
        bytes_commitments.next().ok_or(Error::InvalidParameters)?,
    )?);
    let b_comm = Commitment(G1Affine::read(
        bytes_commitments.next().ok_or(Error::InvalidParameters)?,
    )?);
    let c_comm = Commitment(G1Affine::read(
        bytes_commitments.next().ok_or(Error::InvalidParameters)?,
    )?);
    let z_comm = Commitment(G1Affine::read(
        bytes_commitments.next().ok_or(Error::InvalidParameters)?,
    )?);
    let t_lo_comm = Commitment(G1Affine::read(
        bytes_commitments.next().ok_or(Error::InvalidParameters)?,
    )?);
    let t_mid_comm = Commitment(G1Affine::read(
        bytes_commitments.next().ok_or(Error::InvalidParameters)?,
    )?);
    let t_hi_comm = Commitment(G1Affine::read(
        bytes_commitments.next().ok_or(Error::InvalidParameters)?,
    )?);
    let w_z_comm = Commitment(G1Affine::read(
        bytes_commitments.next().ok_or(Error::InvalidParameters)?,
    )?);
    let w_zw_comm = Commitment(G1Affine::read(
        bytes_commitments.next().ok_or(Error::InvalidParameters)?,
    )?);

    let mut bytes_scalars = (&bytes[9 * 97..]).chunks(32);

    let a_eval = BlsScalar::read(bytes_scalars.next().ok_or(Error::InvalidParameters)?)?;
    let b_eval = BlsScalar::read(bytes_scalars.next().ok_or(Error::InvalidParameters)?)?;
    let c_eval = BlsScalar::read(bytes_scalars.next().ok_or(Error::InvalidParameters)?)?;
    let left_sigma_eval = BlsScalar::read(bytes_scalars.next().ok_or(Error::InvalidParameters)?)?;
    let right_sigma_eval = BlsScalar::read(bytes_scalars.next().ok_or(Error::InvalidParameters)?)?;
    let lin_poly_eval = BlsScalar::read(bytes_scalars.next().ok_or(Error::InvalidParameters)?)?;
    let z_hat_eval = BlsScalar::read(bytes_scalars.next().ok_or(Error::InvalidParameters)?)?;

    Ok(Proof {
        a_comm,
        b_comm,
        c_comm,
        z_comm,
        t_lo_comm,
        t_mid_comm,
        t_hi_comm,
        w_z_comm,
        w_zw_comm,
        a_eval,
        b_eval,
        c_eval,
        left_sigma_eval,
        right_sigma_eval,
        lin_poly_eval,
        z_hat_eval,
    })
}

/// Initialize the zk static data
pub fn init() {
    const CAPACITY: usize = 32768 * 2;

    let public_parameters = srs::setup(CAPACITY, &mut utils::generate_rng(b"phoenix-plonk-srs"));
    let (ck, vk) = srs::trim(&public_parameters, CAPACITY).unwrap();
    let domain: EvaluationDomain<BlsScalar> = EvaluationDomain::new(CAPACITY).unwrap();

    unsafe {
        utils::lazy_static_write(&*DOMAIN, domain);
        utils::lazy_static_write(&*CK, ck);
        utils::lazy_static_write(&*VK, vk);
    }

    let mut tx = Transaction::default();
    let (transcript, _, circuit) = gen_circuit(&mut tx);

    unsafe {
        utils::lazy_static_write(&*TRANSCRIPT, transcript);
        utils::lazy_static_maybeuninit_write(&*PREPROCESSED_CIRCUIT, circuit);
    }
}

/// Generate a new circuit
pub fn gen_circuit(tx: &mut Transaction) -> (Transcript, Composer, Circuit) {
    let mut transcript = gen_transcript();
    let mut composer = Composer::new();

    let db: Db<Blake2b> = Db::default();
    let tx_zk = ZkTransaction::from_tx(&mut composer, tx, &db);
    let pi = tx.public_inputs_mut().iter_mut();

    #[cfg(feature = "circuit-merkle")]
    let (composer, pi) = gadgets::merkle(composer, &tx_zk, pi);

    #[cfg(feature = "circuit-preimage")]
    let (composer, pi) = gadgets::preimage(composer, &tx_zk, pi);

    #[cfg(feature = "circuit-balance")]
    let (composer, pi) = gadgets::balance(composer, &tx_zk, pi);

    #[cfg(feature = "circuit-nullifier")]
    let (composer, pi) = gadgets::nullifier(composer, &tx_zk, pi);

    #[cfg(feature = "circuit-skr")]
    let composer = gadgets::sk_r(composer, &tx_zk);

    let mut pi = pi;
    let mut composer = composer;

    pi.next().map(|p| *p = BlsScalar::zero());
    composer.add_dummy_constraints();

    let circuit = composer.preprocess(&*CK, &mut transcript, &*DOMAIN);

    (transcript, composer, circuit)
}

/// Full transaction circuit
pub fn circuit() -> &'static Circuit {
    unsafe { &*PREPROCESSED_CIRCUIT.as_ptr() }
}

fn gen_transcript() -> Transcript {
    Transcript::new(b"dusk-phoenix-plonk")
}

/// Generate a new transaction zk proof
pub fn prove(tx: &mut Transaction) -> Proof {
    let (mut transcript, mut composer, circuit) = gen_circuit(tx);
    composer.prove(&*CK, &circuit, &mut transcript)
}

/// Verify a proof with a pre-generated circuit
pub fn verify(proof: &Proof, pi: &[BlsScalar]) -> bool {
    let mut transcript = TRANSCRIPT.clone();
    let preprocessed_circuit = circuit();

    proof.verify(preprocessed_circuit, &mut transcript, &*VK, &pi.to_vec())
}
