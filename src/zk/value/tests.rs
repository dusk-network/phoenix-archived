use crate::{Idx, R1CSProof, Value};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

const IDX: Idx = Idx(15);
const VALUE: u64 = 35;
const WRONG_VALUE: u64 = 34;
lazy_static::lazy_static! {
    static ref PHOENIX_VALUE: Value = Value::new(IDX, VALUE);
    static ref COMMITMENT: CompressedRistretto = (&*PHOENIX_VALUE).commitment().clone();
    static ref BLINDING_FACTOR: Scalar = (&*PHOENIX_VALUE).blinding_factor().clone();
    static ref PROOF: R1CSProof = (&*PHOENIX_VALUE).prove(VALUE).unwrap();
}

#[test]
fn from_value() {
    // The owner of the note can produce the blinding factors and the commitment
    (&*PHOENIX_VALUE).verify(&*PROOF).unwrap();
}

#[test]
fn from_value_with_blinding_factor() {
    // The owner of the note can produce the commitment from previously generated blinding factors
    let phoenix_value = Value::with_blinding_factor(IDX, VALUE, (&*BLINDING_FACTOR).clone());
    let proof = phoenix_value.prove(VALUE).unwrap();
    phoenix_value.verify(&proof).unwrap();
}

#[test]
fn from_commitment_with_blinding_factor() {
    // Anyone with the public commitment and the decrypted blinding factors can produce a proof
    let phoenix_value = Value::with_commitment_and_blinding_factor(
        (&*COMMITMENT).clone(),
        (&*BLINDING_FACTOR).clone(),
    );
    let proof = phoenix_value.prove(VALUE).unwrap();
    phoenix_value.verify(&proof).unwrap();
}

#[test]
fn from_proof_with_commitment() {
    // Anyone with a proof and the public commitment can verify the proof
    let phoenix_value = Value::with_commitment((&*COMMITMENT).clone());
    phoenix_value.verify(&*PROOF).unwrap();
}

#[test]
fn error_from_proof_with_wrong_value() {
    // A proof produced with a wrong value cannot be verified
    let proof = (&*PHOENIX_VALUE).prove(WRONG_VALUE).unwrap();
    assert!((&*PHOENIX_VALUE).verify(&proof).is_err());
}

#[test]
fn error_from_proof_with_wrong_commitment() {
    // A valid proof cannot be verified with the wrong commitment
    let commitment = Value::new(IDX, WRONG_VALUE).commitment().clone();
    let phoenix_value = Value::with_commitment(commitment);
    assert!(phoenix_value.verify(&*PROOF).is_err());
}

#[test]
fn error_from_proof_with_wrong_blinding_factor() {
    // A valid proof cannot be produced with the wrong blinding factors
    let phoenix_value = Value::new(IDX, WRONG_VALUE);
    let blinding_factor = phoenix_value.blinding_factor().clone();

    assert_ne!(blinding_factor, *BLINDING_FACTOR);
    assert_ne!(phoenix_value.commitment(), &*COMMITMENT);

    let phoenix_value =
        Value::with_commitment_and_blinding_factor((&*COMMITMENT).clone(), blinding_factor.clone());

    let proof = phoenix_value.prove(VALUE).unwrap();
    assert!(phoenix_value.verify(&proof).is_err());
}
