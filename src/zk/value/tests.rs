use crate::{Idx, R1CSProof, Value};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

const IDX: Idx = Idx(15);
const VALUE: u64 = 35;
const WRONG_VALUE: u64 = 34;
lazy_static::lazy_static! {
    static ref PHOENIX_VALUE: Value = Value::new(IDX, VALUE);
    static ref COMMITMENTS: Vec<CompressedRistretto> = (&*PHOENIX_VALUE).commitments().clone();
    static ref BLINDING_FACTORS: Vec<Scalar> = (&*PHOENIX_VALUE).blinding_factors().clone();
    static ref PROOF: R1CSProof = (&*PHOENIX_VALUE).prove(VALUE).unwrap();
}

#[test]
fn from_value() {
    // The owner of the note can produce the blinding factors and the commitments
    (&*PHOENIX_VALUE).verify(&*PROOF).unwrap();
}

#[test]
fn from_value_with_blinding_factors() {
    // The owner of the note can produce the commitments from previously generated blinding factors
    let phoenix_value = Value::with_blinding_factors(IDX, VALUE, (&*BLINDING_FACTORS).clone());
    let proof = phoenix_value.prove(VALUE).unwrap();
    phoenix_value.verify(&proof).unwrap();
}

#[test]
fn from_commitments_with_blinding_factors() {
    // Anyone with the public commitments and the decrypted blinding factors can produce a proof
    let phoenix_value = Value::with_commitments_and_blinding_factors(
        (&*COMMITMENTS).clone(),
        (&*BLINDING_FACTORS).clone(),
    );
    let proof = phoenix_value.prove(VALUE).unwrap();
    phoenix_value.verify(&proof).unwrap();
}

#[test]
fn from_proof_with_commitments() {
    // Anyone with a proof and the public commitments can verify the proof
    let phoenix_value = Value::with_commitments((&*COMMITMENTS).clone());
    phoenix_value.verify(&*PROOF).unwrap();
}

#[test]
fn error_from_proof_with_wrong_value() {
    // A proof produced with a wrong value cannot be verified
    let proof = (&*PHOENIX_VALUE).prove(WRONG_VALUE).unwrap();
    assert!((&*PHOENIX_VALUE).verify(&proof).is_err());
}

#[test]
fn error_from_proof_with_wrong_commitments() {
    // A valid proof cannot be verified with the wrong commitments
    let commitments = Value::new(IDX, WRONG_VALUE).commitments().clone();
    let phoenix_value = Value::with_commitments(commitments);
    assert!(phoenix_value.verify(&*PROOF).is_err());
}

#[test]
fn error_from_proof_with_wrong_blinding_factors() {
    // A valid proof cannot be produced with the wrong blinding factors
    let phoenix_value = Value::new(IDX, WRONG_VALUE);
    let blinding_factors = phoenix_value.blinding_factors().clone();

    assert_ne!(blinding_factors, *BLINDING_FACTORS);
    assert_ne!(phoenix_value.commitments(), &*COMMITMENTS);

    let phoenix_value = Value::with_commitments_and_blinding_factors(
        (&*COMMITMENTS).clone(),
        blinding_factors.clone(),
    );

    let proof = phoenix_value.prove(VALUE).unwrap();
    assert!(phoenix_value.verify(&proof).is_err());
}
