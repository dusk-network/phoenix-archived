use crate::Scalar;

use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;
use rand::rngs::OsRng;
use rand::RngCore;

pub use phoenix_value::PhoenixValue;

mod phoenix_value;

#[cfg(test)]
mod tests;

/// Generate the constraint system and the transcript for the zk proofs
pub fn gen_cs_transcript() -> (PedersenGens, BulletproofGens, Transcript) {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);
    let transcript = Transcript::new(b"phoenix-transcript-for-zk");

    (pc_gens, bp_gens, transcript)
}

pub fn gen_random_scalar() -> Scalar {
    let mut s = [0x00u8; 32];
    OsRng.fill_bytes(&mut s);
    Scalar::from_bits(s)
}
