use crate::GENERATORS_CAPACITY;

use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;

pub use value::Value;

#[allow(clippy::module_inception)] // TODO
mod value;

#[cfg(test)]
mod tests;

/// Generate the constraint system and the transcript for the zk proofs
pub fn gen_cs_transcript() -> (PedersenGens, BulletproofGens, Transcript) {
    let pc_gens = PedersenGens::default();

    let bp_gens = BulletproofGens::new(GENERATORS_CAPACITY, 2);
    let transcript = Transcript::new(b"phoenix-transcript-for-zk");

    (pc_gens, bp_gens, transcript)
}
