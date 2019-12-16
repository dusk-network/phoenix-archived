use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;

pub use value::Value;

mod value;

#[cfg(test)]
mod tests;

/// Generate the constraint system and the transcript for the zk proofs
pub fn gen_cs_transcript() -> (PedersenGens, BulletproofGens, Transcript) {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);
    let transcript = Transcript::new(b"phoenix-transcript-for-zk");

    (pc_gens, bp_gens, transcript)
}
