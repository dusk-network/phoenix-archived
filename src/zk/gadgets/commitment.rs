use crate::{zk, BlsScalar, Note, NoteVariant, TransactionInput, TransactionItem, ViewKey};

use dusk_plonk::constraint_system::StandardComposer;
use poseidon252::sponge::sponge::sponge_hash_gadget;

pub fn commitment(composer: &mut StandardComposer, note: &NoteVariant, vk: Option<&ViewKey>) {
    let zero = composer.add_input(BlsScalar::zero());
    let value = composer.add_input(BlsScalar::from(note.value(vk)));
    let blinding_factor = composer.add_input(note.blinding_factor(vk));

    let output = sponge_hash_gadget(composer, &[value, blinding_factor]);

    let commitment = composer.add_input(*note.value_commitment());
    composer.add_gate(
        output,
        commitment,
        zero,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, utils, zk, Note, NoteGenerator, SecretKey, Transaction, TransparentNote};

    #[test]
    fn commitment_gadget() {
        let sk = SecretKey::default();
        let vk = sk.view_key();
        let pk = sk.public_key();
        let value = 100;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        let input = note.to_transaction_input(merkle_opening, sk);

        let mut composer = dusk_plonk::constraint_system::StandardComposer::new();

        commitment(&mut composer, input.note(), Some(&vk));
        composer.add_dummy_constraints();
        use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
        use dusk_plonk::fft::EvaluationDomain;
        use merlin::Transcript;

        // Generate Composer & Public Parameters
        let pub_params = PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = pub_params.trim(1 << 16).unwrap();
        let mut transcript = Transcript::new(b"TEST");

        let circuit = composer.preprocess(
            &ck,
            &mut transcript,
            &EvaluationDomain::new(composer.circuit_size()).unwrap(),
        );

        let proof = composer.prove(&ck, &circuit, &mut transcript.clone());

        assert!(proof.verify(&circuit, &mut transcript, &vk, &composer.public_inputs()));
    }
}
