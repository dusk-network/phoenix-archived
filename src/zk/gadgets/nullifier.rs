use crate::{BlsScalar, Note, TransactionInput, TransactionItem};

use dusk_plonk::constraint_system::StandardComposer;
use poseidon252::sponge::sponge::sponge_hash_gadget;

/// Prove knowledge of the input nullifier
pub fn nullifier(composer: &mut StandardComposer, input: &TransactionInput) {
    let sk_r = input.note().sk_r(input.sk());
    let sk_r = composer.add_input(BlsScalar::from_bytes(&sk_r.to_bytes()).unwrap());
    let idx = composer.add_input(BlsScalar::from(input.note().idx()));

    let output = sponge_hash_gadget(composer, &[sk_r, idx]);

    composer.add_gate(
        output,
        composer.zero_var,
        composer.zero_var,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::from_bytes(&input.nullifier().to_bytes()).unwrap(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, Note, NoteGenerator, SecretKey, Transaction, TransparentNote};
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::fft::EvaluationDomain;
    use merlin::Transcript;

    #[test]
    fn nullifier_gadget() {
        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 100;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        let input = note.to_transaction_input(merkle_opening, sk);

        let mut composer = StandardComposer::new();

        nullifier(&mut composer, &input);

        composer.add_dummy_constraints();

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

    #[test]
    fn tx_input_nullifier_invalid() {
        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 61;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        let mut txi = note.to_transaction_input(merkle_opening, sk);
        // Mess up the nullifier
        txi.nullifier = note.generate_nullifier(&SecretKey::default());

        let mut composer = StandardComposer::new();

        nullifier(&mut composer, &txi);

        composer.add_dummy_constraints();

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

        assert!(!proof.verify(&circuit, &mut transcript, &vk, &composer.public_inputs()));
    }
}
