use crate::{BlsScalar, TransactionItem};

use dusk_plonk::constraint_system::StandardComposer;

pub fn range<T: TransactionItem>(composer: &mut StandardComposer, item: &T) {
    let value = composer.add_input(BlsScalar::from(item.value()));
    composer.range_gate(value, 64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, Note, NoteGenerator, SecretKey, TransparentNote};

    #[test]
    fn range_gadget() {
        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 100;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        let input = note.to_transaction_input(merkle_opening, sk);

        let mut composer = StandardComposer::new();

        range(&mut composer, &input);
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
