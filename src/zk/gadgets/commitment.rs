use crate::{NoteVariant, TransactionItem, ViewKey};

use dusk_plonk::constraint_system::StandardComposer;

/// Prove knowledge of the value and blinding factor, which make up the value commitment.
pub fn commitment<T: TransactionItem>(composer: &mut StandardComposer, item: &T) {
    // let value = composer.add_input(BlsScalar::from(item.value()));
    // let blinding_factor = composer.add_input(item.blinding_factor());

    // let output = sponge_hash_gadget(composer, &[value, blinding_factor]);

    // let commitment = composer.add_input(*note.value_commitment());
    // composer.add_gate(
    //     output,
    //     commitment,
    //     composer.zero_var,
    //     -BlsScalar::one(),
    //     BlsScalar::one(),
    //     BlsScalar::one(),
    //     BlsScalar::zero(),
    //     BlsScalar::zero(),
    // );
    //
    // NOTE:
    // We are currently mocking the commitment gadget, as we are still missing the ECC gate
    // implementation.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, Note, NoteGenerator, SecretKey, TransparentNote};
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::fft::EvaluationDomain;
    use merlin::Transcript;

    #[test]
    fn commitment_gadget() {
        let sk = SecretKey::default();
        let vk = sk.view_key();
        let pk = sk.public_key();
        let value = 100;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        let input = note.to_transaction_input(merkle_opening, sk).unwrap();

        let mut composer = StandardComposer::new();

        commitment(&mut composer, &input);
        composer.add_dummy_constraints();
        // NOTE: this is here to make the test pass, as one set of dummy constraints
        // isn't enough when no extra gates are added. It should be removed once the
        // commitment gadget is properly implemented.
        composer.add_dummy_constraints();
        ////////////////////////////////////////////////////////////////////////////

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
