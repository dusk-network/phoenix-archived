use crate::{BlsScalar, Note, TransactionInput, TransactionItem};

use dusk_plonk::constraint_system::StandardComposer;
use poseidon252::sponge::sponge::sponge_hash_gadget;

/// Prove knowledge of the pre-image of an input note
pub fn input_preimage(composer: &mut StandardComposer, input: &TransactionInput) {
    let value_commitment = composer.add_input(*input.note().value_commitment());
    let idx = composer.add_input(BlsScalar::from(input.note().idx()));
    let pk_r_affine_x = composer.add_input(input.note().pk_r().get_x());
    let pk_r_affine_y = composer.add_input(input.note().pk_r().get_y());
    let output = sponge_hash_gadget(
        composer,
        &[value_commitment, idx, pk_r_affine_x, pk_r_affine_y],
    );

    let note_hash = composer.add_input(input.note().hash());
    composer.add_gate(
        output,
        note_hash,
        composer.zero_var,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
}

// pub fn equivalence_gadget(composer: &mut zk::Composer, tx: &zk::ZkTransaction) {
//     composer.add(
//         (BlsScalar::one(), composer.zero_var),
//         (-BlsScalar::one(), tx.hash()),
//         BlsScalar::zero(),
//         tx.hash(),
//     );
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, Note, NoteGenerator, SecretKey, TransparentNote};
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::fft::EvaluationDomain;
    use merlin::Transcript;

    #[test]
    fn preimage_gadget() {
        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 100;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        let input = note.to_transaction_input(merkle_opening, sk);

        let mut composer = StandardComposer::new();

        input_preimage(&mut composer, &input);
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

        assert!(proof.verify(&circuit, &mut transcript, &vk, &[BlsScalar::zero()]));
    }
}
