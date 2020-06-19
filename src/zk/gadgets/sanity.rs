use crate::{BlsScalar};

use jubjub::GENERATOR;
use dusk_plonk::constraint_system::StandardComposer;
use jubjub;

/// Perform the pre-image of the value commitment and check if the inputs equals the outputs + fee
pub fn sanity(mut composer: &mut StandardComposer) {
    let basepoint = GENERATOR;
    let basepoint_affine_xy = basepoint.get_x() * basepoint.get_y();

    composer.add_gate(
        basepoint.get_x(),
        composer.zero_var,
        composer.zero_var,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        basepoint.get_x(),
    );

    composer.add_gate(
        basepoint.get_y(),
        composer.zero_var,
        composer.zero_var,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        basepoint.get_y(),
    );

    composer.add_gate(
        basepoint_affine_xy,
        composer.zero_var,
        composer.zero_var,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        basepoint_affine_xy,
    );

    composer.add_gate(
        composer.zero_var,
        composer.zero_var,
        composer.zero_var,
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    composer.add_gate(
        composer.add_input(BlsScalar::from(1u64)),
        composer.zero_var,
        composer.zero_var,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::one(),
    );

    composer.add_gate(
        composer.add_input(BlsScalar::from(2u64)),
        composer.zero_var,
        composer.zero_var,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::from(2u64),
    );

    composer.add_gate(
        composer.add_input(BlsScalar::from(3u64)),
        composer.zero_var,
        composer.zero_var,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::from(3u64),
    );

    composer.add_gate(
        composer.add_input(BlsScalar::from(15u64)),
        composer.zero_var,
        composer.zero_var,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::from(15u64),
    );

}

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
