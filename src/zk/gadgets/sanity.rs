use crate::BlsScalar;

use dusk_plonk::constraint_system::StandardComposer;
use jubjub;
use jubjub::GENERATOR;

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
        tx.push_input(note.to_transaction_input(merkle_opening, sk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 95;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 2;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 3;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.set_fee(note.to_transaction_output(value, blinding_factor, pk));

        let mut composer = zk::Composer::new();

        let mut composer = StandardComposer::new();

        let mut composer = sanity(composer, &zk_tx);
        let mut transcript = zk::TRANSCRIPT.clone();

        composer.add_dummy_constraints();
        let circuit = composer.preprocess(&zk::CK, &mut transcript, &zk::DOMAIN);

        let proof = composer.prove(&zk::CK, &circuit, &mut transcript);

        assert!(proof.verify(
            &circuit,
            &mut transcript,
            &zk::VK,
            &composer.public_inputs()
        ));
    }
}
