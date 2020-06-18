use crate::{zk, BlsScalar};

use jubjub::GENERATOR;

/// Perform the pre-image of the value commitment and check if the inputs equals the outputs + fee
pub fn sanity(mut composer: zk::Composer, tx: &zk::ZkTransaction) -> zk::Composer {
    let basepoint = GENERATOR;
    let basepoint_affine_xy = basepoint.get_x() * basepoint.get_y();

    composer.add_gate(
        *tx.basepoint_affine_x(),
        *tx.zero(),
        *tx.zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        basepoint.get_x(),
    );

    composer.add_gate(
        *tx.basepoint_affine_y(),
        *tx.zero(),
        *tx.zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        basepoint.get_y(),
    );

    composer.add_gate(
        *tx.basepoint_affine_xy(),
        *tx.zero(),
        *tx.zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        basepoint_affine_xy,
    );

    composer.add_gate(
        *tx.zero(),
        *tx.zero(),
        *tx.zero(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    composer.add_gate(
        *tx.one(),
        *tx.zero(),
        *tx.zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::one(),
    );

    composer.add_gate(
        *tx.two(),
        *tx.zero(),
        *tx.zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::from(2u64),
    );

    composer.add_gate(
        *tx.three(),
        *tx.zero(),
        *tx.zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::from(3u64),
    );

    composer.add_gate(
        *tx.fifteen(),
        *tx.zero(),
        *tx.zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::from(15u64),
    );

    composer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, zk, Note, NoteGenerator, SecretKey, Transaction, TransparentNote};

    #[test]
    fn sanity_gadget() {
        zk::init();

        let mut tx = Transaction::default();

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

        let mut composer = dusk_plonk::constraint_system::StandardComposer::new();

        let zk_tx = zk::ZkTransaction::from_tx(&mut composer, &tx);

        let mut composer = sanity(composer, &zk_tx);
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
