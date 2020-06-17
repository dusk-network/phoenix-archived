use crate::{zk, BlsScalar};

use poseidon252::sponge::sponge::sponge_hash_gadget;

/// TODO: revise comment
/// Prove the pre-image of the notes
///
/// The fee is not validated because its R and pk_r is updated by the block generator
pub fn preimage(composer: &mut zk::Composer, tx: &zk::ZkTransaction) {
    let zero = *tx.zero();
    let zero_perm = [zero; hades252::WIDTH];
    let mut perm = [zero; hades252::WIDTH];

    for item in tx.inputs().iter() {
        perm.copy_from_slice(&zero_perm);
        perm[0] = *item.value_commitment();
        perm[1] = *item.idx();
        perm[2] = *item.pk_r_affine_x();
        perm[3] = *item.pk_r_affine_y();
        let output = sponge_hash_gadget(composer, &perm);

        composer.add_gate(
            output,
            *item.note_hash(),
            zero,
            -BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
    }
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
    use crate::{crypto, utils, zk, Note, NoteGenerator, SecretKey, Transaction, TransparentNote};

    #[test]
    fn preimage_gadget() {
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

        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 2;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let mut composer = dusk_plonk::constraint_system::StandardComposer::new();
        let zk_tx = zk::ZkTransaction::from_tx(&mut composer, &tx);

        preimage(&mut composer, &zk_tx);
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

        assert!(proof.verify(&circuit, &mut transcript, &vk, &[BlsScalar::zero()]));
    }
}
