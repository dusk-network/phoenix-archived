use crate::{zk, BlsScalar};

use hades252::strategies::GadgetStrategy;
use hades252::strategies::Strategy;
use poseidon252::sponge::sponge::sponge_hash_gadget;

/// Prove the pre-image of the notes
///
/// The output notes will be validated as public inputs
///
/// The fee is not validated because its R and pk_r is updated by the block generator
pub fn preimage(mut composer: zk::Composer, tx: &zk::ZkTransaction) -> zk::Composer {
    let zero = *tx.zero();
    let zero_perm = [zero; hades252::WIDTH];
    let mut perm = [zero; hades252::WIDTH];

    for item in tx.inputs().iter() {
        perm.copy_from_slice(&zero_perm);
        perm[0] = *item.value_commitment();
        perm[1] = *item.idx();
        perm[2] = *item.pk_r_affine_x();
        perm[3] = *item.pk_r_affine_y();
        let output = sponge_hash_gadget(&mut composer, &perm);

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

    for item in tx.outputs().iter() {
        composer.add_gate(
            *item.pk_r_affine_x(),
            zero,
            zero,
            -BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            *item.pk_r_affine_x_scalar(),
        );
    }

    composer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, utils, zk, Note, NoteGenerator, SecretKey, Transaction, TransparentNote};

    #[test]
    fn preimage_gadget() {
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

        let zk_tx = zk::ZkTransaction::from_tx(&mut composer, &tx);

        let mut composer = preimage(composer, &zk_tx);
        composer.add_dummy_constraints();

        let mut transcript = zk::TRANSCRIPT.clone();
        let circuit = composer.preprocess(&zk::CK, &mut transcript, &zk::DOMAIN);

        composer.check_circuit_satisfied();

        let proof = composer.prove(&zk::CK, &circuit, &mut transcript);

        assert!(proof.verify(
            &circuit,
            &mut transcript,
            &zk::VK,
            &composer.public_inputs()
        ));
    }
}
