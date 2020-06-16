use crate::{crypto, zk, BlsScalar};

use hades252::strategies::GadgetStrategy;
use hades252::strategies::Strategy;
use poseidon252::sponge::sponge::sponge_hash_gadget;

/// Verify the merkle opening
pub fn merkle(mut composer: zk::Composer, tx: &zk::ZkTransaction) -> zk::Composer {
    let zero = *tx.zero();
    let mut perm = [zero; hades252::WIDTH];

    for item in tx.inputs().iter() {
        // Bool bitflags
        item.merkle().levels().iter().for_each(|l| {
            let sum = l.bitflags().iter().fold(zero, |acc, b| {
                composer.bool_gate(*b);

                composer.add(
                    (BlsScalar::one(), acc),
                    (-BlsScalar::one(), *b),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                )
            });

            composer.add_gate(
                sum,
                zero,
                zero,
                BlsScalar::one(),
                BlsScalar::one(),
                BlsScalar::one(),
                BlsScalar::zero(),
                BlsScalar::one(),
            );
        });

        // Grant `current` is indexed correctly on the leaves
        item.merkle().levels().iter().for_each(|l| {
            let c = *l.current();

            l.bitflags()
                .iter()
                .zip(l.perm().iter().skip(1))
                .for_each(|(b, p)| {
                    let x_prime = composer.mul(
                        -BlsScalar::one(),
                        *b,
                        c,
                        BlsScalar::zero(),
                        BlsScalar::zero(),
                    );

                    let x = composer.mul(
                        -BlsScalar::one(),
                        *b,
                        *p,
                        BlsScalar::zero(),
                        BlsScalar::zero(),
                    );

                    composer.add_gate(
                        x,
                        x_prime,
                        zero,
                        BlsScalar::one(),
                        -BlsScalar::one(),
                        BlsScalar::one(),
                        BlsScalar::zero(),
                        BlsScalar::zero(),
                    );
                });
        });

        // Perform the chain hash towards the merkle root
        let mut prev_hash = *item.note_hash();
        for l in item.merkle().levels().iter() {
            composer.add_gate(
                *l.current(),
                prev_hash,
                zero,
                BlsScalar::one(),
                -BlsScalar::one(),
                BlsScalar::one(),
                BlsScalar::zero(),
                BlsScalar::zero(),
            );

            perm.copy_from_slice(l.perm());

            let output = sponge_hash_gadget(&mut composer, &perm);
            prev_hash = output;
        }

        composer.add_gate(
            item.merkle().levels()[crypto::TREE_HEIGHT - 1].perm()[1],
            zero,
            zero,
            -BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            *item.merkle_root(),
        );
    }

    composer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, utils, zk, Note, NoteGenerator, SecretKey, Transaction, TransparentNote};

    #[test]
    fn merkle_gadget() {
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
        let value = 5;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let mut composer = zk::Composer::new();

        let zk_tx = zk::ZkTransaction::from_tx(&mut composer, &tx);

        let mut composer = merkle(composer, &zk_tx);
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
