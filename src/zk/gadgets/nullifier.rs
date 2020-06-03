use crate::{zk, BlsScalar};

use hades252::strategies::GadgetStrategy;

/// Validate the input nullifiers
pub fn nullifier<'a, P>(
    mut composer: zk::Composer,
    tx: &zk::ZkTransaction,
    mut pi: P,
) -> (zk::Composer, P)
where
    P: Iterator<Item = &'a mut BlsScalar>,
{
    let zero = *tx.zero();
    let one = *tx.one();
    let two = *tx.two();

    let mut zero_perm = [zero; hades252::WIDTH];
    let mut perm = [zero; hades252::WIDTH];

    zero_perm[0] = *tx.three();

    for item in tx.inputs().iter() {
        let mut sk_r_prime = *tx.zero();

        item.sk_r().iter().fold(one, |mut acc, bit| {
            pi.next().map(|p| *p = BlsScalar::zero());
            composer.bool_gate(*bit);

            pi.next().map(|p| *p = BlsScalar::zero());
            acc = composer.mul(
                BlsScalar::one(),
                acc,
                two,
                BlsScalar::zero(),
                BlsScalar::zero(),
            );

            // TODO - The next two gates can be reduced to one with the ability to evaluate the
            // current sk_r_prime for the output of a poly_gate
            pi.next().map(|p| *p = BlsScalar::zero());
            let dif = composer.mul(
                BlsScalar::one(),
                acc,
                *bit,
                BlsScalar::zero(),
                BlsScalar::zero(),
            );

            pi.next().map(|p| *p = BlsScalar::zero());
            sk_r_prime = composer.add(
                (BlsScalar::one(), sk_r_prime),
                (BlsScalar::one(), dif),
                BlsScalar::zero(),
                BlsScalar::zero(),
            );

            acc
        });

        perm.copy_from_slice(&zero_perm);
        perm[1] = sk_r_prime;
        perm[2] = *item.idx();
        let n = GadgetStrategy::poseidon_gadget(&mut composer, &mut perm);

        pi.next().map(|p| *p = *item.nullifier());
        composer.add_gate(
            n,
            zero,
            zero,
            -BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            *item.nullifier(),
        );
    }

    (composer, pi)
}

#[cfg(test)]
mod tests {
    use crate::{crypto, utils, zk, Note, NoteGenerator, SecretKey, Transaction, TransparentNote};

    #[test]
    fn tx_input_nullifier_invalid() {
        utils::init();
        zk::init();

        let mut tx = Transaction::default();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 61;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        let mut txi = note.to_transaction_input(merkle_opening, sk);
        txi.nullifier = note.generate_nullifier(&SecretKey::default());
        tx.push_input(txi).unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 22;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 24;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 15;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.set_fee(note.to_transaction_output(value, blinding_factor, pk));

        tx.prove().unwrap();
        assert!(tx.verify().is_err());
    }
}
