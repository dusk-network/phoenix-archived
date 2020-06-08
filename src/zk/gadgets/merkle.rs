use crate::{crypto, zk, BlsScalar};

use hades252::strategies::GadgetStrategy;


/// Verify the merkle opening
pub fn merkle<'a, P>(
    mut composer: zk::Composer,
    tx: &zk::ZkTransaction,
    mut pi: P,
) -> (zk::Composer, P)
where
    P: Iterator<Item = &'a mut BlsScalar>,
{
    let zero = *tx.zero();
    let mut perm = [zero; hades252::WIDTH];

    for item in tx.inputs().iter() {
        // Bool bitflags
        item.merkle().levels().iter().for_each(|l| {
            let sum = l.bitflags().iter().fold(zero, |acc, b| {
                pi.next().map(|p| *p = BlsScalar::zero());
                composer.bool_gate(*b);

                pi.next().map(|p| *p = BlsScalar::zero());
                composer.add(
                    (BlsScalar::one(), acc),
                    (-BlsScalar::one(), *b),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                )
            });

            pi.next().map(|p| *p = BlsScalar::one());
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
                    pi.next().map(|p| *p = BlsScalar::zero());
                    let x_prime = composer.mul(
                        -BlsScalar::one(),
                        *b,
                        c,
                        BlsScalar::zero(),
                        BlsScalar::zero(),
                    );

                    pi.next().map(|p| *p = BlsScalar::zero());
                    let x = composer.mul(
                        -BlsScalar::one(),
                        *b,
                        *p,
                        BlsScalar::zero(),
                        BlsScalar::zero(),
                    );

                    pi.next().map(|p| *p = BlsScalar::zero());
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
            pi.next().map(|p| *p = BlsScalar::zero());
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
            let x = GadgetStrategy::poseidon_gadget(&mut composer, &mut perm);

            prev_hash = x;
        }

        pi.next().map(|p| *p = *item.merkle_root());
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

    (composer, pi)
}
