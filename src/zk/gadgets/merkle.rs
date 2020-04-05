use crate::{crypto, zk, BlsScalar};

use std::mem;

use hades252::strategies::GadgetStrategy;
use num_traits::{One, Zero};

#[derive(Debug, Clone, Copy)]
pub struct ZkMerkleProof {
    pub levels: [ZkMerkleLevel; crypto::TREE_HEIGHT],
}
impl ZkMerkleProof {
    pub fn new(composer: &mut zk::Composer, merkle: &crypto::MerkleProof) -> Self {
        let mut levels = [ZkMerkleLevel::default(); crypto::TREE_HEIGHT];
        let zero = composer.add_input(BlsScalar::zero());
        let one = composer.add_input(BlsScalar::one());
        let zero = [zero; crypto::ARITY];

        merkle
            .levels
            .iter()
            .zip(levels.iter_mut())
            .for_each(|(m, l)| {
                m.data
                    .iter()
                    .zip(l.perm.iter_mut())
                    .for_each(|(scalar, var)| {
                        *var = composer.add_input(*scalar);
                    });

                l.bitflags.copy_from_slice(&zero);
                l.bitflags[m.idx] = one;

                l.current = composer.add_input(m.data[m.idx + 1]);
            });

        Self { levels }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ZkMerkleLevel {
    pub bitflags: [zk::Variable; crypto::ARITY],
    pub perm: [zk::Variable; hades252::WIDTH],
    pub current: zk::Variable,
}

impl Default for ZkMerkleLevel {
    fn default() -> Self {
        Self {
            bitflags: [unsafe { mem::zeroed() }; crypto::ARITY],
            perm: [unsafe { mem::zeroed() }; hades252::WIDTH],
            current: unsafe { mem::zeroed() },
        }
    }
}

/// Verify the merkle opening
pub fn merkle<'a, P>(
    mut composer: zk::Composer,
    tx: &zk::ZkTransaction,
    mut pi: P,
) -> (zk::Composer, P)
where
    P: Iterator<Item = &'a mut BlsScalar>,
{
    let zero = tx.zero;
    let mut perm = [zero; hades252::WIDTH];

    for item in tx.inputs.iter() {
        // Bool bitflags
        item.merkle.levels.iter().for_each(|l| {
            let sum = l.bitflags.iter().fold(zero, |acc, b| {
                pi.next().map(|p| *p = BlsScalar::zero());
                composer.bool_gate(*b);

                pi.next().map(|p| *p = BlsScalar::zero());
                composer.add(
                    acc,
                    *b,
                    BlsScalar::one(),
                    -BlsScalar::one(),
                    BlsScalar::one(),
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
        item.merkle.levels.iter().for_each(|l| {
            let c = l.current;

            l.bitflags
                .iter()
                .zip(l.perm.iter().skip(1))
                .for_each(|(b, p)| {
                    pi.next().map(|p| *p = BlsScalar::zero());
                    let x_prime = composer.mul(
                        *b,
                        c,
                        -BlsScalar::one(),
                        BlsScalar::one(),
                        BlsScalar::zero(),
                        BlsScalar::zero(),
                    );

                    pi.next().map(|p| *p = BlsScalar::zero());
                    let x = composer.mul(
                        *b,
                        *p,
                        -BlsScalar::one(),
                        BlsScalar::one(),
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
        let mut prev_hash = item.note_hash;
        for l in item.merkle.levels.iter() {
            pi.next().map(|p| *p = BlsScalar::zero());
            composer.add_gate(
                l.current,
                prev_hash,
                zero,
                BlsScalar::one(),
                -BlsScalar::one(),
                BlsScalar::one(),
                BlsScalar::zero(),
                BlsScalar::zero(),
            );

            perm.copy_from_slice(&l.perm);
            let (p_composer, p_pi, x) = GadgetStrategy::poseidon_gadget(composer, pi, &mut perm);

            composer = p_composer;
            pi = p_pi;

            prev_hash = x;
        }

        pi.next().map(|p| *p = item.merkle_root);
        composer.add_gate(
            item.merkle.levels[crypto::TREE_HEIGHT - 1].perm[1],
            zero,
            zero,
            -BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            item.merkle_root,
        );
    }

    (composer, pi)
}
