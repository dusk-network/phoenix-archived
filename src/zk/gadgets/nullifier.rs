use crate::{zk, BlsScalar};

use hades252::strategies::GadgetStrategy;
use num_traits::{One, Zero};

/// Validate the input nullifiers
pub fn nullifier<'a, P>(
    mut composer: zk::Composer,
    tx: &zk::ZkTransaction,
    mut pi: P,
) -> (zk::Composer, P)
where
    P: Iterator<Item = &'a mut BlsScalar>,
{
    let zero = composer.add_input(BlsScalar::zero());
    let mut zero_perm = [zero; hades252::WIDTH];
    let mut perm = [zero; hades252::WIDTH];

    zero_perm[0] = composer.add_input(BlsScalar::one());

    let item = &tx.inputs[0];
    {
        perm.copy_from_slice(&zero_perm);
        perm[1] = item.idx;
        let (mut p_composer, mut p_pi, n) =
            GadgetStrategy::poseidon_gadget(composer, pi, &mut perm);

        p_pi.next().map(|p| *p = item.nullifier);
        p_composer.add_gate(
            n,
            zero,
            zero,
            -BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            item.nullifier,
        );

        composer = p_composer;
        pi = p_pi;
    }

    (composer, pi)
}
