use crate::{zk, BlsScalar};

use hades252::strategies::GadgetStrategy;
use num_traits::{One, Zero};

/// Prove the pre-image of the notes
///
/// The output notes will be validated as public inputs
///
/// The fee is not validated because its R and pk_r is updated by the block generator
pub fn preimage<'a, P>(
    mut composer: zk::Composer,
    tx: &zk::ZkTransaction,
    mut pi: P,
) -> (zk::Composer, P)
where
    P: Iterator<Item = &'a mut BlsScalar>,
{
    let zero = tx.zero;
    let bitflags = tx.fifteen;
    let zero_perm = [zero; hades252::WIDTH];
    let mut perm = [zero; hades252::WIDTH];

    for item in tx.inputs.iter() {
        perm.copy_from_slice(&zero_perm);
        perm[0] = bitflags;
        perm[1] = item.value_commitment;
        perm[2] = item.idx;
        perm[3] = item.pk_r_affine_x;
        perm[4] = item.pk_r_affine_y;
        let (p_composer, p_pi, hs) = GadgetStrategy::poseidon_gadget(composer, pi, &mut perm);

        composer = p_composer;
        pi = p_pi;

        pi.next().map(|p| *p = BlsScalar::zero());
        composer.add_gate(
            hs,
            item.note_hash,
            zero,
            -BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
    }

    for item in tx.outputs.iter() {
        pi.next().map(|p| *p = item.pk_r_affine_x_scalar);
        composer.add_gate(
            item.pk_r_affine_x,
            zero,
            zero,
            -BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            item.pk_r_affine_x_scalar,
        );
    }

    (composer, pi)
}
