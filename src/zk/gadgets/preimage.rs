use crate::{zk, BlsScalar};

use hades252::strategies::GadgetStrategy;
use num_traits::{One, Zero};

macro_rules! note_preimage {
    (
        $item:ident,
        $composer:ident,
        $perm:ident,
        $zero_perm:ident,
        $bitflags:ident,
        $bitflags_affine:ident,
        $pi:ident,
        $hs:ident,
    ) => {
        $perm.copy_from_slice(&$zero_perm);
        $perm[0] = $bitflags_affine;
        $perm[1] = $item.R_affine_x;
        $perm[2] = $item.R_affine_y;
        let (p_composer, p_pi, R) = GadgetStrategy::poseidon_gadget($composer, $pi, &mut $perm);

        $perm.copy_from_slice(&$zero_perm);
        $perm[0] = $bitflags_affine;
        $perm[1] = $item.pk_r_affine_x;
        $perm[2] = $item.pk_r_affine_y;
        let (p_composer, p_pi, pk_r) =
            GadgetStrategy::poseidon_gadget(p_composer, p_pi, &mut $perm);

        $perm.copy_from_slice(&$zero_perm);
        $perm[0] = $bitflags;
        $perm[1] = $item.value_commitment;
        $perm[2] = $item.idx;
        $perm[3] = R;
        $perm[4] = pk_r;
        let (p_composer, p_pi, p_h) = GadgetStrategy::poseidon_gadget(p_composer, p_pi, &mut $perm);

        $composer = p_composer;
        $pi = p_pi;
        $hs = p_h;
    };
}

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
    let zero = composer.add_input(BlsScalar::zero());
    let bitflags_affine = composer.add_input(BlsScalar::from(3u8));
    let bitflags = composer.add_input(BlsScalar::from(15u8));
    let zero_perm = [zero; hades252::WIDTH];
    let mut perm = [zero; hades252::WIDTH];
    let mut hs;

    for item in tx.inputs.iter() {
        note_preimage!(
            item,
            composer,
            perm,
            zero_perm,
            bitflags,
            bitflags_affine,
            pi,
            hs,
        );

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
        note_preimage!(
            item,
            composer,
            perm,
            zero_perm,
            bitflags,
            bitflags_affine,
            pi,
            hs,
        );

        pi.next().map(|p| *p = item.note_hash_scalar);
        composer.add_gate(
            hs,
            zero,
            zero,
            -BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            item.note_hash_scalar,
        );
    }

    (composer, pi)
}
