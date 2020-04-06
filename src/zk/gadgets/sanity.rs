use crate::{utils, zk, BlsScalar};

use algebra::curves::ProjectiveCurve;
use num_traits::{One, Zero};

/// Perform the pre-image of the value commitment and check if the inputs equals the outputs + fee
pub fn sanity<'a, P>(
    mut composer: zk::Composer,
    tx: &zk::ZkTransaction,
    mut pi: P,
) -> (zk::Composer, P)
where
    P: Iterator<Item = &'a mut BlsScalar>,
{
    let basepoint = utils::jubjub_projective_basepoint().into_affine();
    let basepoint_affine_xy = basepoint.x * basepoint.y;

    pi.next().map(|p| *p = basepoint.x);
    composer.add_gate(
        tx.basepoint_affine_x,
        tx.zero,
        tx.zero,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        basepoint.x,
    );

    pi.next().map(|p| *p = basepoint.y);
    composer.add_gate(
        tx.basepoint_affine_y,
        tx.zero,
        tx.zero,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        basepoint.y,
    );

    pi.next().map(|p| *p = basepoint_affine_xy);
    composer.add_gate(
        tx.basepoint_affine_xy,
        tx.zero,
        tx.zero,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        basepoint_affine_xy,
    );

    pi.next().map(|p| *p = BlsScalar::zero());
    composer.add_gate(
        tx.zero,
        tx.zero,
        tx.zero,
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    pi.next().map(|p| *p = BlsScalar::one());
    composer.add_gate(
        tx.one,
        tx.zero,
        tx.zero,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::one(),
    );

    pi.next().map(|p| *p = BlsScalar::from(2u8));
    composer.add_gate(
        tx.two,
        tx.zero,
        tx.zero,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::from(2u8),
    );

    pi.next().map(|p| *p = BlsScalar::from(3u8));
    composer.add_gate(
        tx.three,
        tx.zero,
        tx.zero,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::from(3u8),
    );

    pi.next().map(|p| *p = BlsScalar::from(15u8));
    composer.add_gate(
        tx.fifteen,
        tx.zero,
        tx.zero,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::from(15u8),
    );

    (composer, pi)
}
