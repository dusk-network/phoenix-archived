use crate::{utils, zk, BlsScalar, JubJubAffine};

/// Perform the pre-image of the value commitment and check if the inputs equals the outputs + fee
pub fn sanity<'a, P>(
    mut composer: zk::Composer,
    tx: &zk::ZkTransaction,
    mut pi: P,
) -> (zk::Composer, P)
where
    P: Iterator<Item = &'a mut BlsScalar>,
{
    let basepoint = JubJubAffine::from(utils::jubjub_projective_basepoint());
    let basepoint_affine_xy = basepoint.get_x() * basepoint.get_y();

    pi.next().map(|p| *p = basepoint.get_x());
    composer.add_gate(
        *tx.basepoint_affine_x(),
        *tx.zero(),
        *tx.zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        basepoint.get_x(),
    );

    pi.next().map(|p| *p = basepoint.get_y());
    composer.add_gate(
        *tx.basepoint_affine_y(),
        *tx.zero(),
        *tx.zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        basepoint.get_y(),
    );

    pi.next().map(|p| *p = basepoint_affine_xy);
    composer.add_gate(
        *tx.basepoint_affine_xy(),
        *tx.zero(),
        *tx.zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        basepoint_affine_xy,
    );

    pi.next().map(|p| *p = BlsScalar::zero());
    composer.add_gate(
        *tx.zero(),
        *tx.zero(),
        *tx.zero(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    pi.next().map(|p| *p = BlsScalar::one());
    composer.add_gate(
        *tx.one(),
        *tx.zero(),
        *tx.zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::one(),
    );

    pi.next().map(|p| *p = BlsScalar::from(2u64));
    composer.add_gate(
        *tx.two(),
        *tx.zero(),
        *tx.zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::from(2u64),
    );

    pi.next().map(|p| *p = BlsScalar::from(3u64));
    composer.add_gate(
        *tx.three(),
        *tx.zero(),
        *tx.zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::from(3u64),
    );

    pi.next().map(|p| *p = BlsScalar::from(15u64));
    composer.add_gate(
        *tx.fifteen(),
        *tx.zero(),
        *tx.zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::from(15u64),
    );

    (composer, pi)
}
