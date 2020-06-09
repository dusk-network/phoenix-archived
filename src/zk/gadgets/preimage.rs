use crate::{zk, BlsScalar};

use hades252::strategies::GadgetStrategy;
use hades252::strategies::Strategy;
use poseidon252::sponge::sponge::sponge_hash_gadget;

/// Prove the pre-image of the notes
///
/// The output notes will be validated as public inputs
///
/// The fee is not validated because its R and pk_r is updated by the block generator
pub fn preimage(
    mut composer: zk::Composer,
    tx: &zk::ZkTransaction,
) -> zk::Composer
{
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

        composer.big_add_gate(
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

#[test]
fn test_preimage_gadget(){
    assert!
}