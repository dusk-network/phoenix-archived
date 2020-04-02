use crate::{utils, zk};

use std::mem;

use algebra::curves::{AffineCurve, ProjectiveCurve};
use plonk_gadgets::gadgets::boolean::BoolVar;
use plonk_gadgets::gadgets::ecc::JubJubPointGadget;

/// Gadget to validate the inputs key consistency related to their PKr
///
/// All the public inputs, estimated to be 20k+, are not tracked, and they are only repeated
/// zeroes. Hence, this gadget must be the last one to be called
pub fn sk_r(mut composer: zk::Composer, tx: &zk::ZkTransaction) -> zk::Composer {
    let basepoint = utils::jubjub_projective_basepoint()
        .into_affine()
        .into_projective();
    let basepoint_x = composer.add_input(basepoint.x);
    let basepoint_y = composer.add_input(basepoint.y);
    let basepoint_z = composer.add_input(basepoint.z);
    let basepoint_t = composer.add_input(basepoint.t);
    let basepoint = JubJubPointGadget {
        X: basepoint_x,
        Y: basepoint_y,
        Z: basepoint_z,
        T: basepoint_t,
    };

    for item in tx.inputs.iter() {
        let mut a_bits: [BoolVar; 256] = [unsafe { mem::zeroed() }; 256];
        item.sk_a
            .iter()
            .zip(a_bits.iter_mut())
            .for_each(|(bit, bv)| {
                *bv = (*bit).into();
            });

        let mut b_bits: [BoolVar; 256] = [unsafe { mem::zeroed() }; 256];
        item.sk_b
            .iter()
            .zip(b_bits.iter_mut())
            .for_each(|(bit, bv)| {
                *bv = (*bit).into();
            });

        let R = JubJubPointGadget {
            X: item.R_projective_x,
            Y: item.R_projective_y,
            Z: item.R_projective_z,
            T: item.R_projective_t,
        };
        R.satisfy_curve_eq(&mut composer);

        let pk_r = JubJubPointGadget {
            X: item.pk_r_projective_x,
            Y: item.pk_r_projective_y,
            Z: item.pk_r_projective_z,
            T: item.pk_r_projective_t,
        };
        pk_r.satisfy_curve_eq(&mut composer);

        let aR = R.scalar_mul(&mut composer, &a_bits);
        let B = basepoint.scalar_mul(&mut composer, &b_bits);
        let pk_r_prime = aR.add(&mut composer, &B);

        pk_r_prime.satisfy_curve_eq(&mut composer);
        pk_r_prime.equal(&mut composer, &pk_r);
    }

    composer
}
