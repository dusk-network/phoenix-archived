use crate::zk;

// use std::mem;

// use plonk_gadgets::gadgets::boolean::BoolVar;
// use plonk_gadgets::gadgets::ecc::JubJubPointGadget;

/// Gadget to validate the inputs key consistency related to their PKr
///
/// All the public inputs, estimated to be 20k+, are not tracked, and they are only repeated
/// zeroes. Hence, this gadget must be the last one to be called
pub fn sk_r(composer: zk::Composer, tx: &zk::ZkTransaction) //zk::Composer
{
    /* let basepoint = JubJubPointGadget {
        X: *tx.basepoint_affine_x(),
        Y: *tx.basepoint_affine_y(),
        Z: *tx.one(),
        T: *tx.basepoint_affine_xy(),
    };


    for item in tx.inputs().iter() {
        let mut sk_r_bits: [BoolVar; 256] = [unsafe { mem::zeroed() }; 256];
        item.sk_r()
            .iter()
            .zip(sk_r_bits.iter_mut())
            .for_each(|(bit, bv)| {
                *bv = (*bit).into();
            });

        // let pk_r = JubJubPointGadget {
            X: *item.pk_r_affine_x(),
            Y: *item.pk_r_affine_y(),
            Z: *tx.one(),
            T: *item.pk_r_affine_xy(),
        };

        let pk_r_prime = basepoint.scalar_mul(&mut composer, &sk_r_bits);

        pk_r.satisfy_curve_eq(&mut composer);
        pk_r_prime.satisfy_curve_eq(&mut composer);
        pk_r_prime.equal(&mut composer, &pk_r);
    }

    composer
    */
}
