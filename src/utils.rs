use crate::{MontgomeryPoint, Scalar};

use curve25519_dalek::constants;
use rand::rngs::OsRng;
use rand::RngCore;

pub fn gen_random_scalar() -> Scalar {
    let mut s = [0x00u8; 32];
    OsRng.fill_bytes(&mut s);
    Scalar::from_bits(s)
}

pub fn gen_random_clamped_scalar() -> Scalar {
    let mut s = [0x00u8; 32];
    OsRng.fill_bytes(&mut s);

    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;

    Scalar::from_bits(s)
}

pub fn mul_by_basepoint(s: &Scalar) -> MontgomeryPoint {
    (&constants::ED25519_BASEPOINT_TABLE * s).to_montgomery()
}
