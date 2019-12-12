use crate::{RistrettoPoint, Scalar};

use curve25519_dalek::constants;
use rand::rngs::OsRng;
use rand::RngCore;

pub fn gen_random_scalar() -> Scalar {
    let mut s = [0x00u8; 32];
    OsRng.fill_bytes(&mut s);
    Scalar::from_bits(s)
}

pub fn scalar_to_field(s: &Scalar) -> RistrettoPoint {
    s * &constants::RISTRETTO_BASEPOINT_TABLE
}
