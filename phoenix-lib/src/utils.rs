use crate::{EdwardsPoint, Nonce, Scalar};

use std::cmp;

use curve25519_dalek::constants;
use rand::rngs::OsRng;
use rand::RngCore;
use sodiumoxide::crypto::box_;

pub fn gen_random_scalar() -> Scalar {
    let mut s = [0x00u8; 32];
    OsRng.fill_bytes(&mut s);
    Scalar::from_bits(s)
}

pub fn gen_random_clamped_scalar() -> Scalar {
    let mut s = [0x00u8; 32];
    OsRng.fill_bytes(&mut s);

    clamp_bytes(&mut s);

    Scalar::from_bits(s)
}

pub fn clamp_bytes(b: &mut [u8; 32]) {
    b[0] &= 248;
    b[31] &= 127;
    b[31] |= 64;
}

pub fn mul_by_basepoint_edwards(s: &Scalar) -> EdwardsPoint {
    &constants::ED25519_BASEPOINT_TABLE * s
}

pub fn edwards_to_scalar(p: EdwardsPoint) -> Scalar {
    Scalar::from_bits(p.compress().to_bytes())
}

pub fn gen_nonce() -> Nonce {
    box_::gen_nonce()
}

pub fn safe_32_chunk(bytes: &[u8]) -> [u8; 32] {
    let mut s = [0x00u8; 32];
    let chunk = cmp::min(bytes.len(), 32);

    (&mut s[0..chunk]).copy_from_slice(&bytes[0..chunk]);

    s
}
