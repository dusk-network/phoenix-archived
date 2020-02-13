use crate::{EdwardsPoint, Nonce, PublicKey, Scalar, ViewKey};

use hades252::strategies::{ScalarStrategy, Strategy};
use poseidon252::sponge;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::{
    PublicKey as SodiumPk, SecretKey as SodiumSk,
};

#[cfg(test)]
mod tests;

/// Encrypt a message using `r` as secret for the sender, and `pk` as public for the receiver
pub fn encrypt<V: AsRef<[u8]>>(r: &Scalar, pk: &PublicKey, nonce: &Nonce, value: V) -> Vec<u8> {
    let a_g = SodiumPk(pk.a_g.to_montgomery().to_bytes());
    let r = SodiumSk(r.to_bytes());

    box_::seal(value.as_ref(), nonce, &a_g, &r)
}

/// Decrypt a message using `r_g` as public of the sender, and `vk` as secret for the receiver
pub fn decrypt(r_g: &EdwardsPoint, vk: &ViewKey, nonce: &Nonce, value: &[u8]) -> Vec<u8> {
    let r_g = SodiumPk(r_g.to_montgomery().to_bytes());
    let a = SodiumSk(vk.a.to_bytes());

    box_::open(value, nonce, &r_g, &a).unwrap_or({
        let mut value = value.to_vec();
        value.shuffle(&mut OsRng);
        value
    })
}

/// Hash an arbitrary long message to a [`Scalar`]
pub fn sponge_hash(s: &[Scalar]) -> Scalar {
    sponge::hash(s)
}

/// Hash a [`Scalar`]
pub fn hash_scalar(s: &Scalar) -> Scalar {
    let mut input = vec![Scalar::zero(); hades252::WIDTH];
    input[1] = s.clone();
    ScalarStrategy::new().perm(input)[1]
}
