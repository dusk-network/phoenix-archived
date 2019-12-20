use crate::{MontgomeryPoint, Nonce, PublicKey, Scalar, ViewKey};

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::{
    PublicKey as SodiumPk, SecretKey as SodiumSk,
};

#[cfg(test)]
mod tests;

pub fn encrypt<V: AsRef<[u8]>>(r: &Scalar, pk: &PublicKey, nonce: &Nonce, value: V) -> Vec<u8> {
    let a_g = SodiumPk(pk.a_g.to_bytes());
    let r = SodiumSk(r.to_bytes());

    box_::seal(value.as_ref(), nonce, &a_g, &r)
}

pub fn decrypt(r_g: &MontgomeryPoint, vk: &ViewKey, nonce: &Nonce, value: &[u8]) -> Vec<u8> {
    let r_g = SodiumPk(r_g.to_bytes());
    let a = SodiumSk(vk.a.to_bytes());

    box_::open(value, nonce, &r_g, &a).unwrap_or({
        let mut value = value.to_vec();
        value.shuffle(&mut OsRng);
        value
    })
}
