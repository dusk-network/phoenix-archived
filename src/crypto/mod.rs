use crate::{MontgomeryPoint, PublicKey, Scalar, ViewKey};

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::{
    PublicKey as SodiumPk, SecretKey as SodiumSk,
};

#[cfg(test)]
mod tests;

pub fn encrypt<V: AsRef<[u8]>>(r: &Scalar, pk: &PublicKey, value: V) -> Vec<u8> {
    // TODO - Fetch a proper nonce from the notes
    let nonce = box_::Nonce([0x25; 24]);

    let a_g = SodiumPk(pk.a_g.to_bytes());
    let r = SodiumSk(r.to_bytes());

    box_::seal(value.as_ref(), &nonce, &a_g, &r)
}

pub fn decrypt(r_g: &MontgomeryPoint, vk: &ViewKey, value: &[u8]) -> Vec<u8> {
    // TODO - Fetch a proper nonce from the notes
    let nonce = box_::Nonce([0x25; 24]);

    let r_g = SodiumPk(r_g.to_bytes());
    let a = SodiumSk(vk.a.to_bytes());

    // TODO - Use a proper bottom
    box_::open(value, &nonce, &r_g, &a).unwrap_or(value.to_vec())
}
