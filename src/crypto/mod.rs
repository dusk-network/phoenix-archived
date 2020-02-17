use crate::{Nonce, PublicKey, RistrettoPoint, Scalar, ViewKey};

use hades252::strategies::{ScalarStrategy, Strategy};
use poseidon252::sponge;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use sodiumoxide::crypto::secretbox::{self, Key};

#[cfg(test)]
mod tests;

/// Perform a DHKE to create a shared secret
pub fn dhke(sk: &Scalar, pk: &RistrettoPoint) -> Key {
    Key((sk * pk).compress().to_bytes())
}

/// Encrypt a message using `r` as secret for the sender, and `pk` as public for the receiver
pub fn encrypt<V: AsRef<[u8]>>(r: &Scalar, pk: &PublicKey, nonce: &Nonce, value: V) -> Vec<u8> {
    secretbox::seal(value.as_ref(), nonce, &dhke(r, &pk.a_g))
}

/// Decrypt a message using `r_g` as public of the sender, and `vk` as secret for the receiver
pub fn decrypt(r_g: &RistrettoPoint, vk: &ViewKey, nonce: &Nonce, value: &[u8]) -> Vec<u8> {
    secretbox::open(value, nonce, &dhke(&vk.a, r_g)).unwrap_or({
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
