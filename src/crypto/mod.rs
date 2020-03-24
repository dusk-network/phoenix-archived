use crate::{BlsScalar, JubJubProjective, JubJubScalar, Nonce, PublicKey, ViewKey};

use std::ptr;

use algebra::curves::ProjectiveCurve;
use algebra::groups::Group;
use num_traits::Zero;
use rand::seq::SliceRandom;

use hades252::strategies::{ScalarStrategy, Strategy};
use sodiumoxide::crypto::secretbox::{self, Key};

#[cfg(test)]
mod tests;

/// Perform a DHKE to create a shared secret
pub fn dhke(sk: &JubJubScalar, pk: &JubJubProjective) -> Key {
    let shared_secret = pk.mul(sk).into_affine();
    let shared_secret = (shared_secret.y.0).0;

    let mut key = [0x00u8; 32];
    unsafe {
        let src = (&shared_secret).as_ptr() as *const u8;
        ptr::copy_nonoverlapping(src, key.as_mut_ptr(), 32);
    }

    Key(key)
}

/// Encrypt a message using `r` as secret for the sender, and `pk` as public for the receiver
pub fn encrypt<V: AsRef<[u8]>>(
    r: &JubJubScalar,
    pk: &PublicKey,
    nonce: &Nonce,
    value: V,
) -> Vec<u8> {
    secretbox::seal(value.as_ref(), nonce, &dhke(r, &pk.A))
}

/// Decrypt a message using `r_g` as public of the sender, and `vk` as secret for the receiver
pub fn decrypt(R: &JubJubProjective, vk: &ViewKey, nonce: &Nonce, value: &[u8]) -> Vec<u8> {
    secretbox::open(value, nonce, &dhke(&vk.a, R)).unwrap_or({
        let mut value = value.to_vec();
        value.shuffle(&mut rand::thread_rng());
        value
    })
}

/// Hash an arbitrary long message to a [`BlsScalar`]
///
/// # Panics
///
/// Will panic if the size of the message is bigger than [`hades252::WIDTH`]
pub fn sponge_hash(s: &[BlsScalar]) -> BlsScalar {
    // TODO - Should recursively input on merkle mode
    ScalarStrategy::new().poseidon(s.to_vec().as_mut_slice())
}

/// Hash a [`Scalar`]
pub fn hash_scalar(s: &BlsScalar) -> BlsScalar {
    let mut input = [BlsScalar::zero(); hades252::WIDTH];
    input[0] = *s;

    ScalarStrategy::new().poseidon(&mut input)
}
