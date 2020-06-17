use crate::{
    utils, BlsScalar, JubJubAffine, JubJubExtended, JubJubScalar, Nonce, PublicKey, ViewKey,
};

use std::{ptr};

use rand::seq::SliceRandom;


use sodiumoxide::crypto::secretbox::{self, Key};

pub mod merkle;

pub use merkle::{MerkleProof, MerkleProofProvider, ARITY, TREE_HEIGHT};
pub use poseidon252::sponge::sponge::sponge_hash;

#[cfg(test)]
mod tests;

lazy_static::lazy_static! {
    static ref HASH_BITFLAGS: [BlsScalar; hades252::WIDTH] = {
        let mut bitflags = [BlsScalar::zero(); hades252::WIDTH];
        bitflags[1] = BlsScalar::one();

        let mut b = 1u64;
        for i in 2..hades252::WIDTH {
            b <<= 1;
            b |= 1;

            bitflags[i] = BlsScalar::from(b);
        }

        bitflags
    };
}

/// Perform a DHKE to create a shared secret
pub fn dhke(sk: &JubJubScalar, pk: &JubJubExtended) -> Key {
    let shared_secret = JubJubAffine::from(pk * sk);
    let shared_secret = shared_secret.get_y().0;

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
    secretbox::seal(value.as_ref(), nonce, &dhke(r, pk.A()))
}

/// Decrypt a message using `r_g` as public of the sender, and `vk` as secret for the receiver
pub fn decrypt(R: &JubJubExtended, vk: &ViewKey, nonce: &Nonce, value: &[u8]) -> Vec<u8> {
    secretbox::open(value, nonce, &dhke(vk.a(), R)).unwrap_or({
        let mut value = value.to_vec();
        value.shuffle(&mut rand::thread_rng());
        value
    })
}

/// Convert to a deterministic representation of the projective point, and perform `H(x, y, z, t)`
pub fn hash_jubjub_projective(p: &JubJubExtended) -> BlsScalar {
    let p = JubJubExtended::from(JubJubAffine::from(p));

    sponge_hash(&[p.get_x(), p.get_y(), p.get_z(), p.get_t1(), p.get_t2()])
}

/// Perform  a poseidon merkle slice hash strategy on a bits representation of a jubjub scalar
pub fn jubjub_scalar_to_bls(s: &JubJubScalar) -> BlsScalar {
    let bits = utils::jubjub_scalar_to_bls_bits(s);
    sponge_hash(&bits)
}

/// Hash the point into a [`BlsScalar`], decompose the result in bits and reconstruct a
/// [`JubJubScalar`] from the bits
pub fn hash_jubjub_projective_to_jubjub_scalar(p: &JubJubExtended) -> JubJubScalar {
    // TODO - Review and improve
    let s = hash_jubjub_projective(p);

    let two = JubJubScalar::from(2u64);
    let mut result = JubJubScalar::zero();

    utils::bls_scalar_to_bits(&s)
        .iter()
        .fold(JubJubScalar::one(), |mut acc, bit| {
            acc *= &two;
            if bit == &1u8 {
                result += &acc;
            }
            acc
        });

    result
}
