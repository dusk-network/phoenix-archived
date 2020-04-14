use crate::{
    utils, BlsScalar, JubJubAffine, JubJubProjective, JubJubScalar, Nonce, PublicKey, ViewKey,
};

use std::{cmp, ptr};

use algebra::curves::{AffineCurve, ProjectiveCurve};
use algebra::groups::Group;
use num_traits::{One, Zero};
use rand::seq::SliceRandom;

use hades252::strategies::{ScalarStrategy, Strategy};
use sodiumoxide::crypto::secretbox::{self, Key};

pub mod merkle;

pub use merkle::{MerkleProof, MerkleProofProvider, ARITY, TREE_HEIGHT};

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
    secretbox::seal(value.as_ref(), nonce, &dhke(r, pk.A()))
}

/// Decrypt a message using `r_g` as public of the sender, and `vk` as secret for the receiver
pub fn decrypt(R: &JubJubProjective, vk: &ViewKey, nonce: &Nonce, value: &[u8]) -> Vec<u8> {
    secretbox::open(value, nonce, &dhke(vk.a(), R)).unwrap_or({
        let mut value = value.to_vec();
        value.shuffle(&mut rand::thread_rng());
        value
    })
}

/// Hash an arbitrary long message to a [`BlsScalar`]
pub fn sponge_hash(input: &[BlsScalar]) -> BlsScalar {
    // TODO - Review
    let mut strategy = ScalarStrategy::new();

    let zero = [BlsScalar::zero(); hades252::WIDTH];
    let mut perm = [BlsScalar::zero(); hades252::WIDTH];

    input
        .chunks(hades252::WIDTH - 2)
        .fold(strategy.poseidon(&mut perm), |h, i| {
            perm.copy_from_slice(&zero);

            let chunk = cmp::min(i.len(), hades252::WIDTH - 2);

            perm[0] = HASH_BITFLAGS[chunk];
            perm[1] = h;

            (&mut perm[2..2 + chunk]).copy_from_slice(&i[0..chunk]);

            strategy.poseidon(&mut perm)
        })
}

/// Hash slice of scalars [`BlsScalar`] using a fixed-width merkle aspect
///
/// Will truncate the input to [`hades252::WIDTH`]
pub fn hash_merkle(input: &[BlsScalar]) -> BlsScalar {
    let mut i = [BlsScalar::zero(); hades252::WIDTH];

    let chunk = cmp::min(input.len(), hades252::WIDTH - 1);
    (&mut i[1..1 + chunk]).copy_from_slice(&input[0..chunk]);

    i[0] = HASH_BITFLAGS[chunk];

    ScalarStrategy::new().poseidon(&mut i)
}

/// Hash a [`BlsScalar`]
pub fn hash_scalar(s: &BlsScalar) -> BlsScalar {
    let mut input = [BlsScalar::zero(); hades252::WIDTH];

    input[0] = BlsScalar::one();
    input[1] = *s;

    ScalarStrategy::new().poseidon(&mut input)
}

/// Convert to a deterministic representation of the projective point, and perform `H(x, y, z, t)`
pub fn hash_jubjub_projective(p: &JubJubProjective) -> BlsScalar {
    let p = p.into_affine().into_projective();

    hash_merkle(&[p.x, p.y, p.z, p.t])
}

/// Return a hash represented by `H(x, y)`
pub fn hash_jubjub_affine(p: &JubJubAffine) -> BlsScalar {
    hash_merkle(&[p.x, p.y])
}

/// Perform  a poseidon merkle slice hash strategy on a bits representation of a jubjub scalar
pub fn jubjub_scalar_to_bls(s: &JubJubScalar) -> BlsScalar {
    let bits = utils::jubjub_scalar_to_bls_bits(s);
    ScalarStrategy::new().poseidon_slice(&bits)
}

/// Hash the point into a [`BlsScalar`], decompose the result in bits and reconstruct a
/// [`JubJubScalar`] from the bits
pub fn hash_jubjub_projective_to_jubjub_scalar(p: &JubJubProjective) -> JubJubScalar {
    // TODO - Review and improve
    let s = hash_jubjub_projective(p);

    let two = JubJubScalar::from(2u8);
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
