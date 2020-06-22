use crate::{BlsScalar, Error, JubJubAffine, JubJubExtended, JubJubScalar, Nonce, NONCEBYTES};

use std::io::{self, Read};
use std::mem::{self, MaybeUninit};
use std::{cmp, ptr};

use kelvin::{ByteHash, Source};

use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::secretbox;

pub(crate) unsafe fn lazy_static_write<T>(p: &T, v: T) {
    let ptr: *mut T = mem::transmute(p);
    ptr::write(ptr, v);
}

pub(crate) unsafe fn lazy_static_maybeuninit_write<T>(p: &MaybeUninit<T>, v: T) {
    let ptr = p as *const MaybeUninit<T> as *mut MaybeUninit<T>;
    let p: &mut MaybeUninit<T> = ptr.as_mut().unwrap();
    p.write(v);
}

/// Generate a random [`JubJubScalar`] from [`rand::thread_rng`]
pub fn gen_random_scalar() -> JubJubScalar {
    gen_random_scalar_from_rng(&mut rand::thread_rng())
}

/// Generate a random [`JubJubScalar`] from a provided random number generator
pub fn gen_random_scalar_from_rng<R: RngCore>(rng: &mut R) -> JubJubScalar {
    let random_nums = rng.gen::<[u64; 4]>();
    JubJubScalar::from_raw(random_nums)
}

/// Serialized size of a compressed JubJub affine point
pub const COMPRESSED_JUBJUB_SERIALIZED_SIZE: usize = 32;

/// Serialized size of a [`JubJubScalar`]
pub const JUBJUB_SCALAR_SERIALIZED_SIZE: usize = 32;

/// Serialized size of a [`BlsScalar`]
pub const BLS_SCALAR_SERIALIZED_SIZE: usize = 32;

/// Deserialize a [`JubJubAffine`] from a slice of bytes, and convert it to [`JubJubExtended`]
pub fn deserialize_compressed_jubjub(bytes: &[u8]) -> Result<JubJubExtended, Error> {
    if bytes.len() < 32 {
        return Err(Error::InvalidParameters);
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes[..32]);
    let result = JubJubAffine::from_bytes(array);
    if result.is_none().unwrap_u8() == 1 {
        return Err(Error::InvalidParameters);
    }

    Ok(JubJubExtended::from(result.unwrap()))
}

/// Deserialize a [`JubJubScalar`] from a slice of bytes
pub fn deserialize_jubjub_scalar(bytes: &[u8]) -> Result<JubJubScalar, Error> {
    if bytes.len() < 32 {
        return Err(Error::InvalidParameters);
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes[..32]);
    let result = JubJubScalar::from_bytes(&array);
    if result.is_none().unwrap_u8() == 1 {
        return Err(Error::InvalidParameters);
    }

    Ok(result.unwrap())
}

/// Deserialize a [`BlsScalar`] from a slice of bytes
pub fn deserialize_bls_scalar(bytes: &[u8]) -> Result<BlsScalar, Error> {
    if bytes.len() < 32 {
        return Err(Error::InvalidParameters);
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes[..32]);
    let result = BlsScalar::from_bytes(&array);
    if result.is_none().unwrap_u8() == 1 {
        return Err(Error::InvalidParameters);
    }

    Ok(result.unwrap())
}

/// Deserialize a [`BlsScalar`] from a [`Source`]
pub fn kelvin_source_to_bls_scalar<H: ByteHash>(source: &mut Source<H>) -> io::Result<BlsScalar> {
    let mut s = [0x00u8; BLS_SCALAR_SERIALIZED_SIZE];

    source.read_exact(&mut s)?;

    deserialize_bls_scalar(&s).map_err(|e| e.into())
}

/// Deserialize a [`JubJubScalar`] from a [`Source`]
pub fn kelvin_source_to_jubjub_scalar<H: ByteHash>(
    source: &mut Source<H>,
) -> io::Result<JubJubScalar> {
    let mut s = [0x00u8; JUBJUB_SCALAR_SERIALIZED_SIZE];

    source.read_exact(&mut s)?;

    deserialize_jubjub_scalar(&s).map_err(|e| e.into())
}

/// Deserialize a [`JubJubExtended`] from a [`Source`]
pub fn kelvin_source_to_jubjub_projective<H: ByteHash>(
    source: &mut Source<H>,
) -> io::Result<JubJubExtended> {
    let mut p = [0x00u8; COMPRESSED_JUBJUB_SERIALIZED_SIZE];

    source.read_exact(&mut p)?;

    deserialize_compressed_jubjub(&p).map_err(|e| e.into())
}

/// Deserialize a [`Nonce`] from a [`Source`]
pub fn kelvin_source_to_nonce<H: ByteHash>(source: &mut Source<H>) -> io::Result<Nonce> {
    let mut n = [0x00u8; NONCEBYTES];

    source.read_exact(&mut n).map(|_| Nonce(n))
}

/// Generate a new random nonce
pub fn gen_nonce() -> Nonce {
    secretbox::gen_nonce()
}

/// Safely transpose a slice of any size to a `[u8; 24]`
pub fn safe_24_chunk(bytes: &[u8]) -> [u8; 24] {
    let mut s = [0x00u8; 24];
    let chunk = cmp::min(bytes.len(), 24);

    (&mut s[0..chunk]).copy_from_slice(&bytes[0..chunk]);

    s
}

/// Safely transpose a slice of any size to a `[u8; 48]`
pub fn safe_48_chunk(bytes: &[u8]) -> [u8; 48] {
    let mut s = [0x00u8; 48];
    let chunk = cmp::min(bytes.len(), 48);

    (&mut s[0..chunk]).copy_from_slice(&bytes[0..chunk]);

    s
}

/// Decompose a [`JubJubScalar`] to a set of bits represented by [`BlsScalar`]
pub fn jubjub_scalar_to_bls_bits(scalar: &JubJubScalar) -> [BlsScalar; 256] {
    let mut res = [BlsScalar::zero(); 256];
    let bytes = scalar.to_bytes();

    for (byte, bits) in bytes.iter().zip(res.chunks_mut(8)) {
        bits.iter_mut()
            .enumerate()
            .for_each(|(i, bit)| *bit = BlsScalar::from(((byte >> i) & 1) as u64))
    }
    res
}

/// Decompose a [`JubJubScalar`] to a set of bits
pub fn jubjub_scalar_to_bits(scalar: &JubJubScalar) -> [u8; 256] {
    let mut res = [0u8; 256];
    let bytes = scalar.to_bytes();

    for (byte, bits) in bytes.iter().zip(res.chunks_mut(8)) {
        bits.iter_mut()
            .enumerate()
            .for_each(|(i, bit)| *bit = (byte >> i) & 1)
    }
    res
}

/// Decompose a [`BlsScalar`] to a set of bits
pub fn bls_scalar_to_bits(scalar: &BlsScalar) -> [u8; 256] {
    let mut res = [0u8; 256];
    let bytes = scalar.to_bytes();

    for (byte, bits) in bytes.iter().zip(res.chunks_mut(8)) {
        bits.iter_mut()
            .enumerate()
            .for_each(|(i, bit)| *bit = (byte >> i) & 1)
    }
    res
}

/// Generate a [`StdRng`] from a given slice of bytes
pub fn generate_rng(bytes: &[u8]) -> StdRng {
    let mut hasher = Sha256::default();
    hasher.input(bytes);
    let bytes = hasher.result();

    let mut seed = [0x00u8; 32];
    seed.copy_from_slice(&bytes[0..32]);

    StdRng::from_seed(seed)
}
