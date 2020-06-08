use crate::{BlsScalar, Error, JubJubAffine, JubJubExtended, JubJubScalar, Nonce, NONCEBYTES};

use jubjub::GENERATOR;
use std::io::{self, Read};
use std::mem::{self, MaybeUninit};
use std::ops::Mul;
use std::{cmp, ptr, thread};

use kelvin::{ByteHash, Source};

use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::{CryptoRng, Rng, RngCore};
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::secretbox;

lazy_static::lazy_static! {
    static ref INITIALIZING: bool = false;
    static ref INITIALIZED: bool = false;
    static ref JUBJUB_BASEPOINT_AFFINE: JubJubAffine = unsafe { mem::zeroed() };
    static ref JUBJUB_BASEPOINT_PROJECTIVE: JubJubExtended = unsafe { mem::zeroed() };
}

/// Initialize all sub-modules static variables
pub fn init() {
    // TODO - Improve the lock control
    if *INITIALIZING {
        let mut attempts = 0;

        while !*INITIALIZED {
            attempts += 1;
            thread::yield_now();
            if attempts > 10000 {
                panic!("Init attempts exhausted");
            }
        }

        return ();
    }

    unsafe {
        lazy_static_write(&*INITIALIZING, true);
    }

    let (x, y) = (GENERATOR.get_x(), GENERATOR.get_y());
    let affine = JubJubAffine::from_raw_unchecked(x, y);
    let projective = JubJubExtended::from(affine);

    unsafe {
        lazy_static_write(&*JUBJUB_BASEPOINT_AFFINE, affine);
        lazy_static_write(&*JUBJUB_BASEPOINT_PROJECTIVE, projective);

        lazy_static_write(&*INITIALIZED, true);
    }
}

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
    let random_nums = rand::thread_rng().gen::<[u64; 4]>();
    JubJubScalar::from_raw(random_nums)
}

/// Generate a random [`BlsScalar`] from [`rand::thread_rng`]
pub fn gen_random_bls_scalar() -> BlsScalar {
    gen_random_bls_scalar_from_rng(&mut rand::thread_rng())
}

/// Generate a random [`BlsScalar`] from a provided random number generator
pub fn gen_random_bls_scalar_from_rng<R: Rng + CryptoRng>(mut rng: &mut R) -> BlsScalar {
    BlsScalar::random(&mut rng)
}

pub fn jubjub_projective_basepoint() -> &'static JubJubExtended {
    &JUBJUB_BASEPOINT_PROJECTIVE
}

/// Multiply a [`JubJubScalar`] by the JubJub generator point
///
/// The multiplication is always performed with projective coordinates due to performance gain
pub fn mul_by_basepoint_jubjub(s: &JubJubScalar) -> JubJubExtended {
    JUBJUB_BASEPOINT_PROJECTIVE.mul(s)
}

/// Serialized size of a compressed JubJub affine point
pub const COMPRESSED_JUBJUB_SERIALIZED_SIZE: usize = 32;

/// Serialized size of a [`JubJubScalar`]
pub const JUBJUB_SCALAR_SERIALIZED_SIZE: usize = 32;

/// Serialized size of a [`BlsScalar`]
pub const BLS_SCALAR_SERIALIZED_SIZE: usize = 32;

/// Serialize a jubjub projective point and return the bytes
pub fn projective_jubjub_to_bytes(
    p: &JubJubExtended,
) -> Result<[u8; COMPRESSED_JUBJUB_SERIALIZED_SIZE], Error> {
    let mut bytes = [0x00u8; COMPRESSED_JUBJUB_SERIALIZED_SIZE];

    serialize_compressed_jubjub(p, &mut bytes)?;

    Ok(bytes)
}

/// Serialize a jubjub projective point and return the bytes
pub fn bls_scalar_to_bytes(s: &BlsScalar) -> Result<[u8; BLS_SCALAR_SERIALIZED_SIZE], Error> {
    let mut bytes = [0x00u8; BLS_SCALAR_SERIALIZED_SIZE];

    serialize_bls_scalar(s, &mut bytes)?;

    Ok(bytes)
}

/// Deserialize a [`BlsScalar`] from a [`Source`]
pub fn kelvin_source_to_bls_scalar<H: ByteHash>(source: &mut Source<H>) -> io::Result<BlsScalar> {
    let mut s = [0x00u8; BLS_SCALAR_SERIALIZED_SIZE];

    source.read_exact(&mut s)?;

    deserialize_bls_scalar(&s).map_err(|e| e.into())
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

/// Convert a [`JubJubExtended`] into affine and then serialize the `x` coordinate
pub fn serialize_compressed_jubjub(p: &JubJubExtended, bytes: &mut [u8]) -> Result<usize, Error> {
    let b = JubJubAffine::from(p).to_bytes();
    bytes.copy_from_slice(&b[..]);

    Ok(COMPRESSED_JUBJUB_SERIALIZED_SIZE)
}

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

/// Serialize a [`JubJubScalar`] into bytes
pub fn serialize_jubjub_scalar(s: &JubJubScalar, bytes: &mut [u8]) -> Result<usize, Error> {
    let b = s.to_bytes();
    bytes.copy_from_slice(&b[..]);

    Ok(JUBJUB_SCALAR_SERIALIZED_SIZE)
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

/// Serialize a [`BlsScalar`] into bytes
pub fn serialize_bls_scalar(s: &BlsScalar, bytes: &mut [u8]) -> Result<usize, Error> {
    let b = s.to_bytes();
    bytes.copy_from_slice(&b[..]);

    Ok(BLS_SCALAR_SERIALIZED_SIZE)
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
    let mut bytes = scalar.to_bytes();

    // Compute bit-array
    let mut res = [BlsScalar::zero(); 256];

    let mut res_iter = res.iter_mut();
    bytes.iter_mut().for_each(|b| {
        (0..8).for_each(|_| {
            let r = res_iter.next();
            if (*b) & 1u8 == 1 {
                r.map(|r| *r = BlsScalar::one());
            }
            *b >>= 1;
        });
    });

    res
}

/// Decompose a [`JubJubScalar`] to a set of bits
pub fn jubjub_scalar_to_bits(scalar: &JubJubScalar) -> [u8; 256] {
    let mut bytes = scalar.to_bytes();

    // Compute bit-array
    let mut res = [0x00u8; 256];

    let mut res_iter = res.iter_mut();
    bytes.iter_mut().for_each(|b| {
        (0..8).for_each(|_| {
            let r = res_iter.next();
            if (*b) & 1u8 == 1 {
                r.map(|r| *r = 1);
            }
            *b >>= 1;
        });
    });

    res
}

/// Decompose a [`BlsScalar`] to a set of bits
pub fn bls_scalar_to_bits(scalar: &BlsScalar) -> [u8; 256] {
    let mut bytes = scalar.to_bytes();

    // Compute bit-array
    let mut res = [0x00u8; 256];

    let mut res_iter = res.iter_mut();
    bytes.iter_mut().for_each(|b| {
        (0..8).for_each(|_| {
            let r = res_iter.next();
            if (*b) & 1u8 == 1 {
                r.map(|r| *r = 1u8);
            }
            *b >>= 1;
        });
    });

    res
}

/// Decompose a [`JubJubScalar`] into bits and reconstruct a [`BlsScalar`] from them
pub fn bls_scalar_from_jubjub_bits(s: &JubJubScalar) -> BlsScalar {
    let two = BlsScalar::from(2u64);
    let mut result = BlsScalar::zero();

    jubjub_scalar_to_bits(s)
        .iter()
        .fold(BlsScalar::one(), |mut acc, bit| {
            acc *= &two;
            if bit == &1u8 {
                result += &acc;
            }
            acc
        });

    result
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
