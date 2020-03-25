use crate::{BlsScalar, Error, JubJubAffine, JubJubProjective, JubJubScalar, Nonce, NONCEBYTES};

use std::io::{self, Read};
use std::ops::Mul;
use std::{cmp, mem, ptr, slice, thread};

use algebra::biginteger::BigInteger256;
use algebra::curves::jubjub::JubJubParameters;
use algebra::curves::models::TEModelParameters;
use algebra::curves::{AffineCurve, ProjectiveCurve};
use algebra::serialize::{CanonicalDeserialize, CanonicalSerialize};
use kelvin::{ByteHash, Source};
use rand::{Rng, RngCore};
use sodiumoxide::crypto::secretbox;

lazy_static::lazy_static! {
    static ref INITIALIZING: bool = false;
    static ref INITIALIZED: bool = false;
    static ref JUBJUB_BASEPOINT_AFFINE: JubJubAffine = unsafe { mem::zeroed() };
    static ref JUBJUB_BASEPOINT_PROJECTIVE: JubJubProjective = unsafe { mem::zeroed() };
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

    let (x, y) = JubJubParameters::AFFINE_GENERATOR_COEFFS;
    let affine = JubJubAffine::new(x, y);
    let projective = JubJubProjective::from(affine);

    unsafe {
        lazy_static_write(&*JUBJUB_BASEPOINT_AFFINE, affine);
        lazy_static_write(&*JUBJUB_BASEPOINT_PROJECTIVE, projective);

        lazy_static_write(&*INITIALIZED, true);
    }
}

unsafe fn lazy_static_write<T: Copy>(p: &T, v: T) {
    let ptr: *mut T = mem::transmute(p);
    ptr::write(ptr, v);
}

/// Generate a random [`JubJubScalar`] from [`rand::thread_rng`]
pub fn gen_random_scalar() -> JubJubScalar {
    gen_random_scalar_from_rng(&mut rand::thread_rng())
}

/// Generate a random [`JubJubScalar`] from a provided random number generator
pub fn gen_random_scalar_from_rng<R: RngCore>(rng: &mut R) -> JubJubScalar {
    rng.gen()
}

/// Generate a random [`BlsScalar`] from [`rand::thread_rng`]
pub fn gen_random_bls_scalar() -> BlsScalar {
    gen_random_bls_scalar_from_rng(&mut rand::thread_rng())
}

/// Generate a random [`BlsScalar`] from a provided random number generator
pub fn gen_random_bls_scalar_from_rng<R: RngCore>(rng: &mut R) -> BlsScalar {
    rng.gen()
}

/// Extract a 32-sized slice of bytes from a given scalar
///
/// Both [`JubJubScalar`] and [`BlsScalar`] are represented internally by a [`BigInteger256`]
pub fn scalar_as_slice<'a>(s: &'a BigInteger256) -> &'a [u8] {
    unsafe { slice::from_raw_parts(s.0.as_ptr() as *const u8, 32) }
}

/// Multiply a [`JubJubScalar`] by the JubJub generator point
///
/// The multiplication is always performed with projective coordinates due to performance gain
pub fn mul_by_basepoint_jubjub(s: &JubJubScalar) -> JubJubProjective {
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
    p: &JubJubProjective,
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

/// Deserialize a [`JubJubProjective`] from a [`Source`]
pub fn kelvin_source_to_jubjub_projective<H: ByteHash>(
    source: &mut Source<H>,
) -> io::Result<JubJubProjective> {
    let mut p = [0x00u8; COMPRESSED_JUBJUB_SERIALIZED_SIZE];

    source.read_exact(&mut p)?;

    deserialize_compressed_jubjub(&p).map_err(|e| e.into())
}

/// Deserialize a [`Nonce`] from a [`Source`]
pub fn kelvin_source_to_nonce<H: ByteHash>(source: &mut Source<H>) -> io::Result<Nonce> {
    let mut n = [0x00u8; NONCEBYTES];

    source.read_exact(&mut n).map(|_| Nonce(n))
}

/// Convert a [`JubJubProjective`] into affine and then serialize the `x` coordinate
pub fn serialize_compressed_jubjub(p: &JubJubProjective, bytes: &mut [u8]) -> Result<usize, Error> {
    p.into_affine().serialize(&[], bytes)?;

    Ok(COMPRESSED_JUBJUB_SERIALIZED_SIZE)
}

/// Deserialize a [`JubJubAffine`] from a slice of bytes, and convert it to [`JubJubProjective`]
pub fn deserialize_compressed_jubjub(bytes: &[u8]) -> Result<JubJubProjective, Error> {
    Ok(JubJubAffine::deserialize(bytes, &mut [])?.into_projective())
}

/// Serialize a [`JubJubScalar`] into bytes
pub fn serialize_jubjub_scalar(s: &JubJubScalar, bytes: &mut [u8]) -> Result<usize, Error> {
    s.serialize(&[], bytes)?;

    Ok(JUBJUB_SCALAR_SERIALIZED_SIZE)
}

/// Deserialize a [`JubJubScalar`] from a slice of bytes
pub fn deserialize_jubjub_scalar(bytes: &[u8]) -> Result<JubJubScalar, Error> {
    Ok(JubJubScalar::deserialize(bytes, &mut [])?)
}

/// Serialize a [`BlsScalar`] into bytes
pub fn serialize_bls_scalar(s: &BlsScalar, bytes: &mut [u8]) -> Result<usize, Error> {
    s.serialize(&[], bytes)?;

    Ok(BLS_SCALAR_SERIALIZED_SIZE)
}

/// Deserialize a [`BlsScalar`] from a slice of bytes
pub fn deserialize_bls_scalar(bytes: &[u8]) -> Result<BlsScalar, Error> {
    Ok(BlsScalar::deserialize(bytes, &mut [])?)
}

//
////
/////// Generate a random key-clamped scalar from [`OsRng`]
////pub fn gen_random_clamped_scalar() -> Scalar {
////    let mut s = [0x00u8; 32];
////    OsRng.fill_bytes(&mut s);
////
////    clamp_bytes(&mut s);
////
////    Scalar::from_bits(s)
////}
////
/////// Clamp a slice of bytes for key generation
////pub fn clamp_bytes(b: &mut [u8; 32]) {
////    b[0] &= 248;
////    b[31] &= 127;
////    b[31] |= 64;
////}
////
/////// Get the Y coordinate of a ristretto field element and return it as a scalar
////pub fn ristretto_to_scalar(p: RistrettoPoint) -> Scalar {
////    Scalar::from_bits(p.compress().to_bytes())
////}
////
/// Generate a new random nonce
pub fn gen_nonce() -> Nonce {
    secretbox::gen_nonce()
}
////
/// Safely transpose a slice of any size to a `[u8; 24]`
pub fn safe_24_chunk(bytes: &[u8]) -> [u8; 24] {
    let mut s = [0x00u8; 24];
    let chunk = cmp::min(bytes.len(), 24);

    (&mut s[0..chunk]).copy_from_slice(&bytes[0..chunk]);

    s
}
////
/////// Safely transpose a slice of any size to a `[u8; 32]`
////pub fn safe_32_chunk(bytes: &[u8]) -> [u8; 32] {
////    let mut s = [0x00u8; 32];
////    let chunk = cmp::min(bytes.len(), 32);
////
////    (&mut s[0..chunk]).copy_from_slice(&bytes[0..chunk]);
////
////    s
////}

/// Safely transpose a slice of any size to a `[u8; 48]`
pub fn safe_48_chunk(bytes: &[u8]) -> [u8; 48] {
    let mut s = [0x00u8; 48];
    let chunk = cmp::min(bytes.len(), 48);

    (&mut s[0..chunk]).copy_from_slice(&bytes[0..chunk]);

    s
}
////
/////// Generate a ristretto field element from a scalar
////pub fn mul_by_basepoint_ristretto(s: &Scalar) -> RistrettoPoint {
////    &constants::RISTRETTO_BASEPOINT_TABLE * s
////}
