use crate::{rpc, utils, Error, JubJubScalar, PublicKey, ViewKey};

use std::convert::{TryFrom, TryInto};
use std::fmt;

use rand::RngCore;
use unprolix::{Constructor, Getters, Setters};

/// Secret pair of a and b
///
/// It is used to create a note nullifier via secret b
#[derive(Debug, Clone, Copy, PartialEq, Eq, Constructor, Getters, Setters)]
pub struct SecretKey {
    a: JubJubScalar,
    b: JubJubScalar,
}

impl Default for SecretKey {
    fn default() -> Self {
        SecretKey {
            a: utils::gen_random_scalar(),
            b: utils::gen_random_scalar(),
        }
    }
}

impl SecretKey {
    /// Deterministically create a new [`SecretKey`] from a random number generator
    pub fn from_rng<R: RngCore>(rng: &mut R) -> Self {
        let a = utils::gen_random_scalar_from_rng(rng);
        let b = utils::gen_random_scalar_from_rng(rng);

        SecretKey::new(a, b)
    }

    /// Derive the secret to deterministically construct a [`PublicKey`]
    pub fn public_key(&self) -> PublicKey {
        let A = utils::mul_by_basepoint_jubjub(&self.a);
        let B = utils::mul_by_basepoint_jubjub(&self.b);

        PublicKey::new(A, B)
    }

    /// Derive the secret to deterministically construct a [`ViewKey`]
    pub fn view_key(&self) -> ViewKey {
        let B = utils::mul_by_basepoint_jubjub(&self.b);

        ViewKey::new(self.a, B)
    }
}

impl TryFrom<rpc::SecretKey> for SecretKey {
    type Error = Error;

    fn try_from(k: rpc::SecretKey) -> Result<Self, Self::Error> {
        let a = k.a.ok_or(Error::InvalidPoint).and_then(|s| s.try_into())?;
        let b = k.b.ok_or(Error::InvalidPoint).and_then(|s| s.try_into())?;

        Ok(Self::new(a, b))
    }
}

impl From<SecretKey> for rpc::SecretKey {
    fn from(k: SecretKey) -> Self {
        Self {
            a: Some(k.a.into()),
            b: Some(k.b.into()),
        }
    }
}

const SK_SIZE: usize = utils::JUBJUB_SCALAR_SERIALIZED_SIZE * 2;

impl Into<[u8; SK_SIZE]> for &SecretKey {
    fn into(self) -> [u8; SK_SIZE] {
        let mut bytes = [0x00u8; SK_SIZE];

        utils::serialize_jubjub_scalar(&self.a, &mut bytes[0..SK_SIZE / 2])
            .expect("In-memory write");

        utils::serialize_jubjub_scalar(&self.b, &mut bytes[SK_SIZE / 2..SK_SIZE])
            .expect("In-memory write");

        bytes
    }
}

impl From<&[u8]> for SecretKey {
    fn from(bytes: &[u8]) -> Self {
        SecretKey::from_rng(&mut utils::generate_rng(bytes))
    }
}

impl From<String> for SecretKey {
    fn from(s: String) -> Self {
        Self::from(s.into_bytes().as_slice())
    }
}

impl fmt::LowerHex for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: [u8; SK_SIZE] = self.into();

        let a = hex::encode(&bytes[0..SK_SIZE / 2]);
        let b = hex::encode(&bytes[SK_SIZE / 2..SK_SIZE]);

        write!(f, "{}{}", a, b)
    }
}

impl fmt::UpperHex for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: [u8; SK_SIZE] = self.into();

        let a = hex::encode_upper(&bytes[0..SK_SIZE / 2]);
        let b = hex::encode_upper(&bytes[SK_SIZE / 2..SK_SIZE]);

        write!(f, "{}{}", a, b)
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}
