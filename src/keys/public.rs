use super::SecretKey;
use crate::{rpc, utils, CompressedRistretto, Error, RistrettoPoint};

use std::convert::{TryFrom, TryInto};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Public pair of a·G and b·G
pub struct PublicKey {
    /// Public field element
    pub a_g: RistrettoPoint,
    /// Public field element
    pub b_g: RistrettoPoint,
}

impl Default for PublicKey {
    fn default() -> Self {
        SecretKey::default().public_key()
    }
}

impl PublicKey {
    /// [`PublicKey`] constructor
    pub fn new(a_g: RistrettoPoint, b_g: RistrettoPoint) -> Self {
        PublicKey { a_g, b_g }
    }
}

impl From<SecretKey> for PublicKey {
    fn from(secret: SecretKey) -> Self {
        secret.public_key()
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(secret: &SecretKey) -> Self {
        secret.public_key()
    }
}

impl TryFrom<rpc::PublicKey> for PublicKey {
    type Error = Error;

    fn try_from(k: rpc::PublicKey) -> Result<Self, Self::Error> {
        let a_g: RistrettoPoint = k
            .a_g
            .ok_or(Error::InvalidPoint)
            .and_then(|p| p.try_into())?;
        let b_g: RistrettoPoint = k
            .b_g
            .ok_or(Error::InvalidPoint)
            .and_then(|p| p.try_into())?;

        Ok(Self::new(a_g, b_g))
    }
}

impl From<PublicKey> for rpc::PublicKey {
    fn from(k: PublicKey) -> Self {
        Self {
            a_g: Some(rpc::CompressedPoint::from(k.a_g)),
            b_g: Some(rpc::CompressedPoint::from(k.b_g)),
        }
    }
}

impl TryFrom<String> for PublicKey {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.len() != 128 {
            return Err(Error::InvalidParameters);
        }

        let s = s.as_str();

        let a_g = hex::decode(&s[0..64]).map_err(|_| Error::InvalidPoint)?;
        let a_g = CompressedRistretto::from_slice(&utils::safe_32_chunk(a_g.as_slice()))
            .decompress()
            .ok_or(Error::InvalidPoint)?;

        let b_g = hex::decode(&s[64..128]).map_err(|_| Error::InvalidPoint)?;
        let b_g = CompressedRistretto::from_slice(&utils::safe_32_chunk(b_g.as_slice()))
            .decompress()
            .ok_or(Error::InvalidPoint)?;

        Ok(PublicKey::new(a_g, b_g))
    }
}

impl fmt::LowerHex for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a_g = hex::encode(self.a_g.compress().as_bytes());
        let b_g = hex::encode(self.b_g.compress().as_bytes());

        write!(f, "{}{}", a_g, b_g)
    }
}

impl fmt::UpperHex for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a_g = hex::encode_upper(self.a_g.compress().as_bytes());
        let b_g = hex::encode_upper(self.b_g.compress().as_bytes());

        write!(f, "{}{}", a_g, b_g)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}
