use crate::{rpc, utils, Error, JubJubExtended, SecretKey};

use std::convert::{TryFrom, TryInto};
use std::fmt;
use subtle::{Choice, ConstantTimeEq};

use unprolix::{Constructor, Getters, Setters};

/// Public pair of a·G and b·G
#[derive(Debug, Clone, Copy, Constructor, Getters, Setters)]
pub struct PublicKey {
    A: JubJubExtended,
    B: JubJubExtended,
}

impl ConstantTimeEq for PublicKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.A.ct_eq(&other.A) & self.B.ct_eq(&other.B)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(&other).unwrap_u8() == 1
    }
}

impl Eq for PublicKey {}

impl Default for PublicKey {
    fn default() -> Self {
        SecretKey::default().public_key()
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
        let A = k
            .a_g
            .ok_or(Error::InvalidPoint)
            .and_then(|p| p.try_into())?;

        let B = k
            .b_g
            .ok_or(Error::InvalidPoint)
            .and_then(|p| p.try_into())?;

        Ok(Self::new(A, B))
    }
}

impl From<PublicKey> for rpc::PublicKey {
    fn from(k: PublicKey) -> Self {
        Self {
            a_g: Some(k.A.into()),
            b_g: Some(k.B.into()),
        }
    }
}

const PK_SIZE: usize = utils::COMPRESSED_JUBJUB_SERIALIZED_SIZE * 2;

impl Into<[u8; PK_SIZE]> for &PublicKey {
    fn into(self) -> [u8; PK_SIZE] {
        let mut bytes = [0x00u8; PK_SIZE];

        utils::serialize_compressed_jubjub(&self.A, &mut bytes[0..PK_SIZE / 2])
            .expect("In-memory write");

        utils::serialize_compressed_jubjub(&self.B, &mut bytes[PK_SIZE / 2..PK_SIZE])
            .expect("In-memory write");

        bytes
    }
}

impl TryFrom<String> for PublicKey {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.len() != 128 {
            return Err(Error::InvalidParameters);
        }

        let s = s.as_str();

        let A = hex::decode(&s[0..PK_SIZE]).map_err(|_| Error::InvalidPoint)?;
        let A = utils::deserialize_compressed_jubjub(A.as_slice())?;

        let B = hex::decode(&s[PK_SIZE..PK_SIZE * 2]).map_err(|_| Error::InvalidPoint)?;
        let B = utils::deserialize_compressed_jubjub(B.as_slice())?;

        Ok(PublicKey::new(A, B))
    }
}

impl fmt::LowerHex for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: [u8; PK_SIZE] = self.into();

        let A = hex::encode(&bytes[0..PK_SIZE / 2]);
        let B = hex::encode(&bytes[PK_SIZE / 2..PK_SIZE]);

        write!(f, "{}{}", A, B)
    }
}

impl fmt::UpperHex for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: [u8; PK_SIZE] = self.into();

        let A = hex::encode_upper(&bytes[0..PK_SIZE / 2]);
        let B = hex::encode_upper(&bytes[PK_SIZE / 2..PK_SIZE]);

        write!(f, "{}{}", A, B)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}
