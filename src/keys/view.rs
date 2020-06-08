use crate::{rpc, utils, Error, JubJubExtended, JubJubScalar, PublicKey, SecretKey};

use std::convert::{TryFrom, TryInto};
use std::fmt;
use subtle::{Choice, ConstantTimeEq};

use unprolix::{Constructor, Getters, Setters};

/// Pair of a secret a and public b·G
///
/// The notes are encrypted against secret a, so this is used to decrypt the blinding factor and
/// value
#[derive(Debug, Clone, Copy, Constructor, Getters, Setters)]
pub struct ViewKey {
    a: JubJubScalar,
    B: JubJubExtended,
}

impl ConstantTimeEq for ViewKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.B.ct_eq(&other.B)
    }
}

impl PartialEq for ViewKey {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.ct_eq(&other).unwrap_u8() == 1
    }
}

impl Eq for ViewKey {}

impl Default for ViewKey {
    fn default() -> Self {
        SecretKey::default().view_key()
    }
}

impl ViewKey {
    /// Derive the secret to deterministically construct a [`PublicKey`]
    pub fn public_key(&self) -> PublicKey {
        let A = utils::mul_by_basepoint_jubjub(&self.a);

        PublicKey::new(A, self.B)
    }
}

impl From<SecretKey> for ViewKey {
    fn from(secret: SecretKey) -> Self {
        secret.view_key()
    }
}

impl From<&SecretKey> for ViewKey {
    fn from(secret: &SecretKey) -> Self {
        secret.view_key()
    }
}

impl TryFrom<rpc::ViewKey> for ViewKey {
    type Error = Error;

    fn try_from(k: rpc::ViewKey) -> Result<Self, Self::Error> {
        let a = k.a.ok_or(Error::InvalidPoint).and_then(|s| s.try_into())?;

        let B = k
            .b_g
            .ok_or(Error::InvalidPoint)
            .and_then(|p| p.try_into())?;

        Ok(Self::new(a, B))
    }
}

impl From<ViewKey> for rpc::ViewKey {
    fn from(k: ViewKey) -> Self {
        Self {
            a: Some(k.a.into()),
            b_g: Some(k.B.into()),
        }
    }
}

const VK_SIZE_A: usize = utils::JUBJUB_SCALAR_SERIALIZED_SIZE;
const VK_SIZE_B: usize = utils::COMPRESSED_JUBJUB_SERIALIZED_SIZE;
const VK_SIZE: usize = VK_SIZE_A + VK_SIZE_B;

impl Into<[u8; VK_SIZE]> for &ViewKey {
    fn into(self) -> [u8; VK_SIZE] {
        let mut bytes = [0x00u8; VK_SIZE];

        utils::serialize_jubjub_scalar(&self.a, &mut bytes[0..VK_SIZE_A]).expect("In-memory write");

        utils::serialize_compressed_jubjub(&self.B, &mut bytes[VK_SIZE_A..VK_SIZE])
            .expect("In-memory write");

        bytes
    }
}

impl TryFrom<String> for ViewKey {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.len() != 128 {
            return Err(Error::InvalidParameters);
        }

        let s = s.as_str();

        let a = hex::decode(&s[0..VK_SIZE_A * 2]).map_err(|_| Error::InvalidPoint)?;
        let a = utils::deserialize_jubjub_scalar(a.as_slice())?;

        let B = hex::decode(&s[VK_SIZE_A * 2..VK_SIZE * 2]).map_err(|_| Error::InvalidPoint)?;
        let B = utils::deserialize_compressed_jubjub(B.as_slice())?;

        Ok(ViewKey::new(a, B))
    }
}

impl fmt::LowerHex for ViewKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: [u8; VK_SIZE] = self.into();

        let a = hex::encode(&bytes[0..VK_SIZE_A]);
        let B = hex::encode(&bytes[VK_SIZE_A..VK_SIZE]);

        write!(f, "{}{}", a, B)
    }
}

impl fmt::UpperHex for ViewKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: [u8; VK_SIZE] = self.into();

        let a = hex::encode_upper(&bytes[0..VK_SIZE_A]);
        let B = hex::encode_upper(&bytes[VK_SIZE_A..VK_SIZE]);

        write!(f, "{}{}", a, B)
    }
}

impl fmt::Display for ViewKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}
