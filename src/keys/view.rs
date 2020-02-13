use super::{PublicKey, SecretKey};
use crate::{rpc, utils, CompressedEdwardsY, EdwardsPoint, Error, Scalar};

use std::convert::{TryFrom, TryInto};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Pair of a secret a and public b·G
///
/// The notes are encrypted against secret a, so this is used to decrypt the blinding factor and
/// value
pub struct ViewKey {
    /// Secret scalar
    pub a: Scalar,
    /// Public field element
    pub b_g: EdwardsPoint,
}

impl Default for ViewKey {
    fn default() -> Self {
        SecretKey::default().view_key()
    }
}

impl ViewKey {
    /// [`ViewKey`] constructor
    pub fn new(a: Scalar, b_g: EdwardsPoint) -> Self {
        ViewKey { a, b_g }
    }

    /// Derive the secret to deterministically construct a [`PublicKey`]
    pub fn public_key(&self) -> PublicKey {
        let a_g = utils::mul_by_basepoint_edwards(&self.a);

        PublicKey::new(a_g, self.b_g)
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
        let a: Scalar = k.a.ok_or(Error::InvalidPoint)?.into();
        let b_g: EdwardsPoint = k
            .b_g
            .ok_or(Error::InvalidPoint)
            .and_then(|p| p.try_into())?;

        Ok(Self::new(a, b_g))
    }
}

impl From<ViewKey> for rpc::ViewKey {
    fn from(k: ViewKey) -> Self {
        Self {
            a: Some(rpc::Scalar::from(k.a)),
            b_g: Some(rpc::CompressedPoint::from(k.b_g)),
        }
    }
}

impl TryFrom<String> for ViewKey {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.len() != 128 {
            return Err(Error::InvalidParameters);
        }

        let s = s.as_str();

        let a = hex::decode(&s[0..64]).map_err(|_| Error::InvalidPoint)?;
        let a = Scalar::from_bits(utils::safe_32_chunk(a.as_slice()));

        let b_g = hex::decode(&s[64..128]).map_err(|_| Error::InvalidPoint)?;
        let b_g = CompressedEdwardsY::from_slice(&utils::safe_32_chunk(b_g.as_slice()))
            .decompress()
            .ok_or(Error::InvalidPoint)?;

        Ok(ViewKey::new(a, b_g))
    }
}

impl fmt::LowerHex for ViewKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = hex::encode(self.a.as_bytes());
        let b_g = hex::encode(self.b_g.compress().as_bytes());

        write!(f, "{}{}", a, b_g)
    }
}

impl fmt::UpperHex for ViewKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = hex::encode_upper(self.a.as_bytes());
        let b_g = hex::encode_upper(self.b_g.compress().as_bytes());

        write!(f, "{}{}", a, b_g)
    }
}

impl fmt::Display for ViewKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}
