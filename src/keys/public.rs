use super::SecretKey;
use crate::{rpc, EdwardsPoint, Error};

use std::convert::{TryFrom, TryInto};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    pub a_g: EdwardsPoint,
    pub b_g: EdwardsPoint,
}

impl Default for PublicKey {
    fn default() -> Self {
        SecretKey::default().public_key()
    }
}

impl PublicKey {
    pub fn new(a_g: EdwardsPoint, b_g: EdwardsPoint) -> Self {
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
        let a_g: EdwardsPoint = k
            .a_g
            .ok_or(Error::InvalidPoint)
            .and_then(|p| p.try_into())?;
        let b_g: EdwardsPoint = k
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
