use super::{PublicKey, SecretKey};
use crate::{rpc, utils, EdwardsPoint, Error, Scalar};

use std::convert::{TryFrom, TryInto};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewKey {
    pub a: Scalar,
    pub b_g: EdwardsPoint,
}

impl Default for ViewKey {
    fn default() -> Self {
        SecretKey::default().view_key()
    }
}

impl ViewKey {
    pub fn new(a: Scalar, b_g: EdwardsPoint) -> Self {
        ViewKey { a, b_g }
    }

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
