use super::{CompressedPoint, Scalar};
use crate::{
    Error, PublicKey as BasePublicKey, SecretKey as BaseSecretKey, ViewKey as BaseViewKey,
};

use std::convert::TryInto;

use prost::Message;

#[derive(Clone, PartialEq, Message)]
pub struct SecretKey {
    #[prost(message, required, tag = "1")]
    a: Scalar,
    #[prost(message, required, tag = "2")]
    b: Scalar,
}

impl From<BaseSecretKey> for SecretKey {
    fn from(sk: BaseSecretKey) -> Self {
        Self {
            a: sk.a.into(),
            b: sk.b.into(),
        }
    }
}

impl Into<BaseSecretKey> for SecretKey {
    fn into(self) -> BaseSecretKey {
        BaseSecretKey::new(self.a.into(), self.b.into())
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct ViewKey {
    #[prost(message, required, tag = "1")]
    a: Scalar,
    #[prost(message, required, tag = "2")]
    b_g: CompressedPoint,
}

impl From<BaseViewKey> for ViewKey {
    fn from(vk: BaseViewKey) -> Self {
        Self {
            a: vk.a.into(),
            b_g: vk.b_g.into(),
        }
    }
}

impl TryInto<BaseViewKey> for ViewKey {
    type Error = Error;

    fn try_into(self) -> Result<BaseViewKey, Self::Error> {
        Ok(BaseViewKey::new(self.a.into(), self.b_g.try_into()?))
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct PublicKey {
    #[prost(message, required, tag = "1")]
    a_g: CompressedPoint,
    #[prost(message, required, tag = "2")]
    b_g: CompressedPoint,
}

impl From<BasePublicKey> for PublicKey {
    fn from(pk: BasePublicKey) -> Self {
        Self {
            a_g: pk.a_g.into(),
            b_g: pk.b_g.into(),
        }
    }
}

impl TryInto<BasePublicKey> for PublicKey {
    type Error = Error;

    fn try_into(self) -> Result<BasePublicKey, Self::Error> {
        Ok(BasePublicKey::new(
            self.a_g.try_into()?,
            self.b_g.try_into()?,
        ))
    }
}
