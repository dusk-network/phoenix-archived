use crate::{
    rpc, utils, BlsScalar, Error, JubJubAffine, JubJubExtended, JubJubScalar, Nonce, Nullifier,
};

use std::convert::TryFrom;

impl From<JubJubScalar> for rpc::Scalar {
    fn from(s: JubJubScalar) -> Self {
        let mut data = [0x00u8; utils::JUBJUB_SCALAR_SERIALIZED_SIZE];

        data.copy_from_slice(&s.to_bytes()[..]);

        rpc::Scalar {
            data: data.to_vec(),
        }
    }
}

impl TryFrom<rpc::Scalar> for JubJubScalar {
    type Error = Error;

    fn try_from(s: rpc::Scalar) -> Result<JubJubScalar, Error> {
        utils::deserialize_jubjub_scalar(s.data.as_slice())
    }
}

impl From<BlsScalar> for rpc::Scalar {
    fn from(s: BlsScalar) -> Self {
        let mut data = [0x00u8; utils::BLS_SCALAR_SERIALIZED_SIZE];

        data.copy_from_slice(&s.to_bytes()[..]);

        rpc::Scalar {
            data: data.to_vec(),
        }
    }
}

impl From<Nullifier> for rpc::Nullifier {
    fn from(n: Nullifier) -> Self {
        rpc::Nullifier {
            h: Some((*n.s()).into()),
        }
    }
}

impl TryFrom<rpc::Scalar> for BlsScalar {
    type Error = Error;

    fn try_from(s: rpc::Scalar) -> Result<BlsScalar, Error> {
        utils::deserialize_bls_scalar(s.data.as_slice())
    }
}

impl From<JubJubExtended> for rpc::CompressedPoint {
    fn from(p: JubJubExtended) -> Self {
        let mut x = [0x00u8; utils::COMPRESSED_JUBJUB_SERIALIZED_SIZE];

        x.copy_from_slice(&JubJubAffine::from(p).to_bytes()[..]);

        rpc::CompressedPoint { y: x.to_vec() }
    }
}

impl TryFrom<rpc::CompressedPoint> for JubJubExtended {
    type Error = Error;

    fn try_from(p: rpc::CompressedPoint) -> Result<JubJubExtended, Error> {
        utils::deserialize_compressed_jubjub(p.y.as_slice())
    }
}

impl Into<rpc::Nonce> for Nonce {
    fn into(self) -> rpc::Nonce {
        rpc::Nonce {
            bs: self.0.to_vec(),
        }
    }
}

impl TryFrom<rpc::Nonce> for Nonce {
    type Error = Error;

    fn try_from(nonce: rpc::Nonce) -> Result<Self, Self::Error> {
        Nonce::from_slice(nonce.bs.as_slice()).ok_or(Error::InvalidParameters)
    }
}
