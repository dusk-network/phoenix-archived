use crate::{rpc, utils, BlsScalar, Error, JubJubProjective, JubJubScalar, Nonce, Nullifier};

use std::convert::TryFrom;

impl From<JubJubScalar> for rpc::Scalar {
    fn from(s: JubJubScalar) -> Self {
        let mut data = [0x00u8; utils::JUBJUB_SCALAR_SERIALIZED_SIZE];

        utils::serialize_jubjub_scalar(&s, &mut data).expect("In-memory write");

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

        utils::serialize_bls_scalar(&s, &mut data).expect("In-memory write");

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

impl From<JubJubProjective> for rpc::CompressedPoint {
    fn from(p: JubJubProjective) -> Self {
        let mut x = [0x00u8; utils::COMPRESSED_JUBJUB_SERIALIZED_SIZE];

        utils::serialize_compressed_jubjub(&p, &mut x).expect("In-memory write");

        rpc::CompressedPoint { y: x.to_vec() }
    }
}

impl TryFrom<rpc::CompressedPoint> for JubJubProjective {
    type Error = Error;

    fn try_from(p: rpc::CompressedPoint) -> Result<JubJubProjective, Error> {
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

impl From<&rpc::Scalar> for [u8; 32] {
    fn from(s: &rpc::Scalar) -> Self {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&s.data);
        buf
    }
}

impl From<&rpc::CompressedPoint> for [u8; 32] {
    fn from(s: &rpc::CompressedPoint) -> Self {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&s.y);
        buf
    }
}

impl From<&rpc::Nonce> for [u8; 24] {
    fn from(s: &rpc::Nonce) -> Self {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&s.bs);
        buf
    }
}
