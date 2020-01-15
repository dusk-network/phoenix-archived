use crate::{
    CompressedEdwardsY, CompressedRistretto, EdwardsPoint, Error, RistrettoPoint,
    Scalar as BaseScalar,
};

use std::cmp;
use std::convert::TryInto;

use prost::Message;

#[derive(Clone, PartialEq, Message)]
pub struct Scalar {
    #[prost(bytes, required, tag = "1")]
    data: Vec<u8>,
}

impl From<BaseScalar> for Scalar {
    fn from(s: BaseScalar) -> Self {
        Self {
            data: s.to_bytes().to_vec(),
        }
    }
}

impl Into<BaseScalar> for Scalar {
    fn into(self) -> BaseScalar {
        BaseScalar::from_bits(vec_to_slice(self.data))
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct CompressedPoint {
    #[prost(bytes, required, tag = "1")]
    y: Vec<u8>,
}

impl From<CompressedEdwardsY> for CompressedPoint {
    fn from(p: CompressedEdwardsY) -> Self {
        Self {
            y: p.to_bytes().to_vec(),
        }
    }
}

impl From<EdwardsPoint> for CompressedPoint {
    fn from(p: EdwardsPoint) -> Self {
        p.compress().into()
    }
}

impl Into<CompressedEdwardsY> for CompressedPoint {
    fn into(self) -> CompressedEdwardsY {
        CompressedEdwardsY::from_slice(&vec_to_slice(self.y))
    }
}

impl TryInto<EdwardsPoint> for CompressedPoint {
    type Error = Error;

    fn try_into(self) -> Result<EdwardsPoint, Self::Error> {
        let p: CompressedEdwardsY = self.into();
        p.decompress().ok_or(Error::InvalidPoint)
    }
}

impl From<CompressedRistretto> for CompressedPoint {
    fn from(p: CompressedRistretto) -> Self {
        Self {
            y: p.to_bytes().to_vec(),
        }
    }
}

impl From<RistrettoPoint> for CompressedPoint {
    fn from(p: RistrettoPoint) -> Self {
        p.compress().into()
    }
}

impl Into<CompressedRistretto> for CompressedPoint {
    fn into(self) -> CompressedRistretto {
        CompressedRistretto::from_slice(&vec_to_slice(self.y))
    }
}

impl TryInto<RistrettoPoint> for CompressedPoint {
    type Error = Error;

    fn try_into(self) -> Result<RistrettoPoint, Self::Error> {
        let p: CompressedRistretto = self.into();
        p.decompress().ok_or(Error::InvalidPoint)
    }
}

/// Safe conversion from vec to slice of 32 bytes
fn vec_to_slice(v: Vec<u8>) -> [u8; 32] {
    let mut s = [0u8; 32];

    let chunk = cmp::min(v.len(), 32);
    (&mut s[0..chunk]).copy_from_slice(&v[0..chunk]);

    s
}
