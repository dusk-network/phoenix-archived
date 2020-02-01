use crate::{
    rpc, utils, CompressedEdwardsY, CompressedRistretto, EdwardsPoint, Error, Nonce, NoteUtxoType,
    Nullifier, RistrettoPoint, Scalar,
};

use std::convert::{TryFrom, TryInto};

impl From<Scalar> for rpc::Scalar {
    fn from(s: Scalar) -> Self {
        rpc::Scalar {
            data: s.as_bytes().to_vec(),
        }
    }
}

impl Into<Scalar> for rpc::Scalar {
    fn into(self) -> Scalar {
        Scalar::from_bits(utils::safe_32_chunk(self.data.as_slice()))
    }
}

impl From<CompressedEdwardsY> for rpc::CompressedPoint {
    fn from(s: CompressedEdwardsY) -> Self {
        rpc::CompressedPoint {
            y: s.as_bytes().to_vec(),
        }
    }
}

impl Into<CompressedEdwardsY> for rpc::CompressedPoint {
    fn into(self) -> CompressedEdwardsY {
        CompressedEdwardsY::from_slice(&utils::safe_32_chunk(self.y.as_slice()))
    }
}

impl From<CompressedRistretto> for rpc::CompressedPoint {
    fn from(s: CompressedRistretto) -> Self {
        rpc::CompressedPoint {
            y: s.as_bytes().to_vec(),
        }
    }
}

impl Into<CompressedRistretto> for rpc::CompressedPoint {
    fn into(self) -> CompressedRistretto {
        CompressedRistretto::from_slice(&utils::safe_32_chunk(self.y.as_slice()))
    }
}

impl From<EdwardsPoint> for rpc::CompressedPoint {
    fn from(s: EdwardsPoint) -> Self {
        rpc::CompressedPoint {
            y: s.compress().as_bytes().to_vec(),
        }
    }
}

impl TryInto<EdwardsPoint> for rpc::CompressedPoint {
    type Error = Error;

    fn try_into(self) -> Result<EdwardsPoint, Self::Error> {
        let y: CompressedEdwardsY = self.into();
        y.decompress().ok_or(Error::InvalidPoint)
    }
}

impl From<RistrettoPoint> for rpc::CompressedPoint {
    fn from(s: RistrettoPoint) -> Self {
        rpc::CompressedPoint {
            y: s.compress().as_bytes().to_vec(),
        }
    }
}

impl TryInto<RistrettoPoint> for rpc::CompressedPoint {
    type Error = Error;

    fn try_into(self) -> Result<RistrettoPoint, Self::Error> {
        let y: CompressedRistretto = self.into();
        y.decompress().ok_or(Error::InvalidPoint)
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

impl From<rpc::InputOutput> for NoteUtxoType {
    fn from(io: rpc::InputOutput) -> NoteUtxoType {
        match io {
            rpc::InputOutput::Input => NoteUtxoType::Input,
            rpc::InputOutput::Output => NoteUtxoType::Output,
        }
    }
}

impl From<NoteUtxoType> for rpc::InputOutput {
    fn from(utxo: NoteUtxoType) -> rpc::InputOutput {
        match utxo {
            NoteUtxoType::Input => rpc::InputOutput::Input,
            NoteUtxoType::Output => rpc::InputOutput::Output,
        }
    }
}

impl TryFrom<i32> for rpc::InputOutput {
    type Error = Error;

    fn try_from(io: i32) -> Result<Self, Self::Error> {
        match io {
            0 => Ok(rpc::InputOutput::Input),
            1 => Ok(rpc::InputOutput::Output),
            _ => Err(Error::InvalidParameters),
        }
    }
}

impl TryFrom<rpc::Nullifier> for Nullifier {
    type Error = Error;

    fn try_from(nullifier: rpc::Nullifier) -> Result<Self, Self::Error> {
        nullifier
            .h
            .ok_or(Error::InvalidParameters)
            .map(|x| Nullifier::new(x.into()))
    }
}

impl From<Nullifier> for rpc::Nullifier {
    fn from(nullifier: Nullifier) -> rpc::Nullifier {
        rpc::Nullifier {
            h: Some(nullifier.x.into()),
        }
    }
}
