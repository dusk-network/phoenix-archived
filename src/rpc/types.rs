use crate::{rpc, utils, BlsScalar, Error, JubJubProjective, JubJubScalar, Nonce};

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
//
//impl From<rpc::InputOutput> for NoteUtxoType {
//    fn from(io: rpc::InputOutput) -> NoteUtxoType {
//        match io {
//            rpc::InputOutput::Input => NoteUtxoType::Input,
//            rpc::InputOutput::Output => NoteUtxoType::Output,
//        }
//    }
//}
//
//impl From<NoteUtxoType> for rpc::InputOutput {
//    fn from(utxo: NoteUtxoType) -> rpc::InputOutput {
//        match utxo {
//            NoteUtxoType::Input => rpc::InputOutput::Input,
//            NoteUtxoType::Output => rpc::InputOutput::Output,
//        }
//    }
//}
//
//impl TryFrom<i32> for rpc::InputOutput {
//    type Error = Error;
//
//    fn try_from(io: i32) -> Result<Self, Self::Error> {
//        match io {
//            0 => Ok(rpc::InputOutput::Input),
//            1 => Ok(rpc::InputOutput::Output),
//            _ => Err(Error::InvalidParameters),
//        }
//    }
//}
//
//impl TryFrom<rpc::Nullifier> for Nullifier {
//    type Error = Error;
//
//    fn try_from(nullifier: rpc::Nullifier) -> Result<Self, Self::Error> {
//        nullifier
//            .h
//            .ok_or(Error::InvalidParameters)
//            .map(|x| Nullifier::new(x.into()))
//    }
//}
//
//impl From<Nullifier> for rpc::Nullifier {
//    fn from(nullifier: Nullifier) -> rpc::Nullifier {
//        rpc::Nullifier {
//            h: Some(nullifier.x.into()),
//        }
//    }
//}
