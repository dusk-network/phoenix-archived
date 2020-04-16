use crate::{rpc, utils, BlsScalar, Error};

use std::convert::{TryFrom, TryInto};
use std::io::{self, Read, Write};

use unprolix::{Getters, Setters};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Getters, Setters)]
pub struct Nullifier {
    s: BlsScalar,
    b: [u8; utils::BLS_SCALAR_SERIALIZED_SIZE],
}

impl Nullifier {
    pub fn new(s: BlsScalar) -> Self {
        let mut b = [0x00u8; utils::BLS_SCALAR_SERIALIZED_SIZE];
        utils::serialize_bls_scalar(&s, &mut b).expect("In-memory write");

        Self { s, b }
    }
}

impl From<BlsScalar> for Nullifier {
    fn from(s: BlsScalar) -> Self {
        Nullifier::new(s)
    }
}

impl Into<BlsScalar> for Nullifier {
    fn into(self) -> BlsScalar {
        self.s
    }
}

impl AsRef<[u8]> for Nullifier {
    fn as_ref(&self) -> &[u8] {
        &self.b
    }
}

impl Nullifier {
    pub fn to_bytes(&self) -> Result<[u8; 32], Error> {
        let mut scalar_buf = [0u8; 32];
        utils::serialize_bls_scalar(self.s(), &mut scalar_buf)?;

        Ok(scalar_buf)
    }
}

impl TryFrom<rpc::Nullifier> for Nullifier {
    type Error = Error;

    fn try_from(n: rpc::Nullifier) -> Result<Self, Error> {
        let s = n.h.ok_or(Error::InvalidParameters)?.try_into()?;

        Ok(Nullifier::new(s))
    }
}

impl TryFrom<&rpc::Nullifier> for Nullifier {
    type Error = Error;

    fn try_from(n: &rpc::Nullifier) -> Result<Self, Error> {
        let s =
            n.h.as_ref()
                .cloned()
                .ok_or(Error::InvalidParameters)?
                .try_into()?;

        Ok(Nullifier::new(s))
    }
}

impl Read for Nullifier {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        buf.chunks_mut(utils::BLS_SCALAR_SERIALIZED_SIZE)
            .next()
            .ok_or(Error::InvalidParameters)
            .and_then(|c| utils::serialize_bls_scalar(self.s(), c))
            .map_err::<io::Error, _>(|e| e.into())?;
        let n = utils::BLS_SCALAR_SERIALIZED_SIZE;

        Ok(n)
    }
}

impl Write for Nullifier {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let nullifier = buf
            .chunks(utils::BLS_SCALAR_SERIALIZED_SIZE)
            .next()
            .ok_or(Error::InvalidParameters)
            .and_then(utils::deserialize_bls_scalar)
            .map_err::<io::Error, _>(|e| e.into())?;
        let n = utils::BLS_SCALAR_SERIALIZED_SIZE;

        self.set_s(nullifier);

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
