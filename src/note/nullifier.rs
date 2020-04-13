use crate::{rpc, utils, BlsScalar, Error};

use std::io::{self, Read, Write};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nullifier(pub BlsScalar);

impl From<BlsScalar> for Nullifier {
    fn from(s: BlsScalar) -> Self {
        Nullifier(s)
    }
}

impl Into<BlsScalar> for Nullifier {
    fn into(self) -> BlsScalar {
        self.0
    }
}

impl AsRef<[u8]> for Nullifier {
    fn as_ref(&self) -> &[u8] {
        unimplemented!();
    }
}

impl Nullifier {
    pub fn to_bytes(&self) -> Result<[u8; 32], Error> {
        let mut scalar_buf = [0u8; 32];
        utils::serialize_bls_scalar(&self.0, &mut scalar_buf)?;
        Ok(scalar_buf)
    }
}

impl From<rpc::Nullifier> for Nullifier {
    fn from(n: rpc::Nullifier) -> Self {
        let scalar = utils::deserialize_bls_scalar(n.h.unwrap().data.as_slice()).unwrap();
        Nullifier(scalar)
    }
}

impl From<&rpc::Nullifier> for Nullifier {
    fn from(n: &rpc::Nullifier) -> Self {
        let scalar = utils::deserialize_bls_scalar(n.h.as_ref().unwrap().data.as_slice()).unwrap();
        Nullifier(scalar)
    }
}

impl Read for Nullifier {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        buf.chunks_mut(utils::BLS_SCALAR_SERIALIZED_SIZE)
            .next()
            .ok_or(Error::InvalidParameters)
            .and_then(|c| utils::serialize_bls_scalar(&self.0, c))
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

        (*self).0 = nullifier;

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
