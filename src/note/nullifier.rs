use crate::{rpc, utils, BlsScalar};

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
        unimplemented!()
    }
}

impl From<rpc::Nullifier> for Nullifier {
    fn from(n: rpc::Nullifier) -> Self {
        let scalar = utils::deserialize_bls_scalar(n.h.unwrap().data.as_slice()).unwrap();
        Nullifier(scalar)
    }
}
