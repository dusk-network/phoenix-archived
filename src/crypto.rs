use crate::{Error, RistrettoPoint};

use std::convert::TryFrom;

pub fn encrypt<V: AsRef<[u8]>>(_pk_r: RistrettoPoint, _value: V) -> Vec<u8> {
    unimplemented!()
}

pub fn decrypt<V: TryFrom<Vec<u8>>>(_sk_r: RistrettoPoint, _value: &[u8]) -> Result<V, Error> {
    unimplemented!()
}
