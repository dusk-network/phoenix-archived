use crate::{PublicKey, SecretKey};

pub fn encrypt<V: AsRef<[u8]>>(_pk: &PublicKey, value: V) -> Vec<u8> {
    // theirpk a_p
    // oursk r
    // TODO - Implement
    value.as_ref().to_vec()
}

pub fn decrypt(_sk: &SecretKey, value: &[u8]) -> Vec<u8> {
    // ourpk r_p
    // theirsk a
    // TODO - Implement
    value.as_ref().to_vec()
}
