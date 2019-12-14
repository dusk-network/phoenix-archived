use crate::RistrettoPoint;

pub fn encrypt<V: AsRef<[u8]>>(_pk_r: &RistrettoPoint, value: V) -> Vec<u8> {
    // TODO - Implement
    value.as_ref().to_vec()
}

pub fn decrypt(_sk_r: &RistrettoPoint, value: &[u8]) -> Vec<u8> {
    // TODO - Implement
    value.as_ref().to_vec()
}
