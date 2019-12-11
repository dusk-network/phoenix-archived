use crate::CompressedRistretto;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscatedNote<K> {
    commitments: Vec<CompressedRistretto>,
    r: CompressedRistretto,
    pk_r: CompressedRistretto,
    idx: K,
    encrypted_value: Vec<u8>,
    encrypted_blinding_factors: Vec<u8>,
}
