use crate::CompressedRistretto;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparentNote<K> {
    value: u64,
    r: CompressedRistretto,
    pk_r: CompressedRistretto,
    idx: K,
}
