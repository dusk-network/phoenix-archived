use crate::{crypto, zk, BlsScalar};

use std::mem;

use num_traits::{One, Zero};

#[derive(Debug, Clone, Copy)]
pub struct ZkMerkleProof {
    pub levels: [ZkMerkleLevel; crypto::TREE_HEIGHT],
}

impl ZkMerkleProof {
    pub fn new(composer: &mut zk::Composer, merkle: &crypto::MerkleProof) -> Self {
        let mut levels = [ZkMerkleLevel::default(); crypto::TREE_HEIGHT];
        let zero = composer.add_input(BlsScalar::zero());
        let one = composer.add_input(BlsScalar::one());
        let zero = [zero; crypto::ARITY];

        merkle
            .levels
            .iter()
            .zip(levels.iter_mut())
            .for_each(|(m, l)| {
                m.data
                    .iter()
                    .zip(l.perm.iter_mut())
                    .for_each(|(scalar, var)| {
                        *var = composer.add_input(*scalar);
                    });

                l.bitflags.copy_from_slice(&zero);
                l.bitflags[m.idx] = one;

                l.current = composer.add_input(m.data[m.idx + 1]);
            });

        Self { levels }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ZkMerkleLevel {
    pub bitflags: [zk::Variable; crypto::ARITY],
    pub perm: [zk::Variable; hades252::WIDTH],
    pub current: zk::Variable,
}

impl Default for ZkMerkleLevel {
    fn default() -> Self {
        Self {
            bitflags: [unsafe { mem::zeroed() }; crypto::ARITY],
            perm: [unsafe { mem::zeroed() }; hades252::WIDTH],
            current: unsafe { mem::zeroed() },
        }
    }
}
