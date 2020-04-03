use crate::{BlsScalar, Note, NoteVariant};

use hades252::strategies::{ScalarStrategy, Strategy};
use num_traits::Zero;

pub const ARITY: usize = hades252::WIDTH - 1;
pub const TREE_HEIGHT: usize = 17;

pub trait MerkleProofProvider {
    /// Ability to return the leaves of a given level
    ///
    /// For every level, the first leaf starts with idx 0
    ///
    /// # Example
    ///
    /// This is a graphical representation of arity 3. The actual arity is [`ARITY`]
    ///
    /// The root is represented by (2,0), where 2 is the depth and 0 is the idx
    ///
    /// So, for the following tree
    ///
    /// (0,0) (0,1) (0,2) (0,3) (0,4) (0,5) (0,6) (0,7) (0,8)
    ///   |     |     |     |     |     |     |     |     |
    ///   +---(1,0)---+     +---(1,1)---+     +---(1,2)---+
    ///         |                 |                 |
    ///         +---------------(2,0)---------------+
    ///
    /// With the following values
    ///
    ///   a     b     c     d     e     f     g
    ///   |     |     |     |     |     |     |     |     |
    ///   +-----j-----+     +-----k-----+     +-----l-----+
    ///         |                 |                 |
    ///         +-----------------m-----------------+
    ///
    /// The expected values are:
    ///
    /// query_level(0,2) -> [Some(a), Some(b), Some(c)]
    /// query_level(0,7) -> [Some(g), None, None]
    /// query_level(1,2) -> [Some(j), Some(k), Some(l)]
    /// query_level(2,0) -> [Some(m), None, None]
    fn query_level(&self, depth: u32, idx: usize) -> [Option<BlsScalar>; ARITY];
}

fn leaves_to_perm(leaves: [Option<BlsScalar>; ARITY], perm: &mut [BlsScalar; hades252::WIDTH]) {
    let bitflags = leaves.iter().enumerate().zip(perm.iter_mut().skip(1)).fold(
        0u8,
        |bitflag, ((i, leaf), p)| {
            if let Some(l) = leaf {
                *p = *l;
                bitflag | (1u8 << i)
            } else {
                *p = BlsScalar::zero();
                bitflag
            }
        },
    );

    perm[0] = BlsScalar::from(bitflags);
}

pub struct MerkleProof {
    pub levels: [MerkleLevel; TREE_HEIGHT],
}

impl MerkleProof {
    pub fn new<T: MerkleProofProvider>(tree: &T, note: &NoteVariant) -> Self {
        let mut idx = note.idx() as usize;
        let mut levels = [MerkleLevel::default(); TREE_HEIGHT];

        (0u32..TREE_HEIGHT as u32).for_each(|l| {
            let level = tree.query_level(l, idx);

            levels[l as usize].idx = idx;
            leaves_to_perm(level, &mut levels[l as usize].data);

            idx /= ARITY;
            levels[l as usize].idx -= idx * ARITY;
        });

        // TODO - Kelvin should provide the correct proof
        {
            let mut perm = [BlsScalar::zero(); hades252::WIDTH];
            let mut prev_hash;

            levels[0].data[levels[0].idx + 1] = note.hash();
            perm.copy_from_slice(&levels[0].data);
            prev_hash = ScalarStrategy::new().poseidon(&mut perm);

            for idx in 1..TREE_HEIGHT {
                levels[idx].data[levels[idx].idx + 1] = prev_hash;
                perm.copy_from_slice(&levels[idx].data);
                prev_hash = ScalarStrategy::new().poseidon(&mut perm);
            }
        }

        MerkleProof { levels }
    }

    pub fn verify(&self) -> bool {
        let mut perm = [BlsScalar::zero(); hades252::WIDTH];

        perm.copy_from_slice(&self.levels[0].data);
        let mut hash = ScalarStrategy::new().poseidon(&mut perm);

        self.levels.iter().skip(1).fold(true, |valid, l| {
            let v = l.data[l.idx + 1] == hash;

            perm.copy_from_slice(&l.data);
            hash = ScalarStrategy::new().poseidon(&mut perm);

            valid && v
        })
    }
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct MerkleLevel {
    pub idx: usize,
    pub data: [BlsScalar; hades252::WIDTH],
}
