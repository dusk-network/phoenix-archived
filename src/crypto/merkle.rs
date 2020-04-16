use crate::{BlsScalar, Error, Note, NoteVariant};

use hades252::strategies::{ScalarStrategy, Strategy};
use num_traits::Zero;
use unprolix::{Constructor, Getters, Setters};

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
    fn query_level(&self, depth: u32, idx: usize) -> Result<[Option<BlsScalar>; ARITY], Error>;

    /// Create a merkle opening proof provided a note position
    fn opening(&self, note: &NoteVariant) -> Result<MerkleProof, Error> {
        let mut idx = note.idx() as usize;
        let mut levels = [MerkleLevel::default(); TREE_HEIGHT];

        for l in 0u32..TREE_HEIGHT as u32 {
            let level = self.query_level(l, idx)?;

            levels[l as usize].idx = idx;
            leaves_to_perm(level, &mut levels[l as usize].data);

            idx /= ARITY;
            levels[l as usize].idx -= idx * ARITY;
        }

        // TODO - Kelvin should provide the correct proof
        Ok(MerkleProof::mock(note.hash()))
    }

    /// Return the merkle root of the state
    fn root(&self) -> Result<BlsScalar, Error>;
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Constructor, Getters, Setters)]
pub struct MerkleProof {
    levels: [MerkleLevel; TREE_HEIGHT],
}

impl MerkleProof {
    pub fn root(&self) -> &BlsScalar {
        &self.levels[TREE_HEIGHT - 1].data[1]
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

    pub fn mock(mut bit: BlsScalar) -> Self {
        let mut merkle_proof = MerkleProof::default();
        let mut perm = [BlsScalar::zero(); hades252::WIDTH];

        merkle_proof.levels[0].data[merkle_proof.levels[0].idx + 1] = bit;
        perm.copy_from_slice(&merkle_proof.levels[0].data);
        bit = ScalarStrategy::new().poseidon(&mut perm);

        for idx in 1..TREE_HEIGHT {
            merkle_proof.levels[idx].data[merkle_proof.levels[idx].idx + 1] = bit;
            perm.copy_from_slice(&merkle_proof.levels[idx].data);
            bit = ScalarStrategy::new().poseidon(&mut perm);
        }

        merkle_proof
    }
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Constructor, Getters, Setters)]
pub struct MerkleLevel {
    #[unprolix(copy)]
    idx: usize,
    data: [BlsScalar; hades252::WIDTH],
}
