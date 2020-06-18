use crate::{Note, TransactionInput, TransactionItem};

use dusk_plonk::constraint_system::StandardComposer;
use poseidon252::merkle_proof::{merkle_opening_gadget, PoseidonBranch};

/// Verify the merkle opening
pub fn merkle(composer: &mut StandardComposer, branch: PoseidonBranch, input: TransactionInput) {
    let leaf = composer.add_input(input.note().hash());
    merkle_opening_gadget(composer, branch, leaf, input.merkle_root);
}

#[cfg(test)]
mod tests {
    #[test]
    fn merkle_gadget() {}
}
