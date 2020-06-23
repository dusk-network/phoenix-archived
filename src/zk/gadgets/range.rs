use crate::{BlsScalar, TransactionItem};

use dusk_plonk::constraint_system::StandardComposer;

/// This gadget simply wraps around the composer's `range_gate` function,
/// but takes in any type that implements the [`TransactionItem`] trait,
/// for ease-of-use in circuit construction.
pub fn range<T: TransactionItem>(composer: &mut StandardComposer, item: &T) {
    let value = composer.add_input(BlsScalar::from(item.value()));
    composer.range_gate(value, 64);
}
