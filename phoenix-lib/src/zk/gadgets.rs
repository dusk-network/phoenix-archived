use crate::{ConstraintSystem, LinearCombination, Note, NoteUtxoType, Scalar, TransactionItem};

use hades252::strategies::{GadgetStrategy, Strategy};

/// Pre-image of the note
pub fn note_preimage(
    cs: &mut dyn ConstraintSystem,
    note_pre_image: LinearCombination,
    x_lc: LinearCombination,
) {
    let mut strategy = GadgetStrategy::new(cs);

    let mut input = vec![LinearCombination::from(Scalar::zero()); hades252::WIDTH];
    input[1] = note_pre_image;
    let x = strategy.perm(input)[1].clone();

    // x = H(y)
    cs.constrain(x_lc - x);
}

/// Constrains that the sum of inputs = outputs + fee
pub fn transaction_balance(
    cs: &mut dyn ConstraintSystem,
    items: Vec<(&TransactionItem, LinearCombination)>,
    output: LinearCombination,
) {
    let (input, output) = items.into_iter().fold(
        (LinearCombination::default(), output),
        |(mut input, mut output), (item, value_commitment)| {
            match item.note().utxo() {
                NoteUtxoType::Input => {
                    let total = input.clone();
                    input = input.clone() + value_commitment.clone();
                    cs.constrain(input.clone() - (total + value_commitment));
                }
                NoteUtxoType::Output => {
                    let total = output.clone();
                    output = output.clone() + value_commitment.clone();
                    cs.constrain(output.clone() - (total + value_commitment));
                }
            }

            (input, output)
        },
    );

    cs.constrain(input - output);
}
