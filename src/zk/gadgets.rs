use crate::{ConstraintSystem, LinearCombination, NoteUtxoType, TransactionItem};

use hades252::linear_combination;

pub fn note_preimage(
    cs: &mut dyn ConstraintSystem,
    note_pre_image: LinearCombination,
    x_lc: LinearCombination,
) {
    // TODO - Review in linear_combination::hash if it could ever fail (so should not return
    // result)
    //
    // x = H(y)
    let x = linear_combination::hash(cs, &[note_pre_image]).unwrap();
    cs.constrain(x_lc - x);
}

pub fn transaction_balance(
    cs: &mut dyn ConstraintSystem,
    items: Vec<(&TransactionItem, LinearCombination)>,
    output: LinearCombination,
) {
    let (input, output) = items.iter().fold(
        (LinearCombination::default(), output),
        |(mut input, mut output), (item, value_commitment)| {
            match item.note().utxo() {
                NoteUtxoType::Input => {
                    let total = input.clone();
                    input = input.clone() + value_commitment.clone();
                    cs.constrain(input.clone() - (total + value_commitment.clone()));
                }
                NoteUtxoType::Output => {
                    let total = output.clone();
                    output = output.clone() + value_commitment.clone();
                    cs.constrain(output.clone() - (total + value_commitment.clone()));
                }
            }

            (input, output)
        },
    );

    cs.constrain(input - output);
}
