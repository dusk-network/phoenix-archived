use crate::{ConstraintSystem, Error, LinearCombination};

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
    cs.constrain(x_lc - x.clone());
}
