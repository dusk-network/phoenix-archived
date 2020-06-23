use crate::Transaction;

use dusk_plonk::constraint_system::{Proof, StandardComposer};

fn send_circuit(composer: &mut StandardComposer, tx: &Transaction) -> Proof {}
