/// This file will contain an implementation of the 
/// different macros to vary the different circuit types

use dusk_plonk::constraint_system::StandardComposer;

use crate::{NoteVariant, TransactionItem, ViewKey, Transaction};

#[macro_export]
macro_rules! dusk_tx {
    ($inputs:expr, $outputs:expr, $crossover:expr) => { 
        {
        let mut tx = Transaction::default();
        let value = 100;

        // The inputs
        for i in 0..$inputs {
        let sk = SecretKey::default();
        let vk = sk.view_key();
        let pk = sk.public_key();
        let value = value/inputs;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        let input = note.to_transaction_input(merkle_opening, sk).unwrap();
        
        tx.push_input(input);
        }
    
        let total_output_value = 100;
        let output_value;
        if crossover {
            output_value = total_output_value/(outputs+2);
        } else {
            output_value = total_output_value/(outputs+1);
        }
        
        for i in 0..$outputs {

        let sk = SecretKey::default();
        let vk = sk.view_key();
        let pk = sk.public_key();
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        let output = note.to_transaction_output(output_value, blinding_factor, pk)
    
        tx.push_output(output).unwrap();
        }

        let sk = SecretKey::default();
        let vk = sk.view_key();
        let pk = sk.public_key();
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        let output = note.to_transaction_output(output_value, blinding_factor, pk)
    
        tx.set_fee(output).unwrap();

        if $crossover {
        let sk = SecretKey::default();
        let vk = sk.view_key();
        let pk = sk.public_key();
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        let output = note.to_transaction_output(output_value, blinding_factor, pk)
        
        tx.set_crossover(output);
        tx.set_contract_output(output);
        }


    };

    tx
    }
}




#[test]
fn dusk_tx_test() {
   
}
