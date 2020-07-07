/// This file will contain an implementation of the 
/// different macros to vary the different circuit types

use dusk_plonk::constraint_system::StandardComposer;
use phoenix::{
    utils, zk, Transaction}
use crate::{NoteVariant, TransactionItem, ViewKey};

macro_rules! phoenix_tx(inputs, outputs, crossover) {
    () => { 
        let mut tx = Transaction::default();

        for i in 0..inputs {
        let sk = SecretKey::default();
        let vk = sk.view_key();
        let pk = sk.public_key();
        let value = 100;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        let input = note.to_transaction_input(merkle_opening, sk).unwrap();
        tx.push_input(input);
        }
    
        for i in 0..outputs {
        let sk = SecretKey::default();
        let vk = sk.view_key();
        let pk = sk.public_key();
        let value = 100;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        let output = note.to_transaction_output(value, blinding_factor, pk))
    
        tx.push_output(output).unwrap();
        }

        for i in 0..outputs {
        let sk = SecretKey::default();
        let vk = sk.view_key();
        let pk = sk.public_key();
        let value = 100;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        let output = note.to_transaction_output(value, blinding_factor, pk))
        
        tx.set_crossover;
        }






       
        
    };
}

fn send_to_obfuscate_variant! () {
    
}