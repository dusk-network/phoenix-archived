use crate::{Db, Idx, Note, NoteGenerator, PublicKey, SecretKey, Transaction, TransparentNote};

#[test]
fn transactions_with_transparent_notes() {
    let mut notes = vec![];
    let mut outputs = vec![];
    let mut miner_keys = vec![];

    notes.push(create_and_store_unspent_transparent_note(100));

    // Assert the new unspent note is not nullified
    let sk = &notes[0].0;
    let nullifier = notes[0].4.generate_nullifier(sk);
    assert!(Db::data().fetch_nullifier(&nullifier).unwrap().is_none());

    let mut transaction = Transaction::default();

    // Set the first unspent note as the input of the transaction
    let sk = &notes[0].0;
    transaction.push(notes[0].4.clone().to_transaction_input(sk));

    // Create a expected output of 50 dusk
    outputs.push(create_transparent_output_note(50));

    // Set the fee cost
    miner_keys.push(generate_keys());
    transaction.prepare(&miner_keys[0].1).unwrap();
    let fee_cost = transaction.fee().unwrap().note().value();

    // Create a expected output of 50 - fee dusk
    outputs.push(create_transparent_output_note(50 - fee_cost));
    transaction.push(outputs[1].3.to_transaction_output());

    // Execute the transaction
    transaction.prepare(&miner_keys[0].1).unwrap();
    let unspent_outputs = Db::data().store(&transaction).unwrap();

    // Assert the spent note is nullified
    let sk = &notes[0].0;
    let nullifier = notes[0].4.generate_nullifier(sk);
    assert!(Db::data().fetch_nullifier(&nullifier).unwrap().is_some());

    // Assert the outputs are not nullified
    unspent_outputs.iter().for_each(|idx| {
        let note: TransparentNote = Db::data().fetch_note(idx).unwrap();
        let output_idx = if note.value() == 50 { 0 } else { 1 };
        let nullifier = note.generate_nullifier(&outputs[output_idx].0);
        assert!(Db::data().fetch_nullifier(&nullifier).unwrap().is_none());
    });
}

fn generate_keys() -> (SecretKey, PublicKey) {
    let sk = SecretKey::default();
    let pk = sk.public_key();

    (sk, pk)
}

fn create_and_store_unspent_transparent_note(
    value: u64,
) -> (SecretKey, PublicKey, u64, Idx, TransparentNote) {
    let (sk, pk) = generate_keys();

    let note = TransparentNote::output(&pk, value);
    let idx = Db::data().store_unspent_note(note.box_clone()).unwrap();
    let note: TransparentNote = Db::data().fetch_note(&idx).unwrap();

    (sk, pk, value, idx, note)
}

fn create_transparent_output_note(value: u64) -> (SecretKey, PublicKey, u64, TransparentNote) {
    let (sk, pk) = generate_keys();

    let note = TransparentNote::output(&pk, value);

    (sk, pk, value, note)
}
