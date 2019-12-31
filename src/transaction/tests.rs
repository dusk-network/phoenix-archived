use crate::{
    Db, Idx, Note, NoteGenerator, PublicKey, SecretKey, Transaction, TransparentNote, ViewKey,
};

#[test]
fn transactions_with_transparent_notes() {
    let db = Db::new().unwrap();

    let mut notes = vec![];
    let mut outputs = vec![];
    let mut senders = vec![];
    let mut receivers = vec![];
    let mut miner_keys = vec![];

    // Setup a sender
    senders.push(generate_keys());

    // Setup receivers
    receivers.push(generate_keys());
    receivers.push(generate_keys());

    // Store an unspent note
    let pk = &senders[0].2;
    notes.push(create_and_store_unspent_transparent_note(&db, pk, 100));
    let note = &notes[0].3;
    let vk = &senders[0].1;
    assert!(note.is_owned_by(vk));

    // Assert the new unspent note is not nullified
    let sk = &senders[0].0;
    let note = &notes[0].3;
    let nullifier = note.generate_nullifier(sk);
    assert!(db.fetch_nullifier(&nullifier).unwrap().is_none());

    let mut transaction = Transaction::default();

    // Set the first unspent note as the input of the transaction
    let sk = &senders[0].0;
    let vk = senders[0].1;
    let note = &notes[0].3;
    let nullifier = note.generate_nullifier(sk);
    transaction.push(note.clone().to_transaction_input(vk, nullifier));

    // Set the fee cost
    miner_keys.push(generate_keys());
    let miner_vk = miner_keys[0].1;
    transaction.calculate_fee(&miner_vk);
    let fee_cost = transaction.fee().unwrap().note().value(None);

    // Create two output notes for the transaction
    let pk = &receivers[0].2;
    outputs.push(create_transparent_output_note(pk, 50));
    let pk = &receivers[1].2;
    outputs.push(create_transparent_output_note(pk, 50 - fee_cost));
    let note = &outputs[0].2;
    let vk = receivers[0].1;
    transaction.push(note.to_transaction_output(vk));
    let note = &outputs[1].2;
    let vk = receivers[1].1;
    transaction.push(note.to_transaction_output(vk));

    // Execute the transaction
    transaction.prepare(&db).unwrap();
    let unspent_outputs = db.store(&transaction).unwrap();

    // Assert the spent note is nullified
    let sk = &senders[0].0;
    let note = &notes[0].3;
    let nullifier = note.generate_nullifier(sk);
    assert!(db.fetch_nullifier(&nullifier).unwrap().is_some());

    // Assert the outputs are not nullified
    unspent_outputs.iter().for_each(|idx| {
        let note: TransparentNote = db.fetch_note(idx).unwrap();
        let sk = receivers
            .iter()
            .fold(SecretKey::default(), |sk, (r_sk, r_vk, _)| {
                if note.is_owned_by(r_vk) {
                    r_sk.clone()
                } else {
                    sk
                }
            });
        let nullifier = note.generate_nullifier(&sk);
        assert!(db.fetch_nullifier(&nullifier).unwrap().is_none());
    });
}

fn generate_keys() -> (SecretKey, ViewKey, PublicKey) {
    let sk = SecretKey::default();
    let vk = sk.view_key();
    let pk = sk.public_key();

    (sk, vk, pk)
}

fn create_and_store_unspent_transparent_note(
    db: &Db,
    pk: &PublicKey,
    value: u64,
) -> (PublicKey, u64, Idx, TransparentNote) {
    let note = TransparentNote::output(pk, value);
    let idx = db.store_unspent_note(note.box_clone()).unwrap();
    let note: TransparentNote = db.fetch_note(&idx).unwrap();

    (pk.clone(), value, idx, note)
}

fn create_transparent_output_note(pk: &PublicKey, value: u64) -> (PublicKey, u64, TransparentNote) {
    let note = TransparentNote::output(pk, value);

    (pk.clone(), value, note)
}
