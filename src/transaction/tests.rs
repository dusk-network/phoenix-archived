use crate::{
    Db, Idx, Note, NoteGenerator, ObfuscatedNote, PublicKey, Scalar, SecretKey, Transaction,
    TransparentNote, ViewKey,
};

#[test]
fn transaction_items() {
    let (_, _, pk) = generate_keys();
    let value = 25;
    let (note, blinding_factor) = ObfuscatedNote::output(&pk, value);
    let item = note.to_transaction_output(value, blinding_factor);
    assert_eq!(value, item.value());
}

#[test]
fn transaction_zk() {
    let db = Db::new().unwrap();

    let mut inputs = vec![];
    let mut outputs = vec![];
    let mut senders = vec![];
    let mut receivers = vec![];

    // Setup a sender
    senders.push(generate_keys());
    senders.push(generate_keys());

    // Setup receivers
    receivers.push(generate_keys());
    receivers.push(generate_keys());
    receivers.push(generate_keys());

    // Store an unspent note of 100
    let pk = &senders[0].2;
    inputs.push(create_and_store_unspent_note::<TransparentNote>(
        &db, pk, 100,
    ));

    // Store an unspent note of 50
    let pk = &senders[1].2;
    inputs.push(create_and_store_unspent_note::<ObfuscatedNote>(&db, pk, 50));

    // Store an unspent note of 45 with the same sender for a malicious proof verification
    let pk = &senders[1].2;
    inputs.push(create_and_store_unspent_note::<ObfuscatedNote>(&db, pk, 45));

    // Create an output of 97
    let pk = &receivers[0].2;
    outputs.push(create_output_note::<TransparentNote>(pk, 97));

    // Create an output of 30
    let pk = &receivers[1].2;
    outputs.push(create_output_note::<ObfuscatedNote>(pk, 30));

    // Create an output of 20
    let pk = &receivers[2].2;
    outputs.push(create_output_note::<ObfuscatedNote>(pk, 20));

    // Create an output of 92 with the same sender for a malicious proof verification
    let pk = &receivers[0].2;
    outputs.push(create_output_note::<TransparentNote>(pk, 92));

    let mut transaction = Transaction::default();

    // Set the 100 unspent note as the input of the transaction
    let sk = &senders[0].0;
    let vk = senders[0].1;
    let idx = &inputs[0].2;
    let note: TransparentNote = db.fetch_note(idx).unwrap();
    let nullifier = note.generate_nullifier(sk);
    transaction.push(note.to_transaction_input(vk, nullifier));

    // Push the 30 output note to the transaction
    let note = Db::note_box_into::<ObfuscatedNote>(outputs[1].2.box_clone());
    let blinding_factor = outputs[1].3;
    let value = outputs[1].1;
    transaction.push(note.to_transaction_output(value, blinding_factor));

    // Push the 20 output note to the transaction
    let note = Db::note_box_into::<ObfuscatedNote>(outputs[2].2.box_clone());
    let blinding_factor = outputs[2].3;
    let value = outputs[2].1;
    transaction.push(note.to_transaction_output(value, blinding_factor));

    let mut malicious_transaction = transaction.clone();

    // Push the 97 output note to the transaction
    let note = Db::note_box_into::<TransparentNote>(outputs[0].2.box_clone());
    let blinding_factor = outputs[0].3;
    let value = outputs[0].1;
    transaction.push(note.to_transaction_output(value, blinding_factor));

    // Set the 45 unspent note as the input of the malicious transaction
    let sk = &senders[1].0;
    let vk = senders[1].1;
    let idx = &inputs[2].2;
    let note: ObfuscatedNote = db.fetch_note(idx).unwrap();
    let nullifier = note.generate_nullifier(sk);
    malicious_transaction.push(note.to_transaction_input(vk, nullifier));

    // Push the 92 output note to the malicious transaction
    let note = Db::note_box_into::<TransparentNote>(outputs[3].2.box_clone());
    let blinding_factor = outputs[3].3;
    let value = outputs[3].1;
    malicious_transaction.push(note.to_transaction_output(value, blinding_factor));

    let mut insufficient_inputs_transaction = transaction.clone();

    // Set the 50 unspent note as the input of the transaction
    let sk = &senders[1].0;
    let vk = senders[1].1;
    let idx = &inputs[1].2;
    let note: ObfuscatedNote = db.fetch_note(idx).unwrap();
    let nullifier = note.generate_nullifier(sk);
    transaction.push(note.to_transaction_input(vk, nullifier));

    // Grant only transactions with sufficient inputs can be proven
    assert!(insufficient_inputs_transaction.prove().is_err());

    // Proof and verify the main transaction
    let (proof, commitments) = transaction.prove().unwrap();
    transaction.verify(&proof, &commitments).unwrap();

    // The malicious transaction should be consistent by itself
    let (malicious_proof, malicious_commitments) = malicious_transaction.prove().unwrap();
    malicious_transaction
        .verify(&malicious_proof, &malicious_commitments)
        .unwrap();

    // Validate no malicious proof or commitments could be verified successfully
    assert!(transaction.verify(&malicious_proof, &commitments).is_err());
    assert!(transaction.verify(&proof, &malicious_commitments).is_err());
    assert!(transaction
        .verify(&malicious_proof, &malicious_commitments)
        .is_err());

    // The fee should be the difference between the input and output
    assert_eq!(3, transaction.fee().value());
}

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
    notes.push(create_and_store_unspent_note::<TransparentNote>(
        &db, pk, 100,
    ));
    let idx = &notes[0].2;
    let note: TransparentNote = db.fetch_note(idx).unwrap();
    let vk = &senders[0].1;
    assert!(note.is_owned_by(vk));

    // Assert the new unspent note is not nullified
    let sk = &senders[0].0;
    let idx = &notes[0].2;
    let note: TransparentNote = db.fetch_note(idx).unwrap();
    let nullifier = note.generate_nullifier(sk);
    assert!(db.fetch_nullifier(&nullifier).unwrap().is_none());

    let mut transaction = Transaction::default();

    // Set the first unspent note as the input of the transaction
    let sk = &senders[0].0;
    let vk = senders[0].1;
    let idx = &notes[0].2;
    let note: TransparentNote = db.fetch_note(idx).unwrap();
    let nullifier = note.generate_nullifier(sk);
    transaction.push(note.to_transaction_input(vk, nullifier));

    // Set the fee cost
    miner_keys.push(generate_keys());
    let fee_cost = transaction.fee().note().value(None);

    // Create two output notes for the transaction
    let pk = &receivers[0].2;
    outputs.push(create_output_note::<TransparentNote>(pk, 25));
    let pk = &receivers[1].2;
    outputs.push(create_output_note::<TransparentNote>(pk, 50 - fee_cost));
    let note = Db::note_box_into::<TransparentNote>(outputs[0].2.box_clone());
    let blinding_factor = outputs[0].3;
    let value = outputs[0].1;
    transaction.push(note.to_transaction_output(value, blinding_factor));
    let note = Db::note_box_into::<TransparentNote>(outputs[1].2.box_clone());
    let blinding_factor = outputs[1].3;
    let value = outputs[1].1;
    transaction.push(note.to_transaction_output(value, blinding_factor));

    // Execute the transaction
    transaction.prepare(&db).unwrap();
    let unspent_outputs = db.store(&transaction).unwrap();

    // Assert the spent note is nullified
    let sk = &senders[0].0;
    let idx = &notes[0].2;
    let note: TransparentNote = db.fetch_note(idx).unwrap();
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

fn create_and_store_unspent_note<N: Note + NoteGenerator>(
    db: &Db,
    pk: &PublicKey,
    value: u64,
) -> (PublicKey, u64, Idx, Box<dyn Note>, Scalar) {
    let (note, blinding_factor) = N::output(pk, value);
    let note = note.box_clone();

    let idx = db.store_unspent_note(note.box_clone()).unwrap();
    let note: N = db.fetch_note(&idx).unwrap();

    (pk.clone(), value, idx, note.box_clone(), blinding_factor)
}

fn create_output_note<N: Note + NoteGenerator>(
    pk: &PublicKey,
    value: u64,
) -> (PublicKey, u64, Box<dyn Note>, Scalar) {
    let (note, blinding_factor) = N::output(pk, value);
    let note = note.box_clone();

    (pk.clone(), value, note, blinding_factor)
}
