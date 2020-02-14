use crate::{
    rpc, Db, Idx, Note, NoteGenerator, NoteVariant, ObfuscatedNote, PublicKey, Scalar, SecretKey,
    Transaction, TransparentNote, ViewKey,
};

use std::convert::TryInto;

#[test]
fn transaction_items() {
    let (_, _, pk) = generate_keys();
    let value = 25;
    let (note, blinding_factor) = ObfuscatedNote::output(&pk, value);
    let item = note.to_transaction_output(value, blinding_factor, pk);
    assert_eq!(value, item.value());
}

#[test]
fn transaction_zk() {
    let mut db = Db::new().unwrap();

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
        &mut db, pk, 100,
    ));

    // Store an unspent note of 50
    let pk = &senders[1].2;
    inputs.push(create_and_store_unspent_note::<ObfuscatedNote>(
        &mut db, pk, 50,
    ));

    // Store an unspent note of 45 with the same sender for a malicious proof verification
    let pk = &senders[1].2;
    inputs.push(create_and_store_unspent_note::<ObfuscatedNote>(
        &mut db, pk, 45,
    ));

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
    let sk = senders[0].0;
    let idx = &inputs[0].2;
    let note: TransparentNote = db.fetch_note(idx).unwrap().try_into().unwrap();
    transaction.push(note.to_transaction_input(sk));

    // Push the 30 output note to the transaction
    let note: ObfuscatedNote = outputs[1].2.clone().try_into().unwrap();
    let blinding_factor = outputs[1].3;
    let pk = outputs[1].0;
    let value = outputs[1].1;
    transaction.push(note.to_transaction_output(value, blinding_factor, pk));

    // Push the 20 output note to the transaction
    let note: ObfuscatedNote = outputs[2].2.clone().try_into().unwrap();
    let blinding_factor = outputs[2].3;
    let pk = outputs[2].0;
    let value = outputs[2].1;
    transaction.push(note.to_transaction_output(value, blinding_factor, pk));

    let mut malicious_transaction = transaction.clone();

    // Push the 97 output note to the transaction
    let note: TransparentNote = outputs[0].2.clone().try_into().unwrap();
    let blinding_factor = outputs[0].3;
    let pk = outputs[0].0;
    let value = outputs[0].1;
    transaction.push(note.to_transaction_output(value, blinding_factor, pk));

    // Set the 45 unspent note as the input of the malicious transaction
    let sk = senders[1].0;
    let idx = &inputs[2].2;
    let note: ObfuscatedNote = db.fetch_note(idx).unwrap().try_into().unwrap();
    malicious_transaction.push(note.to_transaction_input(sk));

    // Push the 92 output note to the malicious transaction
    let note: TransparentNote = outputs[3].2.clone().try_into().unwrap();
    let blinding_factor = outputs[3].3;
    let pk = outputs[3].0;
    let value = outputs[3].1;
    malicious_transaction.push(note.to_transaction_output(value, blinding_factor, pk));

    let mut insufficient_inputs_transaction = transaction.clone();

    // Set the 50 unspent note as the input of the transaction
    let sk = senders[1].0;
    let idx = &inputs[1].2;
    let note: ObfuscatedNote = db.fetch_note(idx).unwrap().try_into().unwrap();
    transaction.push(note.to_transaction_input(sk));

    // Grant only transactions with sufficient inputs can be proven
    assert!(insufficient_inputs_transaction.prove().is_err());

    // Proof and verify the main transaction
    transaction.prove().unwrap();
    transaction.verify().unwrap();

    let proof = transaction.r1cs().cloned().unwrap();
    let commitments = transaction.commitments().clone();

    // The malicious transaction should be consistent by itself
    malicious_transaction.prove().unwrap();
    let malicious_proof = malicious_transaction.r1cs().cloned().unwrap();
    let malicious_commitments = malicious_transaction.commitments().clone();
    malicious_transaction.verify().unwrap();

    // Validate no malicious proof or commitments could be verified successfully
    transaction.set_r1cs(malicious_proof.clone());
    transaction.set_commitments(commitments);
    assert!(transaction.verify().is_err());

    transaction.set_r1cs(proof);
    transaction.set_commitments(malicious_commitments.clone());
    assert!(transaction.verify().is_err());

    transaction.set_r1cs(malicious_proof);
    transaction.set_commitments(malicious_commitments);
    assert!(transaction.verify().is_err());

    // The fee should be the difference between the input and output
    assert_eq!(3, transaction.fee().value());
}

#[test]
fn transactions_with_transparent_notes() {
    let mut db = Db::new().unwrap();

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
        &mut db, pk, 100,
    ));
    let idx = &notes[0].2;
    let note: TransparentNote = db.fetch_note(idx).unwrap().try_into().unwrap();
    let vk = &senders[0].1;
    assert!(note.is_owned_by(vk));

    // Assert the new unspent note is not nullified
    let sk = &senders[0].0;
    let idx = &notes[0].2;
    let note: TransparentNote = db.fetch_note(idx).unwrap().try_into().unwrap();
    let nullifier = note.generate_nullifier(sk);
    assert!(db.fetch_nullifier(&nullifier).unwrap().is_none());

    let mut transaction = Transaction::default();

    // Set the first unspent note as the input of the transaction
    let sk = senders[0].0;
    let idx = &notes[0].2;
    let note: TransparentNote = db.fetch_note(idx).unwrap().try_into().unwrap();
    transaction.push(note.to_transaction_input(sk));

    // Set the fee cost
    miner_keys.push(generate_keys());
    let fee_cost = transaction.fee().note().value(None);

    // Create two output notes for the transaction
    let pk = &receivers[0].2;
    outputs.push(create_output_note::<TransparentNote>(pk, 25));
    let pk = &receivers[1].2;
    outputs.push(create_output_note::<TransparentNote>(pk, 50 - fee_cost));
    let note: TransparentNote = outputs[0].2.clone().try_into().unwrap();
    let blinding_factor = outputs[0].3;
    let pk = outputs[0].0;
    let value = outputs[0].1;
    transaction.push(note.to_transaction_output(value, blinding_factor, pk));
    let note: TransparentNote = outputs[1].2.clone().try_into().unwrap();
    let blinding_factor = outputs[1].3;
    let pk = outputs[1].0;
    let value = outputs[1].1;
    transaction.push(note.to_transaction_output(value, blinding_factor, pk));

    // Execute the transaction
    transaction.prove().unwrap();
    let unspent_outputs = db.store(&transaction).unwrap();

    // Assert the spent note is nullified
    let sk = &senders[0].0;
    let idx = &notes[0].2;
    let note: TransparentNote = db.fetch_note(idx).unwrap().try_into().unwrap();
    let nullifier = note.generate_nullifier(sk);
    assert!(db.fetch_nullifier(&nullifier).unwrap().is_some());

    // Assert the outputs are not nullified
    unspent_outputs.iter().for_each(|idx| {
        let note: TransparentNote = db.fetch_note(idx).unwrap().try_into().unwrap();
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

#[test]
fn rpc_transaction() {
    let mut db = Db::new().unwrap();

    let mut senders = vec![];
    let mut receivers = vec![];

    // Setup senders
    senders.push(generate_keys());
    senders.push(generate_keys());

    // Setup receivers
    receivers.push(generate_keys());
    receivers.push(generate_keys());

    let mut inputs = vec![];
    let mut outputs = vec![];

    // Store an unspent note of 100
    let sk = senders[0].0;
    inputs.push(create_and_store_unspent_rpc_note::<TransparentNote>(
        &mut db, sk, 100,
    ));

    // Store an unspent note of 50
    let sk = senders[1].0;
    inputs.push(create_and_store_unspent_rpc_note::<TransparentNote>(
        &mut db, sk, 50,
    ));

    // Create an output of 97
    let pk = &receivers[0].2;
    outputs.push(create_output_rpc_note::<TransparentNote>(pk, 97));

    // Create an output of 50
    let pk = &receivers[1].2;
    outputs.push(create_output_rpc_note::<ObfuscatedNote>(pk, 50));

    let mut transaction = rpc::Transaction::default();

    inputs
        .into_iter()
        .for_each(|input| transaction.inputs.push(input));

    outputs
        .into_iter()
        .for_each(|output| transaction.outputs.push(output));

    let mut transaction = Transaction::try_from_rpc_transaction(&db, transaction).unwrap();

    // It is not possible to verify an unproven transaction
    assert!(transaction.verify().is_err());

    transaction.prove().unwrap();
    transaction.verify().unwrap();

    assert_eq!(3, transaction.fee().value());

    let proof = transaction.r1cs().cloned().unwrap();
    let commitments = transaction.commitments().clone();

    let transaction: rpc::Transaction = transaction.into();
    let mut transaction = Transaction::try_from_rpc_transaction(&db, transaction).unwrap();

    let deserialized_proof = transaction.r1cs().cloned().unwrap();
    let deserialized_commitments = transaction.commitments().clone();

    assert!(!commitments.is_empty());
    assert_eq!(commitments, deserialized_commitments);
    assert_eq!(proof.to_bytes(), deserialized_proof.to_bytes());

    transaction.verify().unwrap();

    assert_eq!(3, transaction.fee().value());
}

fn generate_keys() -> (SecretKey, ViewKey, PublicKey) {
    let sk = SecretKey::default();
    let vk = sk.view_key();
    let pk = sk.public_key();

    (sk, vk, pk)
}

fn create_and_store_unspent_note<N: Note + NoteGenerator>(
    db: &mut Db,
    pk: &PublicKey,
    value: u64,
) -> (PublicKey, u64, Idx, NoteVariant, Scalar) {
    let (note, blinding_factor) = N::output(pk, value);

    let idx = db.store_unspent_note(note.into()).unwrap();
    let note = db.fetch_note(&idx).unwrap();

    (pk.clone(), value, idx, note, blinding_factor)
}

fn create_output_note<N: Note + NoteGenerator>(
    pk: &PublicKey,
    value: u64,
) -> (PublicKey, u64, NoteVariant, Scalar) {
    let (note, blinding_factor) = N::output(pk, value);

    (pk.clone(), value, note.into(), blinding_factor)
}

fn create_and_store_unspent_rpc_note<N: Clone + Note + NoteGenerator>(
    db: &mut Db,
    sk: SecretKey,
    value: u64,
) -> rpc::TransactionInput {
    let pk = sk.public_key();
    let idx = db
        .store_unspent_note(N::output(&pk, value).0.into())
        .unwrap();
    let pos = Some(idx);
    let sk = Some(sk.into());

    rpc::TransactionInput { pos, sk }
}

fn create_output_rpc_note<N: Note + NoteGenerator>(
    pk: &PublicKey,
    value: u64,
) -> rpc::TransactionOutput {
    let (note, blinding_factor) = N::output(pk, value);
    let note = Some(note.into());
    let blinding_factor = Some(blinding_factor.into());
    let pk = Some((*pk).into());

    rpc::TransactionOutput {
        note,
        pk,
        value,
        blinding_factor,
    }
}
