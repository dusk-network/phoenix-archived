use std::convert::TryFrom;

use phoenix_lib::{
    rpc, rpc::phoenix_server::Phoenix, Db, NoteGenerator, ObfuscatedNote, PublicKey, SecretKey,
    Transaction, TransactionItem, TransparentNote,
};
use phoenix_server::PhoenixServer;
use tokio::runtime::{Builder, Runtime};
use tonic::IntoRequest;

#[test]
fn test_rust_cli_tx_prove() {
    let db = Db::new().unwrap();

    let dusk_sk = SecretKey::from(b"dusk".to_vec());
    let dusk_pk = dusk_sk.public_key();

    let alice_sk = SecretKey::default();
    let alice_pk = alice_sk.public_key();

    let bob_sk = SecretKey::default();
    let bob_pk = bob_sk.public_key();

    let note = ObfuscatedNote::output(&dusk_pk, 1000).0;
    let note = Box::new(note);

    db.store_unspent_note(note).unwrap();

    let server = PhoenixServer::new(db);
    let mut rt = Builder::new().basic_scheduler().build().unwrap();
    let mut tx = Transaction::default();

    let inputs = query_inputs(&server, &mut rt, dusk_sk);

    assert_eq!(1, inputs.len());
    tx.push(inputs[0].clone());

    let bob_value = 300;
    let (note, blinding_factor) = ObfuscatedNote::output(&bob_pk, bob_value);
    let output = note.to_transaction_output(bob_value, blinding_factor, bob_pk);
    tx.push(output);

    let alice_value = 600;
    let (note, blinding_factor) = TransparentNote::output(&alice_pk, alice_value);
    let output = note.to_transaction_output(alice_value, blinding_factor, alice_pk);
    tx.push(output);

    let dusk_value = 95;
    let (note, blinding_factor) = ObfuscatedNote::output(&dusk_pk, dusk_value);
    let output = note.to_transaction_output(dusk_value, blinding_factor, dusk_pk);
    tx.push(output);

    let fee_pk = PublicKey::default();
    let fee_value = 5;
    let (note, blinding_factor) = TransparentNote::output(&fee_pk, fee_value);
    let output = note.to_transaction_output(fee_value, blinding_factor, fee_pk);
    tx.set_fee(output);

    tx.prove().unwrap();
    tx.verify().unwrap();

    let transactions = vec![tx.into()];
    let request = rpc::StoreTransactionsRequest { transactions };
    rt.block_on(server.store_transactions(request.into_request()))
        .unwrap()
        .into_inner()
        .notes;

    let dusk_inputs = query_inputs(&server, &mut rt, dusk_sk);
    let bob_inputs = query_inputs(&server, &mut rt, bob_sk);
    let alice_inputs = query_inputs(&server, &mut rt, alice_sk);

    assert_eq!(1, dusk_inputs.len());
    assert_eq!(1, bob_inputs.len());
    assert_eq!(1, alice_inputs.len());

    assert_eq!(dusk_value, dusk_inputs[0].value());
    assert_eq!(bob_value, bob_inputs[0].value());
    assert_eq!(alice_value, alice_inputs[0].value());
}

fn query_inputs(server: &PhoenixServer, rt: &mut Runtime, sk: SecretKey) -> Vec<TransactionItem> {
    let vk = sk.view_key();
    let vk = rpc::ViewKey::from(vk);

    rt.block_on(server.full_scan_owned_notes(vk.into_request()))
        .unwrap()
        .into_inner()
        .notes
        .into_iter()
        .filter_map(|note| {
            let note_type = rpc::NoteType::try_from(note.note_type).unwrap();

            let txin = match note_type {
                rpc::NoteType::Transparent => TransparentNote::try_from(note)
                    .unwrap()
                    .to_transaction_input(sk),
                rpc::NoteType::Obfuscated => ObfuscatedNote::try_from(note)
                    .unwrap()
                    .to_transaction_input(sk),
            };
            let nullifier = txin.nullifier().clone();

            let nullifier = rpc::NullifierStatusRequest {
                nullifier: Some(nullifier.into()),
            };
            let status = rt
                .block_on(server.nullifier_status(nullifier.into_request()))
                .unwrap()
                .into_inner();

            if status.unspent {
                Some(txin)
            } else {
                None
            }
        })
        .collect()
}
