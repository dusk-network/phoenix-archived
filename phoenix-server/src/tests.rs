use crate::PhoenixServer;

use futures::executor::block_on;
use phoenix_lib::{
    rpc, rpc::phoenix_server::Phoenix, Db, Idx, Note, NoteGenerator, ObfuscatedNote, PublicKey,
    Scalar, SecretKey, Transaction, TransparentNote, ViewKey,
};
use tonic::IntoRequest;

#[test]
fn rpc_transaction() {
    let db = Db::new().unwrap();

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
        &db, sk, 100,
    ));

    // Store an unspent note of 50
    let sk = senders[1].0;
    inputs.push(create_and_store_unspent_rpc_note::<TransparentNote>(
        &db, sk, 50,
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
    let transaction = Transaction::try_from_rpc_transaction(&db, transaction).unwrap();

    let deserialized_proof = transaction.r1cs().cloned().unwrap();
    let deserialized_commitments = transaction.commitments().clone();

    assert!(!commitments.is_empty());
    assert_eq!(commitments, deserialized_commitments);
    assert_eq!(proof.to_bytes(), deserialized_proof.to_bytes());

    transaction.verify().unwrap();

    assert_eq!(3, transaction.fee().value());
}

#[test]
fn rpc_server_transaction_api() {
    let db = Db::new().unwrap();

    let mut unspent = vec![];
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
    unspent.push(create_and_store_unspent_note::<TransparentNote>(
        &db, pk, 100,
    ));

    // Store an unspent note of 50
    let pk = &senders[1].2;
    unspent.push(create_and_store_unspent_note::<ObfuscatedNote>(&db, pk, 50));

    let server = PhoenixServer::new(db);

    let mut inputs = vec![];
    let mut outputs = vec![];

    let pos = unspent[0].2.clone();
    let sk: rpc::SecretKey = senders[0].0.into();
    inputs.push(
        block_on(
            server.new_transaction_input(
                rpc::NewTransactionInputRequest {
                    pos: Some(pos),
                    sk: Some(sk),
                }
                .into_request(),
            ),
        )
        .unwrap()
        .into_inner(),
    );

    let pos = unspent[1].2.clone();
    let sk: rpc::SecretKey = senders[1].0.into();
    inputs.push(
        block_on(
            server.new_transaction_input(
                rpc::NewTransactionInputRequest {
                    pos: Some(pos),
                    sk: Some(sk),
                }
                .into_request(),
            ),
        )
        .unwrap()
        .into_inner(),
    );

    // Create an output of 97
    let pk = receivers[0].2;
    outputs.push(
        block_on(
            server.new_transaction_output(
                rpc::NewTransactionOutputRequest {
                    note_type: rpc::NoteType::Transparent.into(),
                    pk: Some(pk.into()),
                    value: 97,
                }
                .into_request(),
            ),
        )
        .unwrap()
        .into_inner(),
    );

    // Create an output of 30
    let pk = receivers[1].2;
    outputs.push(
        block_on(
            server.new_transaction_output(
                rpc::NewTransactionOutputRequest {
                    note_type: rpc::NoteType::Obfuscated.into(),
                    pk: Some(pk.into()),
                    value: 30,
                }
                .into_request(),
            ),
        )
        .unwrap()
        .into_inner(),
    );

    // Create an output of 20
    let pk = receivers[2].2;
    outputs.push(
        block_on(
            server.new_transaction_output(
                rpc::NewTransactionOutputRequest {
                    note_type: rpc::NoteType::Obfuscated.into(),
                    pk: Some(pk.into()),
                    value: 20,
                }
                .into_request(),
            ),
        )
        .unwrap()
        .into_inner(),
    );

    let transaction = block_on(
        server.new_transaction(
            rpc::NewTransactionRequest {
                inputs: inputs.clone(),
                outputs: outputs.clone(),
                fee: 3,
            }
            .into_request(),
        ),
    )
    .unwrap()
    .into_inner();

    block_on(server.verify_transaction(transaction.into_request())).unwrap();

    // Create an output of 70
    let pk = receivers[2].2;
    outputs.push(
        block_on(
            server.new_transaction_output(
                rpc::NewTransactionOutputRequest {
                    note_type: rpc::NoteType::Obfuscated.into(),
                    pk: Some(pk.into()),
                    value: 70,
                }
                .into_request(),
            ),
        )
        .unwrap()
        .into_inner(),
    );

    // Outputs exceeds inputs, should fail
    assert!(block_on(
        server.new_transaction(
            rpc::NewTransactionRequest {
                inputs,
                outputs,
                fee: 3
            }
            .into_request()
        ),
    )
    .is_err());
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

fn create_and_store_unspent_rpc_note<N: Clone + Note + NoteGenerator>(
    db: &Db,
    sk: SecretKey,
    value: u64,
) -> rpc::TransactionInput {
    let pk = sk.public_key();
    let idx = db
        .store_unspent_note(N::output(&pk, value).0.box_clone())
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
