use crate::{
    rpc, Db, Note, NoteGenerator, ObfuscatedNote, PublicKey, SecretKey, TransparentNote, ViewKey,
};

#[test]
fn transaction_from_rpc() {
    let db = Db::new().unwrap();

    let mut inputs = vec![];
    let mut outputs = vec![];
    let mut senders = vec![];
    let mut receivers = vec![];

    // Setup senders
    senders.push(generate_keys());
    senders.push(generate_keys());

    // Setup receivers
    receivers.push(generate_keys());
    receivers.push(generate_keys());

    // Store an unspent note of 100
    let sk = senders[0].0;
    inputs.push(create_and_store_unspent_note::<TransparentNote>(
        &db, sk, 100,
    ));

    // Store an unspent note of 50
    let sk = senders[1].0;
    inputs.push(create_and_store_unspent_note::<TransparentNote>(
        &db, sk, 50,
    ));

    // Create an output of 100
    let pk = &receivers[0].2;
    outputs.push(create_output_note::<TransparentNote>(pk, 100));

    // Create an output of 47
    let pk = &receivers[1].2;
    outputs.push(create_output_note::<ObfuscatedNote>(pk, 47));

    let mut transaction = rpc::Transaction::default();

    inputs
        .into_iter()
        .for_each(|input| transaction.push_input(input));

    outputs
        .into_iter()
        .for_each(|output| transaction.push_output(output));

    let mut transaction = transaction.to_transaction(&db).unwrap();

    let (proof, commitments) = transaction.prove().unwrap();
    transaction.verify(&proof, &commitments).unwrap();

    assert_eq!(3, transaction.fee().value());
}

fn generate_keys() -> (SecretKey, ViewKey, PublicKey) {
    let sk = SecretKey::default();
    let vk = sk.view_key();
    let pk = sk.public_key();

    (sk, vk, pk)
}

fn create_and_store_unspent_note<N: Clone + Note + NoteGenerator>(
    db: &Db,
    sk: SecretKey,
    value: u64,
) -> rpc::TransactionInput {
    let pk = sk.public_key();
    let idx = db
        .store_unspent_note(N::output(&pk, value).0.box_clone())
        .unwrap();

    rpc::TransactionInput::new(idx.into(), sk.into())
}

fn create_output_note<N: Note + NoteGenerator>(
    pk: &PublicKey,
    value: u64,
) -> rpc::TransactionOutput {
    rpc::TransactionOutput::new(N::output(pk, value).0.note().into(), (*pk).into(), value)
}
