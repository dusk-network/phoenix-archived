use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use phoenix::{
    utils, zk, Transaction, MAX_INPUT_NOTES_PER_TRANSACTION, MAX_OUTPUT_NOTES_PER_TRANSACTION,
};
use rand::distributions::Standard;
use rand::seq::SliceRandom;
use rand::Rng;

fn prove_random(txs: &[Transaction]) {
    let mut tx = txs.choose(&mut rand::thread_rng()).cloned().unwrap();

    tx.prove().unwrap();
}

fn verify_random(proved_txs: &[Transaction]) {
    let tx = proved_txs.choose(&mut rand::thread_rng()).cloned().unwrap();

    tx.verify().unwrap();
}

fn benchmark_phoenix(c: &mut Criterion) {
    utils::init();
    zk::init();

    let rng = rand::thread_rng();
    let txs: Vec<Transaction> = rng.sample_iter(Standard).take(5).collect();
    let proved_txs: Vec<Transaction> = rng
        .sample_iter(Standard)
        .take(5)
        .map(|mut tx: Transaction| {
            tx.prove().unwrap();
            tx
        })
        .collect();

    c.bench_function(
        format!(
            "Verification time, capacity {}, max inputs {}, max outputs {}",
            zk::CAPACITY,
            MAX_INPUT_NOTES_PER_TRANSACTION,
            MAX_OUTPUT_NOTES_PER_TRANSACTION
        )
        .as_str(),
        |b| b.iter(|| verify_random(proved_txs.as_slice())),
    );

    c.bench_function(
        format!(
            "Proving time, capacity {}, max inputs {}, max outputs {}",
            zk::CAPACITY,
            MAX_INPUT_NOTES_PER_TRANSACTION,
            MAX_OUTPUT_NOTES_PER_TRANSACTION
        )
        .as_str(),
        |b| b.iter(|| prove_random(txs.as_slice())),
    );
}

criterion_group! {
    name = phoenix_group;

    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(20));

    targets = benchmark_phoenix
}
criterion_main!(phoenix_group);
