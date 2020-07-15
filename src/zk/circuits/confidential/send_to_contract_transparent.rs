use crate::{
    db, zk::gadgets, BlsScalar, NoteVariant, Transaction, TransactionItem, TransactionOutput,
};

use dusk_plonk::constraint_system::StandardComposer;
use kelvin::Blake2b;

/// This gadget constructs the circuit for a "Send To Contract Transparent" transaction.
pub fn send_to_contract_transparent_gadget(
    composer: &mut StandardComposer,
    crossover: &TransactionOutput,
    contract_output: &TransactionOutput,
) {
    // Crossover
    gadgets::commitment(composer, crossover);
    gadgets::range(composer, crossover);

    // Crossover.value - contract_output.value = 0
    let mut sum = composer.zero_var;
    let value = composer.add_input(BlsScalar::from(crossover.value()));
    sum = composer.add(
        (BlsScalar::one(), sum),
        (BlsScalar::one(), value),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    sum = composer.add(
        (-BlsScalar::one(), sum),
        (BlsScalar::one(), composer.zero_var),
        BlsScalar::zero(),
        BlsScalar::from(contract_output.value()),
    );

    composer.constrain_to_constant(sum, BlsScalar::zero(), BlsScalar::zero());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, Note, NoteGenerator, SecretKey, Transaction, TransparentNote};
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::fft::EvaluationDomain;
    use merlin::Transcript;

    #[test]
    fn test_send_to_contract_transparent() {
        let mut tx = Transaction::default();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 100;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        tx.push_input(note.to_transaction_input(merkle_opening, sk).unwrap())
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 95;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.set_contract_output(note.to_transaction_output(value, blinding_factor, pk));

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 95;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.set_crossover(note.to_transaction_output(value, blinding_factor, pk));

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 2;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 3;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.set_fee(note.to_transaction_output(value, blinding_factor, pk));

        let mut composer = StandardComposer::new();

        send_to_contract_transparent_gadget(
            &mut composer,
            &tx.crossover().unwrap(),
            &tx.contract_output().unwrap(),
        );

        composer.add_dummy_constraints();

        // Generate Composer & Public Parameters
        let pub_params = PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = pub_params.trim(1 << 16).unwrap();
        let mut transcript = Transcript::new(b"TEST");

        let circuit = composer.preprocess(
            &ck,
            &mut transcript,
            &EvaluationDomain::new(composer.circuit_size()).unwrap(),
        );

        let proof = composer.prove(&ck, &circuit, &mut transcript.clone());

        assert!(proof.verify(&circuit, &mut transcript, &vk, &composer.public_inputs()));
    }
}