use crate::{zk, BlsScalar, Note, NoteVariant, TransactionInput, TransactionItem, ViewKey};

use dusk_plonk::constraint_system::StandardComposer;

/// Prove knowledge of the sum of a set of [`TransactionItem`].
pub fn sum<T>(composer: &mut StandardComposer, items: Vec<T>)
where
    T: TransactionItem,
{
    let mut sum = 0;
    for item in items.iter() {
        let value = composer.add_input(BlsScalar::from(item.value()));
        let old_sum = composer.add_input(BlsScalar::from(sum));
        sum += item.value();
        let new_sum = composer.add_input(BlsScalar::from(sum));
        composer.add_gate(
            old_sum,
            value,
            new_sum,
            BlsScalar::one(),
            BlsScalar::one(),
            -BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
    }

    let sum_scalar = BlsScalar::from(sum);
    let sum_var = composer.add_input(sum_scalar);
    composer.constrain_to_constant(sum_var, sum_scalar, BlsScalar::zero());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, utils, zk, Note, NoteGenerator, SecretKey, Transaction, TransparentNote};

    #[test]
    fn sum_gadget() {
        let mut inputs = vec![];

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 100;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        let input = note.to_transaction_input(merkle_opening, sk);
        inputs.push(input);

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 100;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        let input = note.to_transaction_input(merkle_opening, sk);
        inputs.push(input);

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 100;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        let input = note.to_transaction_input(merkle_opening, sk);
        inputs.push(input);

        let mut composer = dusk_plonk::constraint_system::StandardComposer::new();

        sum(&mut composer, inputs);
        composer.add_dummy_constraints();
        use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
        use dusk_plonk::fft::EvaluationDomain;
        use merlin::Transcript;

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

        assert!(proof.verify(&circuit, &mut transcript, &vk, &[BlsScalar::zero()]));
    }
}
