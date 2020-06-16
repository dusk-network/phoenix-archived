use crate::{zk, BlsScalar};

use poseidon252::sponge::sponge::sponge_hash_gadget;

macro_rules! value_commitment_preimage {
    (
        $item:ident,
        $composer:ident,
        $perm:ident,
        $zero_perm:ident,
        $zero:ident,
        $acc:ident,
        $cc:ident
    ) => {
        $perm.copy_from_slice(&$zero_perm);
        $perm[0] = *$item.value();
        $perm[1] = *$item.blinding_factor();

        let output = sponge_hash_gadget(&mut $composer, &$perm);

        $cc = output;

        $acc = $composer.add(
            (BlsScalar::one(), $acc),
            (BlsScalar::one(), *$item.value()),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
    };
}

/// Perform the pre-image of the value commitment and check if the inputs equals the outputs + fee
pub fn balance(mut composer: zk::Composer, tx: &zk::ZkTransaction) -> zk::Composer {
    let zero = *tx.zero();
    let zero_perm = [zero; hades252::WIDTH];
    let mut perm = [zero; hades252::WIDTH];
    let mut c;

    let mut inputs = zero;
    let mut outputs = zero;

    for item in tx.inputs().iter() {
        value_commitment_preimage!(item, composer, perm, zero_perm, zero, inputs, c);

        composer.add_gate(
            *item.value_commitment(),
            c,
            zero,
            -BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
    }

    let fee = *tx.fee();
    value_commitment_preimage!(fee, composer, perm, zero_perm, zero, outputs, c);

    composer.add_gate(
        c,
        zero,
        zero,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        *fee.value_commitment_scalar(),
    );

    for item in tx.outputs().iter() {
        value_commitment_preimage!(item, composer, perm, zero_perm, zero, outputs, c);

        composer.add_gate(
            c,
            zero,
            zero,
            -BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            *item.value_commitment_scalar(),
        );
    }

    composer.add_gate(
        inputs,
        outputs,
        zero,
        -BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    composer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, utils, zk, Note, NoteGenerator, SecretKey, Transaction, TransparentNote};

    #[test]
    fn balance_gadget() {
        zk::init();

        let mut tx = Transaction::default();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 100;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        tx.push_input(note.to_transaction_input(merkle_opening, sk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 95;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

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

        let mut composer = zk::Composer::new();

        let zk_tx = zk::ZkTransaction::from_tx(&mut composer, &tx);

        let mut composer = balance(composer, &zk_tx);
        let mut transcript = zk::TRANSCRIPT.clone();

        composer.add_dummy_constraints();
        let circuit = composer.preprocess(&zk::CK, &mut transcript, &zk::DOMAIN);

        let proof = composer.prove(&zk::CK, &circuit, &mut transcript);

        assert!(proof.verify(
            &circuit,
            &mut transcript,
            &zk::VK,
            &composer.public_inputs()
        ));
    }

    #[test]
    fn tx_balance_invalid() {
        zk::init();

        let mut tx = Transaction::default();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 60;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        tx.push_input(note.to_transaction_input(merkle_opening, sk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 22;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 24;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 15;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.set_fee(note.to_transaction_output(value, blinding_factor, pk));

        tx.prove().unwrap();
        assert!(tx.verify().is_err());
    }
}
