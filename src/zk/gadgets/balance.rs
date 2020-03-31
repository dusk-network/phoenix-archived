use crate::{zk, BlsScalar};

use hades252::strategies::GadgetStrategy;
use num_traits::{One, Zero};

macro_rules! value_commitment_preimage {
    (
        $item:ident,
        $composer:ident,
        $perm:ident,
        $zero_perm:ident,
        $bitflags:ident,
        $pi:ident,
        $zero:ident,
        $acc:ident
    ) => {
        $perm.copy_from_slice(&$zero_perm);
        $perm[0] = $bitflags;
        $perm[1] = $item.value;
        $perm[2] = $item.blinding_factor;

        let (p_composer, p_pi, c) = GadgetStrategy::poseidon_gadget($composer, $pi, &mut $perm);

        $composer = p_composer;
        $pi = p_pi;

        $pi.next().map(|p| *p = BlsScalar::zero());
        $composer.add_gate(
            $item.value_commitment,
            c,
            $zero,
            -BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );

        $pi.next().map(|p| *p = BlsScalar::zero());
        $acc = $composer.add(
            $acc,
            $item.value,
            BlsScalar::one(),
            BlsScalar::one(),
            -BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
    };
}

/// Perform the pre-image of the value commitment and check if the inputs equals the outputs + fee
pub fn balance<'a, P>(
    mut composer: zk::Composer,
    tx: &zk::ZkTransaction,
    mut pi: P,
) -> (zk::Composer, P)
where
    P: Iterator<Item = &'a mut BlsScalar>,
{
    let zero = composer.add_input(BlsScalar::zero());
    let bitflags = composer.add_input(BlsScalar::from(3u8));
    let zero_perm = [zero; hades252::WIDTH];
    let mut perm = [zero; hades252::WIDTH];

    let mut inputs = zero;
    let mut outputs = zero;

    for item in tx.inputs.iter() {
        value_commitment_preimage!(item, composer, perm, zero_perm, bitflags, pi, zero, inputs);
    }

    let fee = tx.fee;
    value_commitment_preimage!(fee, composer, perm, zero_perm, bitflags, pi, zero, outputs);

    for item in tx.outputs.iter() {
        value_commitment_preimage!(item, composer, perm, zero_perm, bitflags, pi, zero, outputs);
    }

    pi.next().map(|p| *p = BlsScalar::zero());
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

    (composer, pi)
}

#[cfg(test)]
mod tests {
    use crate::{utils, zk, NoteGenerator, SecretKey, Transaction, TransparentNote};

    #[test]
    fn tx_balance() {
        utils::init();
        zk::init();

        let mut tx = Transaction::default();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 28;
        let note = TransparentNote::output(&pk, value).0;
        tx.push_input(note.to_transaction_input(sk)).unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 33;
        let note = TransparentNote::output(&pk, value).0;
        tx.push_input(note.to_transaction_input(sk)).unwrap();

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
        tx.verify().unwrap();
    }

    #[test]
    fn tx_balance_invalid() {
        utils::init();
        zk::init();

        let mut tx = Transaction::default();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 26;
        let note = TransparentNote::output(&pk, value).0;
        tx.push_input(note.to_transaction_input(sk)).unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 33;
        let note = TransparentNote::output(&pk, value).0;
        tx.push_input(note.to_transaction_input(sk)).unwrap();

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
