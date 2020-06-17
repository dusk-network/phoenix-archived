use crate::{zk, BlsScalar};

use hades252::strategies::GadgetStrategy;
use hades252::strategies::Strategy;

macro_rules! value_commitment_preimage {
    (
        $item:ident,
        $composer:ident,
        $perm:ident,
        $zero_perm:ident,
        $bitflags:ident,
        $pi:ident,
        $zero:ident,
        $acc:ident,
        $cc:ident
    ) => {
        $perm.copy_from_slice(&$zero_perm);
        $perm[0] = $bitflags;
        $perm[1] = *$item.value();
        $perm[2] = *$item.blinding_factor();

        let mut strat = GadgetStrategy::new(&mut $composer);
        strat.perm(&mut $perm);

        $cc = $perm[1];

        $pi.next().map(|p| *p = BlsScalar::zero());
        $acc = $composer.add(
            (BlsScalar::one(), $acc),
            (BlsScalar::one(), *$item.value()),
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
    let zero = *tx.zero();
    let bitflags = *tx.three();
    let zero_perm = [zero; hades252::WIDTH];
    let mut perm = [zero; hades252::WIDTH];
    let mut c;

    let mut inputs = zero;
    let mut outputs = zero;

    for item in tx.inputs().iter() {
        value_commitment_preimage!(item, composer, perm, zero_perm, bitflags, pi, zero, inputs, c);

        pi.next().map(|p| *p = BlsScalar::zero());
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
    value_commitment_preimage!(fee, composer, perm, zero_perm, bitflags, pi, zero, outputs, c);

    pi.next().map(|p| *p = *fee.value_commitment_scalar());
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
        value_commitment_preimage!(item, composer, perm, zero_perm, bitflags, pi, zero, outputs, c);

        pi.next().map(|p| *p = *item.value_commitment_scalar());
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
    use crate::{crypto, zk, Note, NoteGenerator, SecretKey, Transaction, TransparentNote};

    #[test]
    #[ignore]
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
