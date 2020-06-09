use crate::{Note, TransactionInput, TransactionItem};

use dusk_plonk::constraint_system::StandardComposer;
use poseidon252::merkle_proof::{merkle_opening_gadget, PoseidonBranch};
use rand::Rng;

/// Verify the merkle opening
pub fn merkle(composer: &mut StandardComposer, branch: PoseidonBranch, input: &TransactionInput) {
    let leaf = composer.add_input(input.note().hash());
    let root = branch.root;
    merkle_opening_gadget(composer, branch, leaf, root);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, BlsScalar, NoteGenerator, SecretKey, TransparentNote};
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::fft::EvaluationDomain;
    use kelvin::Blake2b;
    use merlin::Transcript;
    use poseidon252::PoseidonTree;
    use poseidon252::StorageScalar;

    #[test]
    fn merkle_gadget() {
        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 100;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        let input = note.to_transaction_input(merkle_opening, sk);

        // Generate a tree with random scalars inside.
        // However, we set our nullifier on a specific index.
        let index = rand::thread_rng().gen_range(0, 1024);
        let mut ptree: PoseidonTree<_, Blake2b> = PoseidonTree::new(17);
        for i in 0..1024u64 {
            if i == index {
                ptree.push(StorageScalar(input.note().hash())).unwrap();
                continue;
            }
            ptree
                .push(StorageScalar(BlsScalar::from(i as u64)))
                .unwrap();
        }

        // Our branch will be on 567
        let branch = ptree.poseidon_branch(index).unwrap().unwrap();

        let mut composer = StandardComposer::new();
        merkle(&mut composer, branch, &input);
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
