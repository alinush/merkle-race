use crate::merkle::AbstractMerkle;
use crate::tree_hasher::TreeHasherFunc;
use more_asserts::assert_le;
use std::fmt::{Debug, Formatter};
use tiny_keccak::{Hasher, Sha3};

pub const HASH_LENGTH: usize = 32;

#[derive(Default, Clone)]
pub struct MerkleHashValue {
    hash: [u8; HASH_LENGTH],
}

impl Debug for MerkleHashValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.hash))
    }
}

pub struct HasherSha3 {
    num_hashes: usize,
    arity: usize,
}

impl HasherSha3 {
    fn new(arity: usize) -> Self {
        HasherSha3 {
            num_hashes: 0,
            arity,
        }
    }
}

impl TreeHasherFunc<String, MerkleHashValue> for HasherSha3 {
    fn get_num_computations(&self) -> usize {
        self.num_hashes
    }

    fn is_incremental(&self) -> bool {
        false
    }

    fn hash_leaf_data(&mut self, _offset: usize, data: String) -> MerkleHashValue {
        self.num_hashes += 1;

        let mut hasher = Sha3::v256();
        hasher.update("leaf:".as_bytes());
        //hasher.update( offset.to_string().as_bytes());
        //hasher.update( ":".as_bytes());
        hasher.update(data.as_bytes());

        let mut hv = MerkleHashValue::default();
        hasher.finalize(&mut hv.hash);
        hv
    }

    fn hash_nodes(
        &mut self,
        _old_parent_hash: MerkleHashValue,
        old_children: &mut Vec<MerkleHashValue>,
        new_children: &Vec<(usize, MerkleHashValue)>,
    ) -> MerkleHashValue {
        self.num_hashes += 1;

        assert_le!(old_children.len(), self.arity);

        let mut hasher = Sha3::v256();
        hasher.update(("internal:").as_bytes());

        // replace old hashes with new ones
        for (pos, hash) in new_children {
            old_children[*pos] = hash.clone(); // TODO(Perf): avoid clone?
        }

        for h in old_children {
            hasher.update(&h.hash[..]);
        }

        let mut hv = MerkleHashValue::default();
        hasher.finalize(&mut hv.hash);
        hv
    }
}

pub fn new_merkle_sha3_256_from_height(
    arity: usize,
    height: usize,
) -> AbstractMerkle<String, MerkleHashValue, HasherSha3> {
    let hasher = HasherSha3::new(arity);

    AbstractMerkle::new(arity, height, hasher)
}

pub fn new_merkle_sha3_256_from_leaves(
    arity: usize,
    num_leaves: usize,
) -> AbstractMerkle<String, MerkleHashValue, HasherSha3> {
    let hasher = HasherSha3::new(arity);

    AbstractMerkle::with_num_leaves(arity, num_leaves, hasher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{max_leaves, random_updates};

    #[test]
    fn bvt_arity_2_examples() {
        let mut merkle = new_merkle_sha3_256_from_leaves(2, 3);
        let updates = vec![
            (0usize, "lol".to_owned()),
            (1usize, "ha".to_owned()),
            (2usize, "bla".to_owned()),
        ];
        merkle.update_leaves(updates);

        let mut merkle = new_merkle_sha3_256_from_leaves(2, 10);
        let updates = vec![
            (0usize, "lol".to_owned()),
            (1usize, "ha".to_owned()),
            (2usize, "bla".to_owned()),
            (8usize, "la".to_owned()),
        ];
        merkle.update_leaves(updates);
    }

    fn test_with_random_updates(num_leaves: usize, merkle: &mut AbstractMerkle<String, MerkleHashValue, HasherSha3>) {
        for num_updates in [1, num_leaves / 3, num_leaves / 2, num_leaves] {
            if num_updates == 0 {
                continue;
            }

            println!();
            let updates = random_updates(num_leaves, num_updates);
            merkle.update_leaves(updates);
        }
    }

    #[test]
    fn bvt_perfect() {
        for arity in [ 2, 4, 8, 16 ] {
            for height in [1, 2, 3, 4] {
                let num_leaves = max_leaves(arity, height);
                let mut merkle = new_merkle_sha3_256_from_leaves(arity, num_leaves);

                test_with_random_updates(num_leaves, &mut merkle)
            }
        }
    }

    #[test]
    fn bvt_imperfect() {
        // e.g., tree with 3 leaves
        //        *
        //      /   \
        //     /     \
        //    *       *
        //   / \     /
        //  1   2   3

        // e.g., tree with 10 leaves
        //                     - - - - [.] - - - -
        //                   /                     \
        //                  /                       \
        //                 /                         \
        //                /                           \
        //              (*)                           (*)
        //            /     \                       /     \
        //           /       \                     /       \
        //          /         \                   /         \
        //         /           \                 /           \
        //       ()             ()             ()             ()
        //      /  \           /  \           /  \           /  \
        //     /    \         /    \         /    \         /    \
        //    *      *       1      2       3     4        5      6
        //   / \    / \
        //  7   8  9   10

        // TODO: Should have these tests for any Merkle tree in tests/
        for arity in [ 2, 4, 8, 16 ] { // {, 32, 64, 128 ] {
            //let arity = 2;
            for num_leaves in 2..=256 {
                println!("Testing arity {} with {} leaves", arity, num_leaves);
                let mut merkle = new_merkle_sha3_256_from_leaves(arity, num_leaves);

                test_with_random_updates(num_leaves, &mut merkle);
            }
        }
    }

    #[test]
    fn bvt_arity_16_imperfect() {
        // TODO: Should have these tests for any Merkle tree in tests/
        let arity = 16;
        for num_leaves in 16..=128 {
            println!("Testing arity {} with {} leaves", arity, num_leaves);
            let mut merkle = new_merkle_sha3_256_from_leaves(arity, num_leaves);

            //assert!(merkle._hashed_nodes.is_empty());
            test_with_random_updates(num_leaves, &mut merkle);
        }
    }


    #[test]
    fn bvt_arity_16_examples() {
        let mut merkle = new_merkle_sha3_256_from_height(16, 3);
        let updates = vec![
            (0usize, "lol".to_owned()),
            (1usize, "ha".to_owned()),
            (2usize, "bla".to_owned()),
            (16usize, "la".to_owned()),
            (19usize, "nah".to_owned()),
            (1023usize, "rer".to_owned()),
            (1024usize, "last".to_owned()),
            (1026usize, "asdsd".to_owned()),
        ];
        merkle.update_leaves(updates);

        let mut merkle = new_merkle_sha3_256_from_leaves(16, 600);
        let updates = vec![
            (0usize, "lol".to_owned()),
            (1usize, "ha".to_owned()),
            (2usize, "bla".to_owned()),
            (16usize, "la".to_owned()),
            (19usize, "nah".to_owned()),
            (523usize, "rer".to_owned()),
            (524usize, "last".to_owned()),
            (526usize, "asdsd".to_owned()),
        ];
        merkle.update_leaves(updates);
    }
}
