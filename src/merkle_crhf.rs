use crate::merkle_abstract::AbstractMerkle;
use crate::tree_hasher::TreeHasherFunc;
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::mem::size_of;
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
        mut old_children: Vec<MerkleHashValue>,
        new_children: &BTreeMap<usize, MerkleHashValue>,
    ) -> MerkleHashValue {
        self.num_hashes += 1;

        assert_eq!(old_children.len(), self.arity);

        let mut hasher = Sha3::v256();
        hasher.update(("internal:").as_bytes());

        // replace old hashes with new ones
        for (pos, hash) in new_children {
            old_children[*pos] = hash.clone();
        }

        for h in old_children {
            hasher.update(&h.hash[..]);
        }

        let mut hv = MerkleHashValue::default();
        hasher.finalize(&mut hv.hash);
        hv
    }
}

pub fn new_merkle_sha3_256(
    k: usize,
    h: usize,
) -> AbstractMerkle<String, MerkleHashValue, HasherSha3> {
    let hasher = HasherSha3::new(k);

    println!("Merkle-SHA3 node is {} bytes", size_of::<MerkleHashValue>());
    AbstractMerkle::new(k, h, hasher)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bvt() {
        let mut merkle = new_merkle_sha3_256(2, 10);

        let updates = vec![
            (0usize, "lol".to_owned()),
            (1usize, "ha".to_owned()),
            (2usize, "bla".to_owned()),
            (8usize, "la".to_owned()),
            (9usize, "nah".to_owned()),
            (1023usize, "last".to_owned()),
        ];

        merkle.update_leaves(&updates);
    }
}
