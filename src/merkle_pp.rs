use crate::merkle_abstract::AbstractMerkle;
use crate::merkle_crhf::HASH_LENGTH;
use crate::tree_hasher::TreeHasherFunc;
use more_asserts::assert_le;
use rust_incrhash::RistBlakeIncHash;
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::mem::size_of;
use tiny_keccak::{Hasher, Sha3};

#[derive(Clone)]
pub enum MerkleppHashValue {
    Internal(RistBlakeIncHash),
    Leaf([u8; HASH_LENGTH]),
}

impl Default for MerkleppHashValue {
    fn default() -> Self {
        MerkleppHashValue::Internal(RistBlakeIncHash::default())
    }
}

impl Debug for MerkleppHashValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MerkleppHashValue::Internal(incr_hash) => write!(f, "{}", incr_hash),
            MerkleppHashValue::Leaf(normal_hash) => write!(f, "{}", hex::encode(normal_hash)),
        }
    }
}

pub struct IncrementalHasher {
    num_hashes: usize,
    arity: usize,
}

impl IncrementalHasher {
    fn new(arity: usize) -> Self {
        IncrementalHasher {
            num_hashes: 0,
            arity,
        }
    }
}

impl TreeHasherFunc<String, MerkleppHashValue> for IncrementalHasher {
    fn get_num_computations(&self) -> usize {
        self.num_hashes
    }

    fn is_incremental(&self) -> bool {
        true
    }

    fn hash_leaf_data(&mut self, _offset: usize, data: String) -> MerkleppHashValue {
        let mut hasher = Sha3::v256();

        let mut hash = [0u8; HASH_LENGTH];
        hasher.update("leaf:".as_bytes());
        hasher.update(data.as_bytes());
        hasher.finalize(&mut hash);

        MerkleppHashValue::Leaf(hash)
    }

    fn hash_nodes(
        &mut self,
        old_parent_hash: MerkleppHashValue,
        mut old_children: Vec<MerkleppHashValue>,
        new_children: &BTreeMap<usize, MerkleppHashValue>,
    ) -> MerkleppHashValue {
        // count the number of children whose hashes have changed
        let num_changes = new_children.len();

        let hash_child = |i: usize, child_hash: &MerkleppHashValue| -> RistBlakeIncHash {
            match child_hash {
                MerkleppHashValue::Internal(incr_hash) => {
                    let mut bytes = bincode::serialize(incr_hash).unwrap();
                    assert_eq!(bytes.len(), 32);

                    bytes.append(bincode::serialize(&i).unwrap().as_mut());

                    RistBlakeIncHash::from(bytes.as_slice())
                }
                MerkleppHashValue::Leaf(leaf_hash) => {
                    let mut bytes = leaf_hash.to_vec();

                    bytes.append(bincode::serialize(&i).unwrap().as_mut());

                    RistBlakeIncHash::from(bytes.as_slice())
                }
            }
        };

        let mut incr_hash = RistBlakeIncHash::default();
        if num_changes > self.arity / 2 {
            // if more than half the siblings changed, just recompute the parent from scratch
            // since otherwise, we'd be computing more than self.arity incremental hashes
            //
            // NOTE(Alin): I guess we would only use this optimization when the Merkle++ tree is in-memory, since
            // we wouldn't want to read unmodified children from disk.
            self.num_hashes += self.arity;

            // replace old hashes with new ones
            for (pos, hash) in new_children {
                old_children[*pos] = hash.clone();
            }

            // recompute parent's incremental hash from scratch
            for i in 0..old_children.len() {
                incr_hash += hash_child(i, &old_children[i]);
            }
        } else {
            // if less than half the siblings changed, incrementally update the parent
            incr_hash = match old_parent_hash {
                MerkleppHashValue::Internal(hash) => hash,
                _ => unreachable!(),
            };

            // incrementally update parent hash
            let mut num_hashes = 0;
            for (pos, hash) in new_children {
                num_hashes += 2;

                incr_hash -= hash_child(*pos, &old_children[*pos]);
                incr_hash += hash_child(*pos, hash);
            }

            self.num_hashes += num_hashes;
            assert_le!(num_hashes, self.arity);
        }

        MerkleppHashValue::Internal(incr_hash)
    }
}

pub fn new_merklepp_rist(
    k: usize,
    h: usize,
) -> AbstractMerkle<String, MerkleppHashValue, IncrementalHasher> {
    let hasher = IncrementalHasher::new(k);

    println!("Merkle++ node is {} bytes", size_of::<MerkleppHashValue>());

    AbstractMerkle::new(k, h, hasher)
}
