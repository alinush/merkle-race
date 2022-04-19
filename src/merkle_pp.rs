use crate::merkle::AbstractMerkle;
use crate::merkle_crhf::HASH_LENGTH;
use crate::tree_hasher::TreeHasherFunc;
use more_asserts::assert_le;
use serde::Serialize;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::ops::{AddAssign, SubAssign};
use tiny_keccak::{Hasher, Sha3};

#[derive(Clone)]
pub enum MerkleppHashValue<IncHash> {
    Internal(IncHash),
    Leaf([u8; HASH_LENGTH]),
}

impl<IncHash: Default> Default for MerkleppHashValue<IncHash> {
    fn default() -> Self {
        MerkleppHashValue::Internal(IncHash::default())
    }
}

impl<IncHash: Display> Debug for MerkleppHashValue<IncHash> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MerkleppHashValue::Internal(incr_hash) => write!(f, "{}", incr_hash),
            MerkleppHashValue::Leaf(normal_hash) => write!(f, "{}", hex::encode(normal_hash)),
        }
    }
}

pub struct IncrementalHasher<FastIncHash> {
    num_hashes: usize,
    arity: usize,
    h: PhantomData<FastIncHash>,
}

impl<FastIncHash> IncrementalHasher<FastIncHash> {
    fn new(arity: usize) -> Self {
        IncrementalHasher {
            num_hashes: 0,
            arity,
            h: Default::default(),
        }
    }
}

// NOTE: We store children hashes in memory as IncrHash<CompressedRistretto, _>'s, but we hash them to
// IncrHash<RistrettoPoints, _> since they are faster to add. This is why there are two paramters here
fn hash_child<ChildIncHash, FastIncHash>(
    i: usize,
    child_hash: &MerkleppHashValue<ChildIncHash>,
) -> FastIncHash
where
    ChildIncHash: Serialize,
    for<'a> FastIncHash: From<&'a [u8]>,
{
    match child_hash {
        MerkleppHashValue::Internal(incr_hash) => {
            let mut bytes = bincode::serialize(incr_hash).unwrap();
            assert_eq!(bytes.len(), 32);

            bytes.append(bincode::serialize(&i).unwrap().as_mut());

            FastIncHash::from(bytes.as_slice())
        }
        MerkleppHashValue::Leaf(leaf_hash) => {
            let mut bytes = leaf_hash.to_vec();

            bytes.append(bincode::serialize(&i).unwrap().as_mut());

            FastIncHash::from(bytes.as_slice())
        }
    }
}

impl<IncHash, FastIncHash> TreeHasherFunc<String, MerkleppHashValue<IncHash>>
    for IncrementalHasher<FastIncHash>
where
    IncHash: Default + Clone + Serialize + AddAssign<FastIncHash>,
    for<'a> FastIncHash: Default + AddAssign + SubAssign + From<&'a [u8]>,
{
    fn get_num_computations(&self) -> usize {
        self.num_hashes
    }

    fn is_incremental(&self) -> bool {
        true
    }

    fn hash_leaf_data(&mut self, _offset: usize, data: String) -> MerkleppHashValue<IncHash> {
        let mut hasher = Sha3::v256();

        let mut hash = [0u8; HASH_LENGTH];
        hasher.update("leaf:".as_bytes());
        hasher.update(data.as_bytes());
        hasher.finalize(&mut hash);

        MerkleppHashValue::<IncHash>::Leaf(hash)
    }

    fn hash_nodes(
        &mut self,
        old_parent_hash: MerkleppHashValue<IncHash>,
        old_children: &mut Vec<MerkleppHashValue<IncHash>>,
        new_children: &Vec<(usize, MerkleppHashValue<IncHash>)>,
    ) -> MerkleppHashValue<IncHash> {
        // count the number of children whose hashes have changed
        let num_changes = new_children.len();

        let mut incr_hash = IncHash::default();
        if num_changes > self.arity / 2 {
            // if more than half the siblings changed, just recompute the parent from scratch
            // since otherwise, we'd be computing more than self.arity incremental hashes
            //
            // NOTE(Alin): I guess we would only use this optimization when the Merkle++ tree is in-memory, since
            // we wouldn't want to read unmodified children from disk.
            self.num_hashes += self.arity;

            // replace old hashes with new ones
            for (pos, hash) in new_children {
                old_children[*pos] = hash.clone(); // TODO(Perf): avoid clone?
            }

            // recompute parent's incremental hash from scratch
            // NOTE: We use an intermediate FastIncHash representation for the incremental hashes
            // to speed up their addition.
            let mut acc = FastIncHash::default();
            for i in 0..old_children.len() {
                acc += hash_child::<IncHash, FastIncHash>(i, &old_children[i]);
            }
            incr_hash += acc;
        } else {
            // if less than half the siblings changed, incrementally update the parent
            incr_hash = match old_parent_hash {
                MerkleppHashValue::<IncHash>::Internal(hash) => hash,
                _ => unreachable!(),
            };

            // incrementally update parent hash
            let mut num_hashes = 0;
            let mut acc = FastIncHash::default();

            for (pos, hash) in new_children {
                num_hashes += 2;
                acc -= hash_child::<IncHash, FastIncHash>(*pos, &old_children[*pos]);
                acc += hash_child::<IncHash, FastIncHash>(*pos, hash);
            }

            incr_hash += acc;

            self.num_hashes += num_hashes;
            assert_le!(num_hashes, self.arity);
        }

        MerkleppHashValue::<IncHash>::Internal(incr_hash)
    }
}

pub fn new_merklepp_from_height<IncHash, FastIncHash>(
    arity: usize,
    height: usize,
) -> AbstractMerkle<String, MerkleppHashValue<IncHash>, IncrementalHasher<FastIncHash>>
where
    IncHash: Clone + Default + Serialize + AddAssign<FastIncHash>,
    for<'a> FastIncHash: Default + AddAssign + SubAssign + From<&'a [u8]>,
{
    let hasher = IncrementalHasher::new(arity);

    AbstractMerkle::new(arity, height, hasher)
}


pub fn new_merklepp_from_leaves<IncHash, FastIncHash>(
    arity: usize,
    num_leaves: usize,
) -> AbstractMerkle<String, MerkleppHashValue<IncHash>, IncrementalHasher<FastIncHash>>
where
    IncHash: Clone + Default + Serialize + AddAssign<FastIncHash>,
    for<'a> FastIncHash: Default + AddAssign + SubAssign + From<&'a [u8]>,
{
    let hasher = IncrementalHasher::new(arity);

    AbstractMerkle::with_num_leaves(arity, num_leaves, hasher)
}