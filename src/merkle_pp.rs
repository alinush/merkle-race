use crate::merkle_abstract::AbstractMerkle;
use crate::hashing_traits::{HASH_LENGTH, TreeHasherFunc};
use more_asserts::assert_le;
use serde::Serialize;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::ops::{AddAssign, SubAssign};
use std::time::Instant;
use blake2::{Digest, Blake2b};
use digest::consts::U32;
use digest::generic_array::GenericArray;
use crate::RunningAverage;

#[derive(Clone)]
pub enum MerkleppHashValue<SmallIncHash> {
    Internal(SmallIncHash),
    Leaf([u8; HASH_LENGTH]),
}

impl<SmallIncHash: Default> Default for MerkleppHashValue<SmallIncHash> {
    fn default() -> Self {
        MerkleppHashValue::Internal(SmallIncHash::default())
    }
}

impl<SmallIncHash: Display> Debug for MerkleppHashValue<SmallIncHash> {
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
    pub avg_hash_time: RunningAverage,
    pub avg_accum_time: RunningAverage,
}

impl<FastIncHash> IncrementalHasher<FastIncHash> {
    fn new(arity: usize) -> Self {
        IncrementalHasher {
            num_hashes: 0,
            arity,
            h: Default::default(),
            avg_hash_time: RunningAverage::new(),
            avg_accum_time: RunningAverage::new(),
        }
    }
}

// NOTE: We store children hashes in memory as IncrHash<CompressedRistretto, _>'s, but we hash them to
// IncrHash<RistrettoPoints, _> since they are faster to add. This is why there are two parameters here
pub fn hash_child<SmallIncHash, FastIncHash>(
    i: usize,
    child_hash: &MerkleppHashValue<SmallIncHash>,
) -> FastIncHash
where
    SmallIncHash: Serialize,
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

impl<SmallIncHash, FastIncHash> TreeHasherFunc<String, MerkleppHashValue<SmallIncHash>>
    for IncrementalHasher<FastIncHash>
where
    SmallIncHash: Default + Clone + Serialize + AddAssign<FastIncHash>,
    for<'a> FastIncHash: Default + AddAssign + SubAssign + From<&'a [u8]>,
{
    fn get_num_computations(&self) -> usize {
        self.num_hashes
    }

    // fn is_incremental(&self) -> bool {
    //     true
    // }

    fn hash_leaf_data(&mut self, _offset: usize, data: String) -> MerkleppHashValue<SmallIncHash> {
        // TODO: allow choice here via template parameter
        let mut hasher = Blake2b::<U32>::new();

        let mut hash = [0u8; HASH_LENGTH];
        hasher.update("leaf:".as_bytes());
        hasher.update(data.as_bytes());
        hasher.finalize_into(GenericArray::from_mut_slice(&mut hash));

        MerkleppHashValue::<SmallIncHash>::Leaf(hash)
    }

    fn hash_nodes(
        &mut self,
        old_parent_hash: MerkleppHashValue<SmallIncHash>,
        old_children: &mut Vec<MerkleppHashValue<SmallIncHash>>,
        new_children: &Vec<(usize, MerkleppHashValue<SmallIncHash>)>,
    ) -> MerkleppHashValue<SmallIncHash> {
        // count the number of children whose hashes have changed
        let num_changes = new_children.len();

        let mut incr_hash;
        let mut num_hashes = 0;
        let mut acc = FastIncHash::default();

        let start = Instant::now();
        if num_changes > self.arity / 2 {
            incr_hash = SmallIncHash::default();
            // if more than half the siblings changed, just recompute the parent from scratch
            // since otherwise, we'd be computing more than self.arity incremental hashes
            //
            // NOTE(Alin): I guess we would only use this optimization when the Merkle++ tree is in-memory, since
            // we wouldn't want to read unmodified children from disk.
            num_hashes = self.arity;

            // replace old hashes with new ones
            for (pos, hash) in new_children {
                old_children[*pos] = hash.clone(); // TODO(Perf): avoid clone?
            }

            // recompute parent's incremental hash from scratch
            // NOTE: We use an intermediate FastIncHash representation for the incremental hashes
            // to speed up their addition.
            for i in 0..old_children.len() {
                acc += hash_child::<SmallIncHash, FastIncHash>(i, &old_children[i]);
            }

            assert_eq!(old_children.len(), self.arity);
        } else {
            // if less than half the siblings changed, incrementally update the parent
            incr_hash = match old_parent_hash {
                MerkleppHashValue::<SmallIncHash>::Internal(hash) => hash,
                _ => unreachable!(),
            };

            for (pos, hash) in new_children {
                num_hashes += 2;
                acc -= hash_child::<SmallIncHash, FastIncHash>(*pos, &old_children[*pos]);
                acc += hash_child::<SmallIncHash, FastIncHash>(*pos, hash);
            }

            assert_le!(num_hashes, self.arity);
        }
        self.num_hashes += num_hashes;
        self.avg_hash_time.add(start.elapsed().as_micros(), num_hashes);


        let start = Instant::now();
        incr_hash += acc;
        self.avg_accum_time.add(start.elapsed().as_micros(), 1);


        MerkleppHashValue::<SmallIncHash>::Internal(incr_hash)
    }
}

pub fn new_merklepp_from_height<SmallIncHash, FastIncHash>(
    arity: usize,
    height: usize,
) -> AbstractMerkle<String, MerkleppHashValue<SmallIncHash>, IncrementalHasher<FastIncHash>>
where
    SmallIncHash: Clone + Default + Serialize + AddAssign<FastIncHash>,
    for<'a> FastIncHash: Default + AddAssign + SubAssign + From<&'a [u8]>,
{
    let hasher = IncrementalHasher::new(arity);

    AbstractMerkle::new(arity, height, hasher)
}


pub fn new_merklepp_from_leaves<SmallIncHash, FastIncHash>(
    arity: usize,
    num_leaves: usize,
) -> AbstractMerkle<String, MerkleppHashValue<SmallIncHash>, IncrementalHasher<FastIncHash>>
where
    SmallIncHash: Clone + Default + Serialize + AddAssign<FastIncHash>,
    for<'a> FastIncHash: Default + AddAssign + SubAssign + From<&'a [u8]>,
{
    let hasher = IncrementalHasher::new(arity);

    AbstractMerkle::with_num_leaves(arity, num_leaves, hasher)
}