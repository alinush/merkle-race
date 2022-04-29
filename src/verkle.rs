use std::borrow::Borrow;
use crate::merkle_abstract::AbstractMerkle;
use crate::hashing_traits::TreeHasherFunc;
use serde::Serialize;
use std::fmt::{Debug, Formatter};
use std::time::Instant;
use blake2::{Digest, Blake2b};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoBasepointTable, RistrettoPoint, VartimeRistrettoSubsetPrecomputation};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, VartimePrecomputedSubsetMultiscalarMul};
use digest::consts::U64;
use more_asserts::assert_le;
use crate::{HistogramAverages, RunningAverage};

// TODO: use Rust unions instead, to avoid the 1-byte tagging overhead
#[derive(Clone)]
pub enum VerkleComm {
    Internal(CompressedRistretto),
    Leaf(Scalar),
    Empty,
}

impl Default for VerkleComm
{
    fn default() -> Self {
        //VerkleComm::Internal(CompressedRistretto::identity())
        VerkleComm::Empty
    }
}

impl Debug for VerkleComm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VerkleComm::Internal(c) => write!(f, "{}", hex::encode(c.as_bytes())),
            VerkleComm::Leaf(a) => write!(f, "{}", hex::encode(a.as_bytes())),
            VerkleComm::Empty => write!(f, "empty node")
        }
    }
}

pub struct VerkleHasher {
    num_hashes: usize,
    arity: usize,
    precomp: VartimeRistrettoSubsetPrecomputation,
    base_tables: Vec<RistrettoBasepointTable>,
    pub hash_nodes_histogram: HistogramAverages,
    pub avg_single_exp_time: RunningAverage,
    pub avg_multi_exp_time: RunningAverage,
    pub avg_exp_time: RunningAverage,
    pub avg_accum_time: RunningAverage,
    // pub avg_clone_time: RunningAverage,
    pub avg_push_updates_time: RunningAverage,
}

impl VerkleHasher
{
    fn new(arity: usize, bases: Vec<RistrettoPoint>) -> Self {
        VerkleHasher {
            num_hashes: 0,
            arity,
            precomp: VartimeRistrettoSubsetPrecomputation::new(bases.clone()),
            base_tables: bases.into_iter().map(|point| RistrettoBasepointTable::create(&point)).collect(),
            hash_nodes_histogram: HistogramAverages::new(arity),
            avg_single_exp_time: RunningAverage::new(),
            avg_multi_exp_time: RunningAverage::new(),
            avg_exp_time: RunningAverage::new(),
            avg_accum_time: RunningAverage::new(),
            // avg_clone_time: RunningAverage::new(),
            avg_push_updates_time: RunningAverage::new(),
        }
    }
}

pub fn hash_to_scalar<SmallGroupElem>(gelem: &SmallGroupElem) -> Scalar
where
    SmallGroupElem: Serialize
{
    Scalar::hash_from_bytes::<Blake2b::<U64>>(bincode::serialize(gelem).unwrap().as_slice())
}

// because we'll store CompressedRistretto but multiexp on RistrettoPoint's
impl TreeHasherFunc<String, VerkleComm>
    for VerkleHasher
{
    fn get_num_computations(&self) -> usize {
        self.num_hashes
    }

    // fn is_incremental(&self) -> bool {
    //     true
    // }

    fn hash_leaf_data(&mut self, _offset: usize, data: String) -> VerkleComm {
        // TODO: allow choice of inner hash function here via template parameter
        let mut hasher = Blake2b::<U64>::new();

        hasher.update("leaf:".as_bytes());
        hasher.update(data.as_bytes());

        VerkleComm::Leaf(Scalar::from_hash(hasher))
    }

    fn hash_nodes(
        &mut self,
        old_parent_comm: VerkleComm,
        old_children: &mut Vec<VerkleComm>,
        new_children: &Vec<(usize, VerkleComm)>,
    ) -> VerkleComm {
        assert_le!(new_children.len(), self.arity);

        // TODO(Perf): Can trade-off double the storage for less than double the speed here
        // We can have each node store its own scalar hash here, which right now we compute manually
        // and discard.

        let start = Instant::now();
        let mut updates: Vec<(usize, Scalar)> = Vec::with_capacity(new_children.len());
        for (offset, new_child_elem) in new_children {
            match (old_children[*offset].borrow(), new_child_elem) {
                (VerkleComm::Empty, VerkleComm::Empty) => {
                    panic!("Old child and new child are both empty.");
                },
                (VerkleComm::Empty, VerkleComm::Internal(new_gelem)) => {
                    let new_scalar = hash_to_scalar(new_gelem);

                    updates.push((*offset, new_scalar));
                },
                (VerkleComm::Empty, VerkleComm::Leaf(new_scalar)) => {
                    updates.push((*offset, *new_scalar));
                },

                (VerkleComm::Internal(_), VerkleComm::Empty) => {
                    panic!("Old child was internal, but new one is empty.");
                }
                (VerkleComm::Internal(old_gelem), VerkleComm::Internal(new_gelem)) => {
                    let old_scalar = hash_to_scalar(old_gelem);
                    let new_scalar = hash_to_scalar(new_gelem);

                    updates.push((*offset, new_scalar - old_scalar));
                }
                (VerkleComm::Internal(_), VerkleComm::Leaf(_)) => {
                    panic!("Old child was internal, but new one is leaf.");
                },

                (VerkleComm::Leaf(_), VerkleComm::Empty) => {
                    panic!("Old child was a leaf, but new one is empty.");
                },
                (VerkleComm::Leaf(_), VerkleComm::Internal(_)) => {
                    panic!("Old child was a leaf, but new one is internal.");
                },
                (VerkleComm::Leaf(old_scalar), VerkleComm::Leaf(new_scalar)) => {
                    updates.push((*offset, new_scalar - old_scalar));
                }
            }
        }
        self.avg_push_updates_time.add(start.elapsed().as_micros(), 1);

        assert_le!(updates.len(), self.arity);

        // NOTE(Perf): If the # of updates is small, just do normal exps!
        let num_exps = updates.len();
        let num_measurements = num_exps;
        self.num_hashes += num_exps;
        let mut delta = RistrettoPoint::identity();

        let start_exp = Instant::now();
        if num_exps <= 4 {
            // NOTE: Run benches/multiexp.rs to figure out what cutoff to use for updates.len()
            for (index, exp) in updates {
                let start = Instant::now();
                delta += &self.base_tables[index] * &exp;
                self.avg_single_exp_time.add(start.elapsed().as_micros(), 1);
            }
        } else {
            let start = Instant::now();
            delta = self.precomp.vartime_subset_multiscalar_mul(updates);
            self.avg_multi_exp_time.add(start.elapsed().as_micros(), num_exps);
        }
        self.avg_exp_time.add(start_exp.elapsed().as_micros(), num_measurements);


        let new_parent = match old_parent_comm {
            VerkleComm::Empty => {
                let start = Instant::now();
                let comp = delta.compress();

                // NOTE(Perf): In practice, we would pay this cost when decompressing the parent, but
                // in this implementation the parents are VerkleComm::Empty by default, so that's why
                // I'm adding it here, so as to get correct numbers.
                comp.decompress();

                self.avg_accum_time.add(start.elapsed().as_micros(), 1);

                VerkleComm::Internal(comp)
            },

            // NOTE(Perf): This actually loses us around 7 us: we do a decompress, we add the delta
            // and then a compress. No way around it AFAICT.
            VerkleComm::Internal(_small_gelem) => {
                unreachable!("I believe this will never be reached because we start with an empty tree");
                // let start = Instant::now();
                // let result = small_gelem + delta;
                // self.avg_accum_time.add(start.elapsed().as_micros(), 1);
                //
                // VerkleComm::Internal(result)
            },

            VerkleComm::Leaf(_) => unreachable!("Expected non-leaf parent node in VerkleHasher::hash_nodes"),
        };

        self.hash_nodes_histogram.add(num_exps, start.elapsed().as_micros());

        new_parent
    }
}

pub fn new_verkle_from_height(
    arity: usize,
    height: usize,
    bases: Vec<RistrettoPoint>,
) -> AbstractMerkle<String, VerkleComm, VerkleHasher>
{
    let hasher = VerkleHasher::new(arity, bases);

    AbstractMerkle::new(arity, height, hasher)
}

pub fn new_verkle_from_leaves(
    arity: usize,
    num_leaves: usize,
    bases: Vec<RistrettoPoint>,
) -> AbstractMerkle<String, VerkleComm, VerkleHasher>
{
    let hasher = VerkleHasher::new(arity, bases);

    AbstractMerkle::with_num_leaves(arity, num_leaves, hasher)
}