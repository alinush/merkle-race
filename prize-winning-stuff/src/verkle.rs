use std::borrow::Borrow;
use crate::merkle_abstract::AbstractMerkle;
use crate::hashing_traits::TreeHasherFunc;
use serde::Serialize;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Mul};
use std::time::Instant;
use blake2::{Digest, Blake2b};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, VartimePrecomputedSubsetMultiscalarMul};
use digest::consts::U64;
use more_asserts::assert_le;
use crate::RunningAverage;
use crate::verkle_ristretto::{Compressable, CreateFromPoint};

// TODO: use Rust unions instead, to avoid the 1-byte tagging overhead
#[derive(Clone)]
pub enum VerkleComm<SmallGroupElem> {
    Internal(SmallGroupElem),
    Leaf(Scalar),
    Empty,
}

impl<SmallGroupElem: Identity> Default for VerkleComm<SmallGroupElem>
{
    fn default() -> Self {
        //VerkleComm::Internal(SmallGroupElem::identity())
        VerkleComm::Empty
    }
}

impl<SmallGroupElem: Display> Debug for VerkleComm<SmallGroupElem> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VerkleComm::Internal(c) => write!(f, "{}", c),
            VerkleComm::Leaf(a) => write!(f, "{}", hex::encode(a.as_bytes())),
            VerkleComm::Empty => write!(f, "empty node")
        }
    }
}

pub struct VerkleHasher<FastGroupElem, MultiscalarMulPrecomp, BasepointTable> {
    num_hashes: usize,
    arity: usize,
    h: PhantomData<FastGroupElem>,
    precomp: MultiscalarMulPrecomp,
    base_tables: Vec<BasepointTable>,
    pub avg_exp_time: RunningAverage,
    pub avg_accum_time: RunningAverage,
    // pub avg_clone_time: RunningAverage,
    pub avg_push_updates_time: RunningAverage,
}

impl<FastGroupElem, MultiscalarMulPrecomp, BasepointTable> VerkleHasher<FastGroupElem, MultiscalarMulPrecomp, BasepointTable>
where
    MultiscalarMulPrecomp: VartimePrecomputedSubsetMultiscalarMul<Point = FastGroupElem>,
    FastGroupElem: Clone + Borrow<<MultiscalarMulPrecomp as VartimePrecomputedSubsetMultiscalarMul>::Point>,
    BasepointTable: CreateFromPoint<Point = FastGroupElem>,
{
    fn new(arity: usize, bases: Vec<FastGroupElem>) -> Self {
        VerkleHasher {
            num_hashes: 0,
            arity,
            h: Default::default(),
            precomp: MultiscalarMulPrecomp::new(bases.clone()),
            base_tables: bases.into_iter().map(|point| BasepointTable::create(&point)).collect(),
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
impl<FastGroupElem, SmallGroupElem, MultiscalarMulPrecomp, BasepointTable> TreeHasherFunc<String, VerkleComm<SmallGroupElem>>
    for VerkleHasher<FastGroupElem, MultiscalarMulPrecomp, BasepointTable>
where
    FastGroupElem: AddAssign + Identity + Compressable<CompressedPoint = SmallGroupElem>,
    SmallGroupElem: Serialize + Add<FastGroupElem, Output = SmallGroupElem> + Identity,
    MultiscalarMulPrecomp: VartimePrecomputedSubsetMultiscalarMul<Point = FastGroupElem>,
    BasepointTable: Clone + Mul<Scalar, Output = FastGroupElem>,
{
    fn get_num_computations(&self) -> usize {
        self.num_hashes
    }

    // fn is_incremental(&self) -> bool {
    //     true
    // }

    fn hash_leaf_data(&mut self, _offset: usize, data: String) -> VerkleComm<SmallGroupElem> {
        // TODO: allow choice of inner hash function here via template parameter
        let mut hasher = Blake2b::<U64>::new();

        hasher.update("leaf:".as_bytes());
        hasher.update(data.as_bytes());

        VerkleComm::<SmallGroupElem>::Leaf(Scalar::from_hash(hasher))
    }

    fn hash_nodes(
        &mut self,
        old_parent_comm: VerkleComm<SmallGroupElem>,
        old_children: &mut Vec<VerkleComm<SmallGroupElem>>,
        new_children: &Vec<(usize, VerkleComm<SmallGroupElem>)>,
    ) -> VerkleComm<SmallGroupElem> {
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
        let num_measurements = updates.len();
        self.num_hashes += updates.len();
        let mut delta = FastGroupElem::identity();

        let start = Instant::now();
        if updates.len() <= 4 {
            // NOTE: Run benches/multiexp.rs to figure out what cutoff to use for updates.len()
            // * Average time per clone: 1.29 us (but this multiples by average # of updates)
            for (index, exp) in updates {
                // TODO(Perf): I am cloning a rather large object here because I can't figure out Rust
                //let start = Instant::now();
                let point = self.base_tables[index].clone();
                //self.avg_clone_time.add(start.elapsed().as_micros(), 1);

                delta += point * exp;
            }
        } else {
            delta = self.precomp.vartime_subset_multiscalar_mul(updates);
        }
        self.avg_exp_time.add(start.elapsed().as_micros(), num_measurements);


        match old_parent_comm {
            VerkleComm::Empty => {
                let start = Instant::now();
                let comp = delta.compress();
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
        }
    }
}

pub fn new_verkle_from_height<FastGroupElem, SmallGroupElem, MultiscalarMulPrecomp, BasepointTable>(
    arity: usize,
    height: usize,
    bases: Vec<FastGroupElem>,
) -> AbstractMerkle<String, VerkleComm<SmallGroupElem>, VerkleHasher<FastGroupElem, MultiscalarMulPrecomp, BasepointTable>>
where
    FastGroupElem: Clone + AddAssign + Identity + Compressable<CompressedPoint = SmallGroupElem>,
    SmallGroupElem: Clone + Default + Serialize + Add<FastGroupElem, Output = SmallGroupElem> + Identity,
    MultiscalarMulPrecomp: VartimePrecomputedSubsetMultiscalarMul<Point = FastGroupElem>,
    BasepointTable: Clone + CreateFromPoint<Point = FastGroupElem> + Mul<Scalar, Output = FastGroupElem>,
{
    let hasher = VerkleHasher::new(arity, bases);

    AbstractMerkle::new(arity, height, hasher)
}

pub fn new_verkle_from_leaves<FastGroupElem, SmallGroupElem, MultiscalarMulPrecomp, BasepointTable>(
    arity: usize,
    num_leaves: usize,
    bases: Vec<FastGroupElem>,
) -> AbstractMerkle<String, VerkleComm<SmallGroupElem>, VerkleHasher<FastGroupElem, MultiscalarMulPrecomp, BasepointTable>>
where
    FastGroupElem: Clone + AddAssign + Identity + Compressable<CompressedPoint = SmallGroupElem>,
    SmallGroupElem: Clone + Default + Serialize + Add<FastGroupElem, Output = SmallGroupElem> + Identity,
    MultiscalarMulPrecomp: VartimePrecomputedSubsetMultiscalarMul<Point = FastGroupElem>,
    BasepointTable: Clone + CreateFromPoint<Point = FastGroupElem> + Mul<Scalar, Output = FastGroupElem>,
{
    let hasher = VerkleHasher::new(arity, bases);

    AbstractMerkle::with_num_leaves(arity, num_leaves, hasher)
}