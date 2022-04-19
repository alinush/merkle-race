use merkle_race::merkle::AbstractMerkle;
use merkle_race::merkle_crhf::{new_merkle_sha3_256_from_leaves};
use merkle_race::tree_hasher::TreeHasherFunc;
use merkle_race::{max_leaves, random_updates};
use more_asserts::assert_le;
use std::fmt::Debug;
use std::time::Instant;
use thousands::Separable;

use clap::Parser;
use merkle_race::merkle_pp::{new_merklepp_from_leaves};
use rust_incrhash::compressed_ristretto::CompRistBlakeIncHash;
use rust_incrhash::ristretto::RistBlakeIncHash;

/// Program to benchmark three types of Merkle trees: traditional CRHF-based Merkle,
/// incrementally-hashed Merkle (or Merkle++), and VC-based Merkle (or Verkle)
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Can be either: merkle_sha3, merkle++, merkle++naive
    #[clap(short, long)]
    _type: String, // TODO: list options

    /// Tree arity
    #[clap(short, long)]
    arity: usize,

    /// Tree height
    #[clap(short, long, required_unless_present("num-leaves"))]
    height: Option<usize>,

    /// Number of leaves
    #[clap(short('l'), long, required_unless_present("height"))]
    num_leaves: Option<usize>,

    /// Number of leaves to update
    #[clap(short('u'), long)]
    num_updates: usize,
}

fn main() {
    let args = Args::parse();

    let num_updates: usize = args.num_updates;

    let num_leaves;
    match (args.height, args.num_leaves) {
        (Some(h), None) => num_leaves = max_leaves(args.arity, h),
        (None, Some(l)) => num_leaves = l,
        (Some(_), Some(_)) => panic!("clap failed: it allowed both height and num leaves"),
        (None, None) => panic!("clap failed: it did allow no height and no num leaves"),
    }

    // println!(
    //     "Allocating memory for arity-{} height-{} {}, to benchmark updating {} out of {} leaves",
    //     args.arity,
    //     height,
    //     args._type,
    //     num_updates.separate_with_commas(),
    //     max_leaves.separate_with_commas()
    // );
    println!();

    match args._type.as_str() {
        "merkle_sha3" => {
            let mut merkle = new_merkle_sha3_256_from_leaves(args.arity, num_leaves);

            bench_merkle(&mut merkle, num_leaves, num_updates);
        }
        "merkle++" => {
            let mut merklepp =
                new_merklepp_from_leaves::<CompRistBlakeIncHash, RistBlakeIncHash>(args.arity, num_leaves);

            bench_merkle(&mut merklepp, num_leaves, num_updates);
        }
        "merkle++naive" => {
            let mut merklepp =
                new_merklepp_from_leaves::<CompRistBlakeIncHash, RistBlakeIncHash>(args.arity, num_leaves);

            bench_merkle(&mut merklepp, num_leaves, num_updates);
        }
        _ => {
            println!("Unknown type of Merkle tree provided: {}", args._type)
        }
    }
}

fn bench_merkle<HashType, Hasher>(
    merkle: &mut AbstractMerkle<String, HashType, Hasher>,
    num_leaves: usize,
    num_updates: usize,
) where
    HashType: Clone + Debug + Default,
    Hasher: TreeHasherFunc<String, HashType>,
{
    let updates = random_updates(num_leaves, num_updates);

    assert_le!(num_updates, merkle.num_leaves());

    // NOTE: accounting for preprocessing does reduce time from 860us to 800us in a tree of 2^28 leaves with 200K updates
    let (queue, pre_duration) = merkle.preprocess_leaves(updates.clone());
    let start = Instant::now();
    merkle.update_preprocessed_leaves(queue);
    let duration = start.elapsed() + pre_duration;

    println!(
        "Updated {} leaves in {:?}\n\
         * Updates per second: {}",
        num_updates.separate_with_commas(),
        duration,
        (((num_updates as f64 / duration.as_millis() as f64) * 1000.0) as usize)
            .separate_with_commas()
    );

    println!(
        "Total hashes computed: {}\n\
         * Hashes per second: {}\n",
        merkle.hasher.get_num_computations().separate_with_commas(),
        (((merkle.hasher.get_num_computations() as f64 / duration.as_millis() as f64) * 1000.0)
            as usize)
            .separate_with_commas()
    );
}
