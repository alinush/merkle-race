use itertools::Itertools;
use merkle_race::max_leaves;
use merkle_race::merkle_abstract::AbstractMerkle;
use merkle_race::merkle_crhf::new_merkle_sha3_256;
use merkle_race::tree_hasher::TreeHasherFunc;
use more_asserts::assert_le;
use rand::distributions::Alphanumeric;
use rand::seq::IteratorRandom;
use rand::Rng;
use std::fmt::Debug;
use std::iter::zip;
use std::time::Instant;
use thousands::Separable;

use clap::Parser;
use merkle_race::merkle_pp::new_merklepp_rist;

/// Program to benchmark three types of Merkle trees: traditional CRHF-based Merkle,
/// incrementally-hashed Merkle (or Merkle++), and VC-based Merkle (or Verkle)
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Type of Merkle tree
    #[clap(short, long)]
    _type: String, // TODO: list options

    /// Tree arity
    #[clap(short, long, default_value_t = 2)]
    arity: usize,

    /// Tree height
    #[clap(short, long, default_value_t = 30)]
    height: usize,

    /// Number of leaves to update
    #[clap(short, long, default_value_t = 200000)]
    num_updates: usize,
}

const LEAF_LENGTH: usize = 32 + 64;

fn main() {
    let args = Args::parse();

    let height = args.height;
    let num_updates: usize = args.num_updates;
    let max_leaves = max_leaves(args.arity, height);

    println!(
        "Allocating memory for arity-{} height-{} {}, to benchmark updating {} out of {} leaves",
        args.arity,
        height,
        args._type,
        num_updates.separate_with_commas(),
        max_leaves.separate_with_commas()
    );
    println!();

    match args._type.as_str() {
        "merkle_sha3" => {
            let mut merkle = new_merkle_sha3_256(args.arity, height);
            bench_merkle(&mut merkle, num_updates);
        }
        "merkle++" => {
            let mut merklepp = new_merklepp_rist(args.arity, height);
            bench_merkle(&mut merklepp, num_updates);
        }
        _ => {
            unreachable!()
        }
    }
}

fn bench_merkle<HashType, Hasher>(
    merkle: &mut AbstractMerkle<String, HashType, Hasher>,
    num_updates: usize,
) where
    HashType: Clone + Debug + Default,
    Hasher: TreeHasherFunc<String, HashType>,
{
    let update_prefix = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(LEAF_LENGTH)
        .map(char::from)
        .collect::<String>();
    let update_prefix_slice = update_prefix.as_str();

    println!("Leaf prefix: {}", update_prefix_slice);
    println!();

    let start = Instant::now();
    let updates: Vec<(usize, String)> = zip(
        (0..num_updates)
            .choose_multiple(&mut rand::thread_rng(), num_updates)
            .into_iter()
            .sorted(),
        (0..num_updates)
            .map(|i| update_prefix_slice.to_string() + "/" + &i.to_string())
            .collect::<Vec<String>>(),
    )
    .collect::<Vec<(usize, String)>>();

    println!(
        "Sampled {} random updates in {:?}",
        num_updates.separate_with_commas(),
        start.elapsed()
    );
    println!();

    assert_le!(num_updates, merkle.num_leaves());

    let start = Instant::now();
    merkle.update_leaves(&updates);
    let duration = start.elapsed();

    println!(
        "Updated {} leaves in {:?}",
        num_updates.separate_with_commas(),
        duration
    );
    println!(
        "Updates per second: {}",
        (((num_updates as f64 / duration.as_millis() as f64) * 1000.0) as usize)
            .separate_with_commas()
    );
    println!();
    println!(
        "Total hashes computed: {}",
        merkle.hasher.get_num_computations().separate_with_commas()
    );
    println!(
        "Hasher per second: {}",
        (((merkle.hasher.get_num_computations() as f64 / duration.as_millis() as f64) * 1000.0)
            as usize)
            .separate_with_commas()
    );
}
