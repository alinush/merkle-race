use merkle_race::merkle_abstract::AbstractMerkle;
use merkle_race::merkle_crhf::{new_merkle_crhf_from_leaves, Blake2sHashFunc, TinySha3HashFunc, Blake2bHashFunc, Sha3HashFunc};
use merkle_race::hashing_traits::TreeHasherFunc;
use merkle_race::{max_leaves, random_updates};
use more_asserts::assert_le;
use std::fmt::Debug;
use std::time::Instant;
use thousands::Separable;

use clap::Parser;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;
use merkle_race::merkle_pp::new_merklepp_from_leaves;
use rust_incrhash::compressed_ristretto::CompRistBlakeIncHash;
use rust_incrhash::ristretto::RistBlakeIncHash;
use merkle_race::verkle::new_verkle_from_leaves;

/// Program to benchmark three types of Merkle trees: traditional CRHF-based Merkle,
/// incrementally-hashed Merkle (or Merkle++), and VC-based Merkle (or Verkle)
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Can be either: merkle_sha3, merkle_blake2s, merkle_blake2b, merkle++, merkle++naive, or verkle
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
        "merkle_tiny_sha3" => {
            let mut merkle = new_merkle_crhf_from_leaves::<TinySha3HashFunc>(args.arity, num_leaves);

            bench_merkle(&mut merkle, num_leaves, num_updates);
        }
        "merkle_sha3" => {
            let mut merkle = new_merkle_crhf_from_leaves::<Sha3HashFunc>(args.arity, num_leaves);

            bench_merkle(&mut merkle, num_leaves, num_updates);
        }
        "merkle_blake2s" => {
            let mut merkle = new_merkle_crhf_from_leaves::<Blake2sHashFunc>(args.arity, num_leaves);

            bench_merkle(&mut merkle, num_leaves, num_updates);
        }
        "merkle_blake2b" => {
            let mut merkle = new_merkle_crhf_from_leaves::<Blake2bHashFunc>(args.arity, num_leaves);

            bench_merkle(&mut merkle, num_leaves, num_updates);
        }
        "merkle++" => {
            let mut merklepp = new_merklepp_from_leaves::<CompRistBlakeIncHash, RistBlakeIncHash>(
                args.arity, num_leaves,
            );

            bench_merkle(&mut merklepp, num_leaves, num_updates);

            println!("Average time per incremental hash: {}", merklepp.hasher.avg_hash_time);
            println!("Average time per accumulation (compress/decompress): {}", merklepp.hasher.avg_accum_time);
            println!("hash_nodes histogram:\n{}", merklepp.hasher.hash_nodes_histogram);
        }
        "merkle++naive" => {
            let mut merklepp = new_merklepp_from_leaves::<RistBlakeIncHash, RistBlakeIncHash>(
                args.arity, num_leaves,
            );

            bench_merkle(&mut merklepp, num_leaves, num_updates);
        }
        "verkle" => {
            let mut rng = thread_rng();
            let bases = (0..args.arity).map(|_|
                (&Scalar::random(&mut rng) * &RISTRETTO_BASEPOINT_TABLE)).collect::<Vec<RistrettoPoint>>();

            let mut verkle = new_verkle_from_leaves(
                args.arity, num_leaves, bases,
            );

            bench_merkle(&mut verkle, num_leaves, num_updates);

            println!("Average time to push updates (Vec::new, hash_to_scalar): {:.2}", verkle.hasher.avg_push_updates_time);

            println!("Average time per *single* exponentiation: {:.2}", verkle.hasher.avg_single_exp_time);

            println!("Average exponentiation time via *multiexps*: {:.2}", verkle.hasher.avg_multi_exp_time);

            println!("Average time per (any) exponentiation: {:.2}", verkle.hasher.avg_exp_time);
            // println!(" * Average time per clone: {:.2}", verkle.hasher.avg_clone_time);

            println!("Average time per accumulation (compress/decompress): {:.2}", verkle.hasher.avg_accum_time);
            println!("hash_nodes histogram:\n{}", verkle.hasher.hash_nodes_histogram);
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
    let (queue, pre_duration) = merkle.preprocess_leaves(updates);
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
         * Hashes per second: {}\n\
         * Time per hash: {:.2} us\n",
        merkle.hasher.get_num_computations().separate_with_commas(),
        (((merkle.hasher.get_num_computations() as f64 / duration.as_millis() as f64) * 1000.0)
            as usize)
            .separate_with_commas(),
        duration.as_micros() as f64 / merkle.hasher.get_num_computations() as f64
    );
}
