extern crate core;

use itertools::Itertools;
use rand::distributions::Alphanumeric;
use rand::prelude::IteratorRandom;
use rand::Rng;
use std::iter::zip;
use std::time::Instant;
use std::vec::IntoIter;
use thousands::Separable;

//#![feature(is_sorted)]

#[macro_use]
pub(crate) mod macros;

pub mod merkle_abstract;
pub mod merkle_crhf;
pub mod merkle_pp;
pub mod node_index;
pub mod hashing_traits;
pub mod verkle;
pub mod verkle_ristretto;

pub fn max_leaves(arity: usize, height: usize) -> usize {
    arity.pow(height as u32)
}

pub fn random_leaf_positions(max_num_leaves: usize, num_pos: usize) -> IntoIter<usize> {
    (0..max_num_leaves)
        .choose_multiple(&mut rand::thread_rng(), num_pos)
        .into_iter()
        .sorted()
}

const TEST_LEAF_LENGTH: usize = 32 + 64;

pub fn random_updates(max_num_leaves: usize, num_updates: usize) -> Vec<(usize, String)> {
    println!("Sampling {} out of {} random leaf updates", num_updates.separate_with_commas(), max_num_leaves.separate_with_commas());


    let update_prefix = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(TEST_LEAF_LENGTH)
        .map(char::from)
        .collect::<String>();
    let update_prefix_slice = update_prefix.as_str();

    println!("Leaf prefix: {}", update_prefix_slice);

    let start = Instant::now();
    let updates: Vec<(usize, String)> = zip(
        random_leaf_positions(max_num_leaves, num_updates),
        (0..num_updates)
            .map(|i| update_prefix_slice.to_string() + "/" + &i.to_string())
            .collect::<Vec<String>>(),
    )
    .collect::<Vec<(usize, String)>>();

    println!(
        "Sampled {} random updates in {:?}\n",
        num_updates.separate_with_commas(),
        start.elapsed()
    );
    updates
}

// pub fn new_merkle_from_height<LeafDataType, HashType, Hasher>(
//     arity: usize,
//     height: usize,
// ) -> AbstractMerkle<LeafDataType, HashType, Hasher> {
//     AbstractMerkle::new(arity, height, Hasher::new(arity))
// }
//
// pub fn new_merkle_from_leaves<LeafDataType, HashType, Hasher>(
//     arity: usize,
//     num_leaves: usize,
// ) -> AbstractMerkle<LeafDataType, HashType, Hasher> {
//     AbstractMerkle::with_num_leaves(arity, num_leaves, Hasher::new(arity))
// }

// pub fn smallestPowerAbove(arity : usize, n: usize) -> usize {
//
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bvt() {
        assert_eq!(max_leaves(2, 30), 1073741824);
        assert_eq!(max_leaves(2, 60), max_leaves(4, 30));
        assert_eq!(max_leaves(4, 30), 1152921504606846976);
    }
}
