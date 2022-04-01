extern crate core;

//#![feature(is_sorted)]
pub mod merkle_abstract;
pub mod merkle_crhf;
pub mod merkle_pp;
pub mod node_index;
pub mod tree_hasher;

pub fn max_leaves(k: usize, h: usize) -> usize {
    k.pow(h as u32)
}

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
