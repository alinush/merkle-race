use std::collections::BTreeMap;

pub trait TreeHasherFunc<LeafDataType, HashType> {
    fn get_num_computations(&self) -> usize;

    // returns true if hash_nodes() does not need *all* the old children hashes to compute the parent's new hash
    fn is_incremental(&self) -> bool;

    // We need this in Merkle++/Verkle because there we will hash leaf data using slightly more efficient
    // hash functions.
    // 'offset' is the leaf's position w.r.t its parent; i.e., a number in [0, arity)
    fn hash_leaf_data(&mut self, offset: usize, leaf: LeafDataType) -> HashType;

    // For Merkle, need to recompute new parent's hash from all the children, so we need *all* the
    // unmodified old children hashes.
    // But for Merkle++/Verkle, we only need the modified children's old and new hashes
    //
    // child_hashes maps child position to its optional new hash and an optional old hash
    // e.g., in non-incremental Merkle, we will store hashes for all children: updated ones are
    // stored in the new hash and old ones are stored in the old hash
    fn hash_nodes(
        &mut self,
        old_parent_hash: HashType,
        old_children: Vec<HashType>,
        new_children: &BTreeMap<usize, HashType>,
    ) -> HashType;
}
