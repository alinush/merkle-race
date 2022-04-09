use crate::max_leaves;
use crate::node_index::NodeIndex;
use crate::tree_hasher::TreeHasherFunc;
use more_asserts::assert_le;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};
use std::marker::PhantomData;

// An abstract, "perfect" Merkle tree of arity k and height h, where "perfect" means the tree has
// *exactly* k^h leaves
pub struct AbstractMerkle<LeafDataType, HashType, Hasher> {
    //height: usize, // the tree height
    arity: usize, // the tree's arity

    n: usize, // the number of leaves = arity^height

    //n: usize,             // the number of leaves in the tree; equal to k^h

    // The array of *internal* nodes only, including leaves.
    // (When leaves need to be hashed differently than internal nodes, use an enum.)
    //
    // Root is stored at nodes[0]; its k children are stored at nodes[1...k].
    // The children of nodes[i] are stored at nodes[i*k + 1 .. i*k + k] = nodes[i*k + 1 .. (i+1)*k].
    // The parent of nodes[i] is stored at nodes[(i-1)/k].
    // e.g.,
    //                              0
    //    1             2                3               4
    // 5 6 7 8      9 10 11 12      13 14 15 16     17 18 19 20
    nodes: Vec<HashType>,

    // The function used to update parent hashes when some (or all) of the k children change.
    // Recall that in an incremental Merkle (but not Verkle) tree, the hash of the parent when the
    // ith child changes is updated as:
    //
    //      new_parent_hash = old_parent_hash - H(i : old_child_hash) + H(i : new_child_hash)
    //
    // So we need both the old and the new hash of the child as parameters.
    //
    // Similarly, in a Verkle tree, when the ith child changes, we update the parent as:
    //
    //      new_parent_vc = old_parent_vc / g_i^{H(old_child_vc) - H(new_child_vc)}
    //
    // So we still need the old and the new VC of the child as parameters.
    //
    // In a normal Merkle however, we just need to know the new hash of all the children, since we
    // recompute the parent from scratch.
    pub hasher: Hasher,

    // Rust is weird.
    phantom: PhantomData<LeafDataType>,
}

impl<LeafDataType, HashType, Hasher> AbstractMerkle<LeafDataType, HashType, Hasher>
where
    LeafDataType: Clone,
    HashType: Default + Clone,
    Hasher: TreeHasherFunc<LeafDataType, HashType>,
{
    pub fn num_leaves(&self) -> usize {
        self.n
    }

    pub fn new(arity: usize, height: usize, hasher: Hasher) -> Self {
        let n = max_leaves(arity, height);
        let internal_nodes = (n - 1) / (arity - 1);
        let total_nodes = internal_nodes + n;

        AbstractMerkle {
            arity,
            //height,
            n,
            nodes: vec![HashType::default(); total_nodes],
            hasher,
            phantom: Default::default(),
        }
    }

    // returns this node's child offset; i.e., its position i relative to its parent, where i \in [0, arity)
    fn child_offset(&self, node: &NodeIndex) -> usize {
        node.child_offset(self.arity)
    }

    // returns the parent's NodeIndex
    fn parent_node(&self, node: &NodeIndex) -> NodeIndex {
        node.parent(self.arity)
    }

    // returns the NodeIndex of the ith child, where i \in [0, arity)
    fn child_node(&self, node: &NodeIndex, i: usize) -> NodeIndex {
        node.child(self.arity, i)
    }

    // returns true if this node is a sibling of 'other'
    // fn are_siblings(&self, first: &NodeIndex, second: &NodeIndex) -> bool {
    //     first.is_sibling(self.arity, second)
    // }

    fn get_node_hash(&self, node: &NodeIndex) -> HashType {
        self.nodes[node.0].clone()
    }

    fn set_node_hash(&mut self, node: &NodeIndex, hash: HashType) {
        self.nodes[node.0] = hash;
    }

    // given a leaf's position (from 0 to the max number of leaves n = arity^height), returns that
    // leaf's NodeIndex
    fn get_leaf_idx(&self, leaf_pos: usize) -> NodeIndex {
        let leaf_offset = (self.num_leaves() - 1) / (self.arity - 1); // the index of the first leaf

        NodeIndex(leaf_offset + leaf_pos)
    }

    // Problem: We need old leaf values here in order to update parent in Merkle++ and in Verkle
    // e.g., in Merkle++, need parent = old_parent - H(i : old_leaf) + H(i : new_leaf)
    // e.g., in Verkle, have parent = VC.UpdCom(old_parent, i, MapToField(new_leaf) - MapToField(old_leaf))
    // In Merkle, just need new value, but also the old siblings:
    // e.g., parent = H(old_child|1, old_child|2, ..., new_leaf|i, ..., old_child|k)
    //
    // updates.0 is the index of the leaf being updates, in [0, n)
    pub fn update_leaves(&mut self, updates: &Vec<(usize, LeafDataType)>) {
        // NOTE: This needs +nightly, so replaced it with something else below
        // assert!(updates.as_slice().is_sorted_by(|a , b| {
        //     let (idx1, _) = a;
        //     let (idx2, _) = b;
        //
        //     Some(idx1.cmp(idx2))
        // }));

        // Assert that leaf updates are sorted by index
        // NOTE: debug_assert_* calls are disabled for benchmarks!
        assert!((0..updates.len() - 1).all(|i| updates[i].0 <= updates[i + 1].0));

        // Convert the leaf positions (which are given in [0, n)) to a NodeIndex inside the tree and
        // hash the leaves (which are given as LeafDataType's)
        let mut curr_updates: VecDeque<(NodeIndex, HashType)> = updates
            .clone()
            .into_iter()
            .map(|leaf| {
                let (leaf_pos, leaf_data) = leaf;
                let leaf_idx = self.get_leaf_idx(leaf_pos);
                let child_offset: usize = self.child_offset(&leaf_idx);

                (
                    leaf_idx,
                    self.hasher.hash_leaf_data(child_offset, leaf_data.clone()),
                )
            })
            .collect::<VecDeque<_>>();

        // Now, we have a queue of updated leaves: their position and new hash.
        // We can group these into size-k chunks where all nodes are siblings.
        // Then, we can compute the new parent hash and add it to the queue.

        let pop_sibling = |tree: &mut Self,
                           queue: &mut VecDeque<(NodeIndex, HashType)>,
                           siblings: &mut BTreeMap<_, _>| {
            let sib = queue.pop_front().unwrap();
            let sib_idx = sib.0;
            let sib_offset = tree.child_offset(&sib_idx);

            siblings.insert(sib_offset, sib.1);

            // NOTE: the tree will be updated with this sibling's new hash later

            sib_idx
        };

        while !curr_updates.is_empty() {
            let mut new_siblings = BTreeMap::new();
            let mut old_siblings: Vec<HashType> = Vec::with_capacity(self.arity);

            // pop the first sibling off the queue
            let first_sib_idx = pop_sibling(self, &mut curr_updates, &mut new_siblings);

            // if this sibling is actually the root node, we are done
            if !first_sib_idx.is_root() {
                let parent_idx = self.parent_node(&first_sib_idx);

                // pop all other siblings off the queue
                while !curr_updates.is_empty() {
                    let (potential_sib, _) = curr_updates.front().unwrap();

                    // if this is an actual sibling, track it so we can use it to update the parent
                    if self.parent_node(&potential_sib) == parent_idx {
                        pop_sibling(self, &mut curr_updates, &mut new_siblings);
                    } else {
                        break;
                    }
                }

                // now we have all siblings that were updated in 'old_siblings'
                assert_le!(new_siblings.len(), self.arity);

                // we always give *all* the *old* hashes of the siblings, since Merkle++ requires them
                // to speed up parent updates
                for i in 0..self.arity {
                    let child_idx = self.child_node(&parent_idx, i);
                    old_siblings.push(self.get_node_hash(&child_idx));
                }

                // first, compute the updated parent hash and schedule it to be processed later
                curr_updates.push_back((
                    parent_idx,
                    self.hasher.hash_nodes(
                        self.get_node_hash(&parent_idx),
                        old_siblings,
                        &new_siblings,
                    ),
                ));

                // second, update tree with new sibling hashes
                for (idx, hash) in new_siblings {
                    let child_idx = self.child_node(&parent_idx, idx);
                    self.set_node_hash(&child_idx, hash);
                }

                // end of !first_sib_idx.is_root()
            } else {
                assert_eq!(new_siblings.len(), 1);

                match new_siblings.entry(0) {
                    Entry::Vacant(_) => panic!("Expected root node to be in the new_siblings map"),
                    Entry::Occupied(hash) => {
                        self.set_node_hash(&NodeIndex::root_node(), hash.remove())
                    }
                }
            }
        }
    }
}
