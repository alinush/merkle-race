use std::collections::{HashSet, VecDeque};
use std::marker::PhantomData;
use std::mem::size_of;
use std::time::Duration;

use more_asserts::{assert_le, debug_assert_le};

use crate::max_leaves;
use crate::node_index::NodeIndex;
use crate::tree_hasher::TreeHasherFunc;

// An abstract, "perfect" Merkle tree of arity k and height h, where "perfect" means the tree has
// *exactly* k^h leaves
pub struct AbstractMerkle<LeafDataType, HashType, Hasher> {
    //perfect: bool, // set to true when the # of leaves == arity^height

    arity: usize, // the tree's arity

    //height: usize, // tree height, including the last level which might not be completely filled

    num_internal_nodes: usize, // helpful for computing the index of the first leaf in 'nodes'

    num_leaves: usize, // the number of leaves <= arity^height

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

    // This is the node index of the first leaf on the last level h of the tree, since in some cases
    // we might also have leaves on level h-1.
    //
    // NOTE: We could've computed this on the fly, but it's much more convenient to store it here.
    first_last_level_leaf: NodeIndex,

    // This is a debugging tool: we use it to make sure we never compute a node's hash twice
    _hashed_nodes: HashSet<NodeIndex>,
}

impl<LeafDataType, HashType, Hasher> AbstractMerkle<LeafDataType, HashType, Hasher>
    where
        LeafDataType: Clone,
        HashType: Default + Clone,
        Hasher: TreeHasherFunc<LeafDataType, HashType>,
{
    pub fn with_num_leaves(arity: usize, num_leaves: usize, hasher: Hasher) -> Self {
        dbg!(size_of::<HashType>());

        let mut height: usize = 0;
        let mut n = num_leaves;

        // compute the tree's height
        while n / arity > 0 {
            height += 1;

            n /= arity;
        }

        // We need to handle case where leaves do *not* fully fit on last level. For example, when
        // arity = 3 and num_leaves = 10, we'll get n / arity = 10 / 3 > 0 => { height = 1, n = 3 }
        // Then, 3 / 3 > 0 => { height = 2, n = 1 }. Then, 1 / 3 = 0, so height stays 2. However,
        // this tree has height 3: 1 root, 3 children, 9 children and the last level could have all
        // the 10 leaves or they might be split amongst this last level and the second-to-last. So
        // we need to decide how to handle this. How about this:
        //
        // If all leafs fit on the last level, we are done. Otherwise, we split the leaves across
        // level 'height' and 'height+1' as per https://hackmd.io/54A_Zk58SHqxpBQwwfx0Cg
        let max_leaves = max_leaves(arity, height);
        let mut num_internal_nodes = (max_leaves - 1) / (arity - 1);
        let mut total_nodes = num_internal_nodes + num_leaves;
        //let mut perfect = true;
        let mut first_last_level_leaf = NodeIndex(num_internal_nodes);

        if num_leaves > max_leaves {
            //perfect = false;
            let last_level_max_size = max_leaves * arity;
            let num_last: usize;
            let num_second_to_last: usize;
            if last_level_max_size - num_leaves >= arity {
                let mut epsilon = arity;
                let r_num_f = |e: usize| {
                    // dbg!(last_level_max_size);
                    // dbg!(num_leaves);
                    // dbg!(arity);
                    // dbg!(e);

                    last_level_max_size - num_leaves - (arity - e)
                };
                let mut r_num = r_num_f(epsilon);
                let r_denom = arity - 1;

                while r_num % r_denom != 0 {
                    epsilon -= 1;
                    if epsilon == 0 {
                        panic!("Alin math fail: epsilon was supposed to stay in [1, arity]");
                    }
                    r_num = r_num_f(epsilon);
                }
                assert_eq!(r_num % r_denom, 0);

                num_second_to_last = r_num / r_denom;
                num_last = (max_leaves - num_second_to_last - 1) * arity + epsilon;
            } else {
                num_second_to_last = 0;
                num_last = num_leaves;
            }

            assert_eq!(num_second_to_last + num_last, num_leaves);

            // dbg!(num_second_to_last);
            // dbg!(num_last);

            //height += 1;
            num_internal_nodes = (max_leaves - 1) / (arity - 1) + max_leaves - num_second_to_last; // because the last R nodes on level 'h' are leaves
            total_nodes = num_internal_nodes + num_leaves; // by definition
            first_last_level_leaf = NodeIndex(num_internal_nodes + num_second_to_last);
        } else {
            println!("Leaves perfectly fit on last level!");
        }

        // dbg!(height);
        // dbg!(max_leaves);
        // dbg!(num_internal_nodes);
        // dbg!(first_last_level_leaf);
        //
        // println!(
        //     "arity {}, height {}, # leaves {}, internal nodes {}, total nodes {}",
        //     arity, height, num_leaves, num_internal_nodes, total_nodes
        // );

        AbstractMerkle {
            //perfect,
            arity,
            //height,
            num_internal_nodes,
            num_leaves,
            nodes: vec![HashType::default(); total_nodes],
            hasher,
            phantom: Default::default(),
            first_last_level_leaf,
            _hashed_nodes: HashSet::new(),
        }
    }

    pub fn new(arity: usize, height: usize, hasher: Hasher) -> Self {
        AbstractMerkle::with_num_leaves(arity, max_leaves(arity, height), hasher)
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
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

    fn get_node_hash(&self, node: &NodeIndex) -> Option<HashType> {
        self.nodes.get(node.0).cloned()
    }

    fn set_node_hash(&mut self, node: &NodeIndex, hash: HashType) {
        self.nodes[node.0] = hash;
    }

    fn is_leaf(&self, node: &NodeIndex) -> bool {
        node.0 > self.num_internal_nodes - 1
    }

    fn get_node_height(&self, node: &NodeIndex) -> usize {
        let mut curr = *node;
        let mut h = 0;

        while !curr.is_root() {
            curr = self.parent_node(&curr);
            h += 1
        }

        h
    }

    pub fn has_leaves_on_two_levels(&self) -> bool {
        debug_assert_ne!(self.num_leaves, 0);
        // get the index of the last leaf in the tree
        let last_leaf = NodeIndex(self.nodes.len() - 1);

        // get the index of the first leaf in the tree
        let first_leaf = NodeIndex(self.nodes.len() - self.num_leaves);

        // check if their levels match or not
        self.get_node_height(&first_leaf) != self.get_node_height(&last_leaf)
    }

    pub fn is_last_level_leaf(&self, leaf_idx: &NodeIndex) -> bool {
        leaf_idx.0 >= self.first_last_level_leaf.0
    }

    // Given a leaf's position (in [0,n), where n is the # of leaves), returns that leaf's NodeIndex
    //
    // Here, we have to number the leaves rather awkwardly in order to make sure they get queued up
    // in the right order: the nodes in the queue need to have monotonically decreasing level numbers,
    // so if we first queue up the leaves at level h and then the leaves at level h+1, that won't
    // work. (Details get gory, but you end up needing siblings to process dequeued updates and those
    // siblings have not yet been updated because they are in the queue.)
    //
    // As a result, numbering starts with the leaves at level h+1, and then goes to the leaves at level
    // h. This is more complicated but avoids the problem mentioned above!
    fn get_leaf_idx(&self, leaf_pos: usize) -> NodeIndex {
        // NOTE: If the tree were "perfect" (i.e., exactly arity^height leaves), then the first leaf
        // would be at index (self.num_leaves() - 1) / (self.arity - 1)

        NodeIndex(self.num_internal_nodes + leaf_pos)
    }

    #[allow(dead_code)]
    fn get_leaf_pos(&self, leaf_idx: &NodeIndex) -> usize {
        leaf_idx.0 - self.num_internal_nodes
    }

    fn pop_sibling(
        self: &mut Self,
        queue: &mut VecDeque<(NodeIndex, HashType)>,
        siblings: &mut Vec<(usize, HashType)>,
    ) -> NodeIndex {
        let sib = queue.pop_front().unwrap();
        let sib_idx = sib.0;
        let sib_offset = self.child_offset(&sib_idx);

        // NOTE: Uncomment for debugging
        if !sib_idx.is_root() {
            if !self.is_leaf(&sib_idx) {
                // println!(
                //     "Dequeing new children {} (offset {}) of parent {}",
                //     sib_idx.0,
                //     sib_offset,
                //     self.parent_node(&sib_idx).0
                // );
            } else {
                // println!(
                //     "Dequeing new leaf {} (offset {}, leaf #{}) of parent {}",
                //     sib_idx.0,
                //     sib_offset,
                //     self.get_leaf_pos(&sib_idx),
                //     self.parent_node(&sib_idx).0
                // );
            }
        } else {
            // println!("Dequeing new root {}", sib_idx.0);
        }

        siblings.push((sib_offset, sib.1));

        // NOTE: the tree will be updated with this sibling's new hash later
        sib_idx
    }

    // TODO: Generate the leaf data here pseudo-randomly: e.g., for strings "abcdef|" + leaf_no
    pub fn preprocess_leaves(
        &mut self,
        updates: Vec<(usize, LeafDataType)>,
    ) -> (VecDeque<(NodeIndex, HashType)>, Duration) {
        // clear the map of nodes we hashed
        self._hashed_nodes.clear();

        // Assert that leaf updates are sorted by index
        // NOTE: debug_assert_* calls are disabled for benchmarks!
        debug_assert!((0..updates.len() - 1).all(|i| updates[i].0 <= updates[i + 1].0));

        let mut upd_queue: VecDeque<(NodeIndex, HashType)> = VecDeque::new();

        // If the tree is perfect, the last level leaf is the first leaf in 'updates'

        // Otherwise, we need to skip over the second-to-last level leaves and find it in 'updates'
        // TODO: I think this can be simplified a little
        if self.has_leaves_on_two_levels() {
            // println!("Has two levels of leaves");
            let opt = updates
                .iter()
                .position(|(leaf_pos, _)| {
                    self.is_last_level_leaf(&self.get_leaf_idx(*leaf_pos))
                });

            let first_last_level_leaf = opt.unwrap_or(0);
            // println!("updates[{}] = {} is the first last level leaf", first_last_level_leaf,
            //          updates[first_last_level_leaf].0);

            let (second_to_last, last) = updates.split_at(first_last_level_leaf);

            let start = std::time::Instant::now();

            // If there are leaves on the second-to-last level, we need to compute all updated parents
            // of the updated last level leaves, so that all updates are on the second-to-last level
            let mut tmp_queue: VecDeque<(NodeIndex, HashType)> = self._queuefy(last);
            self._process_update_queue(&mut tmp_queue, Some(&mut upd_queue));

            let duration = start.elapsed();

            // remove the last level leaves from 'updates' so we can move the remaining second-to-last
            // level leaves into the update queue
            upd_queue.append(&mut self._queuefy(second_to_last));
            // println!("Done pre-processing last level of leaves")

            (upd_queue, duration)
        } else {
            upd_queue.append(&mut self._queuefy(updates.as_slice()));
            // println!("Does NOT have two levels of leaves");

            (upd_queue, Duration::ZERO)
        }

        // TODO: Stream updates to save memory on updates vec?
        // First, we would build a queue for all
        // second-to-last leaves, and if this was actually the last level, we'd be done. If there is
        // another level of leaves, we would stream that into a different queue and then we would
        // append the first queue to this one (ideally moving it in somehow).
    }

    fn _queuefy(&mut self, upds: &[(usize, LeafDataType)]) -> VecDeque<(NodeIndex, HashType)> {
        upds.iter()
            .map(|(leaf_pos, leaf_data)| {
                let leaf_idx = self.get_leaf_idx(*leaf_pos);
                let child_offset: usize = self.child_offset(&leaf_idx);

                // NOTE: Uncomment for debugging
                debug_assert!(self.is_leaf(&leaf_idx));
                //println!("Hashing and queueing leaf idx {} (leaf #{})", leaf_idx.0, *leaf_pos);
                debug_assert!(self._hashed_nodes.insert(leaf_idx));

                (
                    leaf_idx,
                    self.hasher.hash_leaf_data(child_offset, leaf_data.clone()),
                )
            })
            .collect::<VecDeque<_>>()
    }

    pub fn update_leaves(&mut self, new_leaves: Vec<(usize, LeafDataType)>) {
        // takes care of cases where the leaves are split amongst the last and second to last level
        let (mut curr_updates, _) = self.preprocess_leaves(new_leaves);

        self._process_update_queue(&mut curr_updates, None);
    }

    pub fn update_preprocessed_leaves(&mut self, mut curr_updates: VecDeque<(NodeIndex, HashType)>) {

        self._process_update_queue(&mut curr_updates, None);
    }

    fn _process_update_queue(
        &mut self,
        dequeue: &mut VecDeque<(NodeIndex, HashType)>,
        mut enqueue_opt: Option<&mut VecDeque<(NodeIndex, HashType)>>,
    ) {
        let mut new_siblings = Vec::with_capacity(self.arity);
        let mut old_siblings: Vec<HashType> = Vec::with_capacity(self.arity);

        while !dequeue.is_empty() {
            new_siblings.clear();
            old_siblings.clear();

            // pop the first sibling off the queue
            let first_sib_idx = self.pop_sibling(dequeue, &mut new_siblings);

            // if this sibling is actually the root node, we are done
            if !first_sib_idx.is_root() {
                let parent_idx = self.parent_node(&first_sib_idx);

                // pop all other siblings off the queue
                while !dequeue.is_empty() {
                    let (potential_sib, _) = dequeue.front().unwrap();

                    // if this is an actual sibling, track it so we can use it to update the parent
                    if self.parent_node(&potential_sib) == parent_idx {
                        self.pop_sibling(dequeue, &mut new_siblings);
                    } else {
                        break;
                    }
                }

                // now we have all siblings that were updated in 'old_siblings'
                debug_assert_le!(new_siblings.len(), self.arity);

                // we always give *all* the *old* hashes of the siblings, since Merkle++ requires them
                // to speed up parent updates when more than arity/2 children are updated
                for i in 0..self.arity {
                    let child_idx = self.child_node(&parent_idx, i);
                    if let Some(opt_child_hash) = self.get_node_hash(&child_idx) {
                        // NOTE: Uncomment for debugging
                        // if !self.is_leaf(&child_idx) {
                        //     println!(
                        //         "Including old children {} (offset {}) of parent {}",
                        //         child_idx.0, i, parent_idx.0
                        //     );
                        // } else {
                        //     println!(
                        //         "Including old leaf {} (offset {}, leaf #{}) of parent {}",
                        //         child_idx.0,
                        //         i,
                        //         self.get_leaf_pos(&child_idx),
                        //         self.parent_node(&child_idx).0
                        //     );
                        // }

                        old_siblings.push(opt_child_hash);
                    } else {
                        // NOTE: Uncomment for debugging
                        // println!("Parent {} has no child #{}, breaking...", parent_idx.0, i);
                        // println!("Breaking at missing child {}. len(old_siblings) = {}", child_idx.0, old_siblings.len());

                        // If the parent has no child i, it has no children > i
                        //
                        // NOTE(Alin): It's possible for a parent on the second-to-last level, to
                        // have less than 'arity' leaves. In that case, old_siblings will have length
                        // smaller than 'arity' but so will 'new_siblings' and we won't run into
                        // problems inside 'TreeHasherFunc::hash_nodes'
                        break;
                    }
                }

                // first, compute the updated parent hash and schedule it to be processed later
                //println!("Hashing and queueing parent {}", parent_idx.0);
                debug_assert!(self._hashed_nodes.insert(parent_idx));
                let hash = self.hasher.hash_nodes(
                    self.get_node_hash(&parent_idx).unwrap(),
                    &mut old_siblings,
                    &new_siblings,
                );

                // NOTE(Alin): I did not understand why/how this 'as_deref_mut' works. Alden helped
                // convince me there is a default implementation of DerefMut for any mutable
                // reference:
                //
                //      impl<T> DerefMut for &mut T {
                //          type Target = T
                //          fn deref_mut(&mut self) -> &mut Self::Target {
                //              self
                //          }
                //      }
                //
                // Then, as_deref_mut() returns an Opt<&mut T::Target>. And we know that T::Target = T
                // even when T = &mut VecDeque like below. Therefore, as_deref_mut() just returns itself
                // without consuming itself somehow. Okay, maybe I still don't understand it.
                if let Some(enqueue) = enqueue_opt.as_deref_mut() {
                    enqueue.push_back((parent_idx, hash));
                } else {
                    dequeue.push_back((parent_idx, hash));
                }

                // second, update tree with new sibling hashes
                for (idx, hash) in &new_siblings {
                    // TODO(Perf): Recomputing child node idx
                    let child_idx = self.child_node(&parent_idx, *idx);
                    self.set_node_hash(&child_idx, hash.clone());
                }

                // end of !first_sib_idx.is_root()
            } else {
                debug_assert_eq!(new_siblings.len(), 1);

                self.set_node_hash(&NodeIndex::root_node(), new_siblings.pop().unwrap().1)
            }
        }
    }
}
