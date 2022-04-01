use more_asserts::{assert_ge, assert_lt};
use std::fmt::{Debug, Formatter};

// There are (n-1) / (k-1) internal nodes and n leaves.
// We use a node index, i.e., a number from 0 to [(n - 1) / (k - 1) + n] - 1 to refer to any node (internal or leaf.)
#[derive(Copy, Clone, PartialEq)]
pub struct NodeIndex(pub(crate) usize);

impl NodeIndex {
    pub(crate) fn root_node() -> NodeIndex {
        NodeIndex(0)
    }
    // returns true if this node is the root
    pub(crate) fn is_root(&self) -> bool {
        self.0 == 0
    }

    // returns this node's child offset; i.e., its position i relative to its parent, where i \in [0, arity)
    pub(crate) fn child_offset(&self, arity: usize) -> usize {
        if self.is_root() {
            0
        } else {
            self.0 % arity
        }
    }

    // returns the parent's NodeIndex
    pub(crate) fn parent(&self, arity: usize) -> Self {
        assert_ne!(self.0, 0); // the root has no parent

        NodeIndex((self.0 - 1) / arity)
    }

    // returns the NodeIndex of the ith child, where i \in [0, arity)
    pub(crate) fn child(&self, arity: usize, i: usize) -> Self {
        assert_lt!(i, arity);
        assert_ge!(i, 0);

        NodeIndex(self.0 * arity + (i + 1))
    }

    // pub(crate) fn next_sibling(&self) -> Self {
    //     NodeIndex(self.0 + 1)
    // }

    // returns true if this node is a sibling of 'other'
    // fn is_sibling(&self, arity: usize, other: &NodeIndex) -> bool {
    //     self.parent(arity) == other.parent(arity)
    // }

    // returns the level i of the node: root is at level 0
    // i.e., level i has k^i nodes
    //fn level(&self, arity: usize) -> usize {
    //  TODO: for k = 2, compute floor(log_2(node + 1))
    //  ...but for k > 2 need to account for k (see figure above)
    //}
}

impl Debug for NodeIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
