use rand::prelude::*;
use bitvec::prelude::*;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use rocksdb::{DB, DBWithThreadMode, Options, SingleThreaded};
use serde::{Serialize, Deserialize};
use std::{sync::Mutex, collections::HashMap};
use std::borrow::Borrow;
use std::error::Error;
use std::hash::Hash;
use std::ops::{Add, AddAssign, SubAssign};
use std::path::Path;
use bitvec::macros::internal::funty::Fundamental;
use curve25519_dalek::scalar::Scalar;
use more_asserts::assert_ge;
use once_cell::sync::Lazy;
use sha2::{Sha256, Sha512, Digest};
use crate::ipa_multipoint::{Commitment, gen_multipoint_proof, PolyFieldElement};
use crate::polynomial::Polynomial;

pub type UserKey = Vec<u8>;
pub type UserValue = Vec<u8>;
type NodeId = [u8; 32];
type HashValue = [u8; 32];

pub fn rand_node_id() -> NodeId {
    let mut rng = thread_rng();
    let bytes : [u8; 32] = rng.gen();
    bytes
}

pub trait VerkleIO {
    fn write_tree_node(&mut self, node:&TreeNode);
    fn put_prop(&mut self, key: &[u8], value:&[u8]);
    fn put_prop_u64(&mut self, key: &[u8], value: u64);
    fn get_prop(&mut self, key: &[u8]) -> Option<Vec<u8>>;
    fn get_prop_u64(&mut self, key: &[u8]) -> Option<u64>;
    fn read_tree_node(&mut self, key: NodeId) -> Option<TreeNode>;
}

pub struct NaiveVerkleIO {
    db_handle: DBWithThreadMode<SingleThreaded>,
}

impl NaiveVerkleIO {
    pub fn new(path: &str) -> Self {
        let db_handle = DB::open_default(path).unwrap();
        NaiveVerkleIO {
            db_handle
        }
    }
}

#[test]
fn sedes() {
    let mut rng = ThreadRng::default();
    let node = TreeNode {
        version: 2,
        node_id: rand_node_id(),
        payload: TreeNodePayload::NonLeaf(NonLeafPayload {
            commitment: RistrettoPoint::random(&mut rng),
            children_ids: vec![Some(rand_node_id()), None, None, Some(rand_node_id())],
        }),
    };

    let s = serde_json::to_string(&node).unwrap();
    println!("s={s:?}");
    let encoded = s.as_bytes().to_vec();
    let decoded = serde_json::from_slice(encoded.as_slice()).unwrap();
    assert_eq!(node, decoded);

}

impl VerkleIO for NaiveVerkleIO {
    fn write_tree_node(&mut self, node: &TreeNode) {
        self.db_handle.put(node.node_id, serde_json::to_string(node).unwrap()).unwrap()
    }

    fn put_prop(&mut self, key: &[u8], value: &[u8]) {
        self.db_handle.put(key, value).unwrap()
    }

    fn put_prop_u64(&mut self, key: &[u8], value: u64) {
        self.db_handle.put(key, value.to_le_bytes().as_slice()).unwrap()
    }

    fn get_prop(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.db_handle.get(key).unwrap()
    }

    fn get_prop_u64(&mut self, key: &[u8]) -> Option<u64> {
        self.db_handle.get(key).unwrap().map(|val|u64::from_le_bytes(val.as_slice().try_into().unwrap()))
    }

    fn read_tree_node(&mut self, key: NodeId) -> Option<TreeNode> {
        let raw = self.db_handle.get(key).unwrap();
        raw.map(|r| serde_json::from_slice(r.as_slice()).unwrap())
    }
}
pub type UserKeyValuePair = (UserKey, UserValue);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LeafPayload {
    pub kvhash: RistrettoPoint,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct NonLeafPayload {
    pub commitment: RistrettoPoint,
    pub children_ids: Vec<Option<NodeId>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum TreeNodePayload {
    Leaf(LeafPayload),
    NonLeaf(NonLeafPayload),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TreeNode {
    pub version: u64,
    pub node_id: NodeId,
    pub payload: TreeNodePayload,
}

fn msb_to_u64(bits: &BitSlice) -> u64 {
    let mut ret = 0_u64;
    for bit in bits {
        ret = ret*2+bit.as_u64();
    }
    ret
}
#[test]
fn test_msb_to_u64() {
    let bits = bitvec![1,0,0,0,0];
    let actual = msb_to_u64(bits.as_bitslice());
    assert_eq!(16, actual);
}

fn get_digest(node:&Option<TreeNode>) -> RistrettoPoint {
    match node {
        None => {RistrettoPoint::identity()}
        Some(x) => {
            x.get_digest()
        }
    }
}

fn get_new_prefix(old:&BitSlice, patch_len:usize, branch_id:usize) -> BitVec {
    let mut new_prefix = old.to_bitvec();
    let mut prefix_patch = branch_id.view_bits::<Lsb0>().to_bitvec();
    prefix_patch.resize(patch_len as usize, false);
    prefix_patch.reverse();
    new_prefix.extend_from_bitslice(prefix_patch.as_bitslice());
    new_prefix
}

#[test]
fn test_get_new_prefix() {
    let bits = bitvec![1,1,1,1,1];
    let actual = get_new_prefix(bits.as_bitslice(), 5, 1);
    assert_eq!(bitvec![1,1,1,1,1,0,0,0,0,1], actual);
}

impl TreeNode {
    fn get_digest(&self) -> RistrettoPoint {
        match self.payload.clone() {
            TreeNodePayload::Leaf(x) => {
                x.kvhash
            }
            TreeNodePayload::NonLeaf(x) => {
                x.commitment
            }
        }
    }
    fn get_children(&self) -> Vec<Option<NodeId>> {
        match self.payload.clone() {
            TreeNodePayload::Leaf(x) => {
                unimplemented!()
            }
            TreeNodePayload::NonLeaf(x) => {
                x.children_ids.clone()
            }
        }
    }
    pub fn bulk_update(
        key_size_in_bit: usize,
        cur_prefix: &BitSlice,
        fanout : usize,
        io: &mut dyn VerkleIO,
        new_version:u64,
        cur: Option<&TreeNode>,
        sorted_key_hashes: &[&BitSlice],
        sorted_kvpair_hashes: &[&BitSlice],
    ) -> Option<TreeNode> {
        assert_eq!(sorted_key_hashes.len(), sorted_kvpair_hashes.len());
        assert_ge!(sorted_key_hashes.len(), 1);
        assert!(sorted_key_hashes[0].starts_with(cur_prefix) && sorted_key_hashes[sorted_key_hashes.len()-1].starts_with(cur_prefix));
        let prefix_patch_len = fanout.trailing_zeros();
        let i_am_leaf = cur_prefix.len() == key_size_in_bit;
        let new_node = if i_am_leaf {
            assert_eq!(sorted_key_hashes.len(), 1);
            TreeNode {
                version: new_version,
                node_id: rand_node_id(),
                payload: TreeNodePayload::Leaf(LeafPayload {
                    kvhash: RistrettoPoint::hash_from_bytes::<Sha512>(sorted_kvpair_hashes[sorted_kvpair_hashes.len()-1].to_string().as_bytes()),
                })
            }
        } else {
            let mut child_ids = cur.map_or(Vec::with_capacity(fanout as usize), |x|x.get_children());
            let mut new_digest = cur.map_or(RistrettoPoint::identity(), |x|x.get_digest());
            let mut new_child_ids = Vec::with_capacity(fanout as usize);
            let mut ptr = 0;
            for cid in 0..fanout {
                let mut new_prefix = get_new_prefix(cur_prefix, prefix_patch_len as usize, cid as usize);
                let start= ptr;
                while ptr<sorted_key_hashes.len() && msb_to_u64(&sorted_key_hashes[ptr][cur_prefix.len()..(cur_prefix.len()+(prefix_patch_len as usize))])< (cid + 1) as u64 {
                    ptr+=1;
                }
                new_child_ids[cid] = child_ids[cid];
                if start < ptr {
                    let child_node_id = child_ids[cid];
                    let child = child_node_id.map_or(None, |id|io.read_tree_node(id));
                    let new_child = TreeNode::bulk_update(key_size_in_bit, new_prefix.as_bitslice(), fanout, io, new_version, child.as_ref(), &sorted_key_hashes[start..ptr], &sorted_kvpair_hashes[start..ptr]);
                    new_digest.add_assign(get_digest(&new_child)-get_digest(&child));
                    new_child_ids[cid] = new_child.map_or(child_ids[cid], |x|Some(x.node_id));
                }
            }
            TreeNode {
                version: new_version,
                node_id: rand_node_id(),
                payload: (TreeNodePayload::NonLeaf(NonLeafPayload { commitment: new_digest, children_ids: new_child_ids }))
            }
        };
        io.write_tree_node(&new_node);
        Some(new_node)
    }
}

// fn read_digest(db_handle:&DbHandle, nid:NodeId) -> Option<RistrettoPoint> {
//     let mut key:Vec<u8> = vec![];
//     key.extend_from_slice(b"digestOf");
//     key.extend_from_slice(&nid);
//     let val = db_handle.get(key).unwrap().map(|val|RistrettoPoint::hash_from_bytes::<Sha512>(val.as_slice()));
//     val
// }

static VERKLE_ROOT_ID: Lazy<NodeId> = Lazy::new(|| {
    let mut node_id_bytes = b"verkleRoot".to_vec();
    node_id_bytes.resize(32, 0);
    node_id_bytes.as_slice().try_into().unwrap()
});

pub struct VerkleKvStore<'a> {
    io: &'a mut dyn VerkleIO,
    fanout: usize,
}

type Proof = Vec<u8>;


impl<'a> VerkleKvStore<'a> {
    pub fn new(io: &'a mut (dyn VerkleIO + 'a), fanout: usize) -> Self {
        let latest_version = io.get_prop_u64(b"metadata/lastVersionIdCommitted");
        match latest_version {
            Some(_v) => {
                let stored_fanout = io.get_prop_u64(b"metadata/fanout").unwrap() as usize;
                assert_eq!(fanout, stored_fanout);
                VerkleKvStore {
                    io,
                    fanout,
                }
            },
            None => {
                let root = TreeNode {
                    version: 0,
                    node_id: *VERKLE_ROOT_ID,
                    payload: TreeNodePayload::NonLeaf(NonLeafPayload {
                        commitment: RistrettoPoint::identity(),
                        children_ids: vec![None; fanout],
                    }),
                };
                io.write_tree_node(&root);
                io.put_prop_u64(b"metadata/nextVersionIdToUse", 1_u64);
                io.put_prop_u64(b"metadata/lastVersionIdCommitted", 0_u64);
                io.put_prop_u64(b"metadata/fanout", fanout as u64);
                VerkleKvStore {
                    io,
                    fanout,
                }
            }
        }
    }

    pub fn get_latest_version_id(&mut self) -> u64 {
        self.io.get_prop_u64(b"metadata/lastVersionIdCommitted").unwrap()
    }

    // Executes the updates and returns the new version ID.
    pub fn batch_update(&mut self, version:u64, key_value_pairs: &[UserKeyValuePair]) -> u64 {
        let new_version = self.io.get_prop_u64(b"metadata/nextVersionIdToUse").unwrap();
        let mut vkh_kvh_pairs: Vec<(BitVec, BitVec)> = Vec::new();
        for (key,val) in key_value_pairs {
            let version_key_hash = self.hash_version_key(new_version, key.clone());
            let version_key_hash_bv = bytes_to_bits(version_key_hash.as_slice());
            self.io.put_prop(version_key_hash.as_slice(), val);
            let key_value_hash: BitVec = self.hash_key_value(key, val);
            vkh_kvh_pairs.push((version_key_hash_bv, key_value_hash));
        }
        vkh_kvh_pairs.sort();

        let mut sorted_key_hashes = Vec::with_capacity(key_value_pairs.len());
        let mut sorted_key_value_pairs = Vec::with_capacity(key_value_pairs.len());
        for i in 0..key_value_pairs.len() {
            sorted_key_hashes[i] = vkh_kvh_pairs[i].0.as_bitslice();
            sorted_key_value_pairs[i] = vkh_kvh_pairs[i].1.as_bitslice();
        }
        let raw = self.io.get_prop(format!("roots/{version}").as_bytes());
        if raw == None {
            panic!("do not know such version: {version}");
        }
        let root_id = raw.unwrap();
        let node = self.io.read_tree_node(root_id.try_into().unwrap());
        assert!(node.is_some());
        let bs: BitVec = bitvec![];
        TreeNode::bulk_update(
            256,
            bs.as_bitslice(),
            self.fanout,
            self.io,
            new_version,
            node.as_ref(),
            sorted_key_hashes.as_slice(),
            sorted_key_value_pairs.as_slice(),
        );
        self.io.put_prop_u64(b"metadata/lastVersionIdCommitted", new_version);
        new_version
    }

    pub fn get(&mut self, version:u64, key: UserKey) -> Option<UserValue> {
        let hash_value = self.hash_version_key(version, key);
        self.io.get_prop(hash_value.as_slice())
    }

    pub fn get_proof(&mut self, version:u64, keys: Vec<UserKey>) -> Proof {
        let nodes: Vec<TreeNode> = vec![];
        let commitments: Vec<Commitment> = vec![];
        let polynomials: Vec<Polynomial> = vec![];//poly_i(path_i)=y_values[i]
        let z_values: Vec<PolyFieldElement> = vec![];//segmented path
        let y_values: Vec<PolyFieldElement> = vec![];//commit[1..-1]
        let proof = gen_multipoint_proof(&commitments, &polynomials, &z_values, &y_values);
        /*

         */
        unimplemented!();
    }

    fn hash_version_key(&self, version: u64, key: UserKey) -> HashValue {
        let mut input_bytes: Vec<u8> = vec![];
        input_bytes.extend_from_slice(version.to_le_bytes().as_slice());
        input_bytes.extend_from_slice(key.as_slice());
        let hash_value = Sha256::digest(input_bytes).to_vec().try_into().unwrap();
        hash_value
    }

    fn hash_key_value(&self, key: &UserKey, val: &UserValue) -> BitVec {
        todo!()
    }
}

fn bytes_to_bits(p0: &[u8]) -> BitVec {
    unimplemented!()
}
//
// #[test]
// fn verkle2_basics() {
//     let db = VerkleKvStore::new("/tmp/verkle-t1".to_string()).unwrap();
//     let key = [0;32].to_vec();
//     let val_expected = [1_u8;32].to_vec();
//     let x:KeyValuePair = (key.clone(), val_expected.clone());
//     let latest_version = db.get_latest_version_id().unwrap();
//     println!("latest_version={latest_version}");
//     let new_ver = db.batch_update(latest_version, &vec![x]).unwrap();
//     let val_actual = db.get(new_ver, key);
//     assert_eq!(Some(val_expected), val_actual);
// }
//
// #[test]
// fn verkle2_version_increase_for_each_update() {
//     let db = VerkleKvStore::new("/tmp/verkle-t2".to_string()).unwrap();
//     let key1 = [0;32].to_vec();
//     let val1 = [1_u8;32].to_vec();
//     let key2 = [2;32].to_vec();
//     let val2 = [3_u8;32].to_vec();
//     let rv0 = db.get_latest_version_id().unwrap();
//     let rv1 = db.batch_update(rv0, &vec![(key1,val1)]).unwrap();
//     let rv2 = db.batch_update(rv1, &vec![(key2,val2)]).unwrap();
//     println!("rv2={rv2}");
//     assert_eq!(rv1+1, rv2);
// }


// fn binsearch(left:usize, right:usize, f:&dyn Fn(usize) -> bool) -> (usize,usize) {
//     let mut li = left;
//     let mut ri = right;
//     while li+1<ri {
//         let mi = (li+ri)/2;
//         if f(mi) {
//             ri = mi;
//         } else {
//             li = mi;
//         }
//     }
//     (li,ri)
// }


#[test]
fn bits() {
    let x = 8_u8;
    let mut y = x.view_bits::<Lsb0>().to_bitvec();
    println!("{y}");
    y.resize(4, false);
    println!("{y}");
}

#[test]
fn ec() {
    let mut rng = thread_rng();
    let i = RistrettoPoint::hash_from_bytes::<Sha512>(b"qwer");
    let j = RistrettoPoint::hash_from_bytes::<Sha512>(b"asdf");

    let x = Scalar::random(&mut rng);
    let k = x*i;
    let ic = i.compress();
    // let jc = j.compress();
    // let kc = ic+jc;
    println!("ic={ic:?}");
    println!("x={x:?}");

}