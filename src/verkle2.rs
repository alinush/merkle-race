use rand::prelude::*;

use std::ops::AddAssign;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use rocksdb::{DB, DBWithThreadMode, Error, Options, SingleThreaded};
use serde::{Serialize, Deserialize};
use std::{sync::Mutex, collections::HashMap};
use std::hash::Hash;
use std::path::Path;
use once_cell::sync::Lazy;
use sha2::{Sha256, Sha512, Digest};

static VERKLE_ROOT_ID: Lazy<NodeId> = Lazy::new(|| {
    let mut node_id_bytes = b"verkleRoot".to_vec();
    node_id_bytes.resize(32, 0);
    node_id_bytes.as_slice().try_into().unwrap()
});


pub type Key = Vec<u8>;
pub type Val = Vec<u8>;
type NodeId = [u8; 32];
type HashValue = [u8; 32];


pub fn rand_node_id() -> NodeId {
    let mut rng = thread_rng();
    let bytes : [u8; 32] = rng.gen();
    bytes
}

pub type KeyValuePair = (Key, Val);


#[derive(Serialize, Deserialize, Debug)]
struct LeafNode {
    kvhash: RistrettoPoint,
}

#[derive(Serialize, Deserialize, Debug)]
struct NonLeafNode {
    commitment: RistrettoPoint,
    childrenIds: [Option<NodeId>; 16],
}

#[derive(Serialize, Deserialize, Debug)]
enum TreeNodePayload {
    Leaf(LeafNode),
    NonLeaf(NonLeafNode),
}

#[derive(Serialize, Deserialize, Debug)]
struct TreeNode {
    pub version: u64,
    pub node_id: NodeId,
    payload: TreeNodePayload,
}

impl TreeNode {
    pub fn bulk_update(db_handle: &DBWithThreadMode<SingleThreaded>, root_id: NodeId, sorted_key_value_pairs: &Vec<KeyValuePair>) {
        let root_encoded = db_handle.get(root_id).unwrap().unwrap();
        let root : TreeNode = serde_json::from_slice(&root_encoded).unwrap();
        match &root.payload {
            TreeNodePayload::Leaf(node) => {},
            TreeNodePayload::NonLeaf(node) => {},
        }
        //todo
    }
}

pub struct VerkleKvStore {
    metadata_db_handle: DBWithThreadMode<SingleThreaded>,
    value_db_handle: DBWithThreadMode<SingleThreaded>,
}

impl VerkleKvStore {
}

impl VerkleKvStore {
}

pub fn commit(points: &[RistrettoPoint; 16]) -> RistrettoPoint {
    let mut acc = RistrettoPoint::identity();
    for point in points {
        let P = RistrettoPoint::hash_from_bytes::<Sha512>(point.compress().as_bytes());
        acc.add_assign(P);
    }
    acc
}


impl VerkleKvStore {
    pub fn new(root_path: String) -> Result<VerkleKvStore, Error> {
        let metadata_db_handle = DB::open_default(format!("{root_path}/m")).unwrap();
        let value_db_handle = DB::open_default(format!("{root_path}/v")).unwrap();
        let points = [();16].map(|x|RistrettoPoint::identity());
        let latest_version = Self::try_get_latest_version(&metadata_db_handle);
        match latest_version {
            Some(v) => {
                Ok(
                    VerkleKvStore {
                        metadata_db_handle,
                        value_db_handle,
                    }
                )

            },
            None => {
                let root = TreeNode {
                    version: 0,
                    node_id: *VERKLE_ROOT_ID,
                    payload: TreeNodePayload::NonLeaf(NonLeafNode {
                        commitment: commit(&points),
                        childrenIds: [None; 16],
                    }),
                };
                Self::persist_verkle_tree_node(&metadata_db_handle, &root)?;
                metadata_db_handle.put(b"nextVersionIdToUse", 1_u64.to_le_bytes())?;
                metadata_db_handle.put(b"lastVersionIdGenerated", 0_u64.to_le_bytes())?;
                Ok(
                    VerkleKvStore {
                        metadata_db_handle,
                        value_db_handle,
                    }
                )
            }
        }
    }

    pub fn get_latest_version_id(&self) -> Result<u64, Error> {
        let raw_value = self.metadata_db_handle.get(b"lastVersionIdGenerated")?.unwrap();
        Ok(
            u64::from_le_bytes(
                    raw_value.as_slice()
                    .try_into()
                    .unwrap()
            )
        )
    }

    fn try_get_latest_version(metadata_db_handle:&DBWithThreadMode<SingleThreaded>) -> Option<u64> {
        metadata_db_handle.get(b"nextVersionIdToUse")
            .unwrap()
            .map_or(None, |v|Some(u64::from_le_bytes(v.as_slice().try_into().unwrap())))
    }

    // Read the value of the given key as a u64, increment it, write back, and return the old value.
    fn bump_u64<K:AsRef<[u8]>>(&self, key:K) -> Result<u64, Error> {
        let current_value = self.metadata_db_handle.get(key.as_ref())?
            .map_or(0, |x| u64::from_le_bytes(x.as_slice().try_into().unwrap()));
        let new_value = current_value + 1;
        self.metadata_db_handle.put(key.as_ref(), new_value.to_le_bytes())?;
        Ok(current_value)
    }

    // Executes the updates and returns the new version ID.
    pub fn batch_update(&self, version:u64, sorted_key_value_pairs: &Vec<KeyValuePair>) -> Result<u64, Error> {
        let new_version = self.bump_u64(b"nextVersionIdToUse")?;
        for (key,val) in sorted_key_value_pairs {
            let hash_value = self.hash_version_key(new_version, key.clone());
            self.value_db_handle.put(hash_value, val)?;
        }
        //todo: update verkle tree
        // TreeNode::bulk_update(&self.metadata_db_handle, *VERKLE_ROOT_ID, sorted_key_value_pairs);
        self.metadata_db_handle.put(b"lastVersionIdGenerated", new_version.to_le_bytes())?;
        Ok(new_version)
    }

    pub fn get(&self, version:u64, key:Key) -> Option<Val>{
        let hash_value = self.hash_version_key(version, key);
        self.value_db_handle.get(hash_value).unwrap()
    }

    fn persist_verkle_tree_node(db_handle: &DBWithThreadMode<SingleThreaded>, node: &TreeNode) -> Result<(), Error> {
        let bytes = serde_json::to_vec(node).unwrap();
        db_handle.put(&node.node_id, bytes.as_slice())
    }

    fn read_verkle_tree_node(db_handle: &DBWithThreadMode<SingleThreaded>, node_id: NodeId ) -> TreeNode {
        let bytes = db_handle.get(&node_id).unwrap().unwrap();
        serde_json::from_slice(bytes.as_slice()).unwrap()
    }

    fn hash_version_key(&self, version: u64, key:Key) -> HashValue {
        let mut input_bytes: Vec<u8> = vec![];
        input_bytes.extend_from_slice(version.to_le_bytes().as_slice());
        input_bytes.extend_from_slice(key.as_slice());
        let hash_value = Sha256::digest(input_bytes).to_vec().try_into().unwrap();
        hash_value
    }
}

#[test]
fn verkle2_basics() {
    let db = VerkleKvStore::new("/tmp/verkle-t1".to_string()).unwrap();
    let key = [0;32].to_vec();
    let val_expected = [1_u8;32].to_vec();
    let x:KeyValuePair = (key.clone(), val_expected.clone());
    let latest_version = db.get_latest_version_id().unwrap();
    println!("latest_version={latest_version}");
    let new_ver = db.batch_update(latest_version, &vec![x]).unwrap();
    let val_actual = db.get(new_ver, key);
    assert_eq!(Some(val_expected), val_actual);
}

#[test]
fn verkle2_version_increase_for_each_update() {
    let db = VerkleKvStore::new("/tmp/verkle-t2".to_string()).unwrap();
    let key1 = [0;32].to_vec();
    let val1 = [1_u8;32].to_vec();
    let key2 = [2;32].to_vec();
    let val2 = [3_u8;32].to_vec();
    let rv0 = db.get_latest_version_id().unwrap();
    let rv1 = db.batch_update(rv0, &vec![(key1,val1)]).unwrap();
    let rv2 = db.batch_update(rv1, &vec![(key2,val2)]).unwrap();
    println!("rv2={rv2}");
    assert_eq!(rv1+1, rv2);
}
