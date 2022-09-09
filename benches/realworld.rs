use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::sleep;
use std::time::Duration;
use criterion::{Criterion, criterion_group, criterion_main};
use merkle_race::verkle2::{Key, KeyValuePair, Val, VerkleKvStore};
use rand::{Rng, thread_rng};
use rand::distributions::{Alphanumeric, DistString};

const batch_count : usize = 10000;
fn bench_group(c: &mut Criterion) {
    c.bench_function(format!("{batch_count} bulk updates, 1000 keys in each batch").as_str(), |b| {
        //init db
        let db : VerkleKvStore = VerkleKvStore::new("/tmp/verkle/b1".to_string()).unwrap();
        //todo: grow it to
        let batches : Vec<Vec<KeyValuePair>> = ((0..batch_count).map(|x|rand_key_value_pairs(100)).collect());
        let mut target_version = db.get_latest_version_id().unwrap();
        b.iter(|| {
            for batch in batches.iter() {
                target_version = db.batch_update(target_version,&batch).unwrap();
            }
        })
    });
}

fn rand_key() -> Key {
    Alphanumeric.sample_string(&mut thread_rng(), 32).into_bytes()
}

fn rand_value() -> Val {
    Alphanumeric.sample_string(&mut thread_rng(), 128).into_bytes()
}

fn rand_key_value_pairs(count: usize) -> Vec<KeyValuePair> {
    (0..count).map(|x|(rand_key(),rand_value())).collect()
}


criterion_group!(
    name = benches;
    //config = Criterion::default().sample_size(10);
    config = Criterion::default();
    targets = bench_group);

criterion_main!(benches);
