use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use criterion::{Criterion, criterion_group, criterion_main};
use merkle_race::verkle2::{UserKey, UserKeyValuePair, NaiveVerkleIO, UserValue, VerkleKvStore};
use rand::{Rng, thread_rng};
use rand::distributions::{Alphanumeric, DistString};

const batch_count : usize = 100;
const batch_size : usize = 1000;
fn bench_group(c: &mut Criterion) {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    println!("ts={ts}");
    c.bench_function(format!("{batch_count} bulk updates, {batch_size} keys in each batch").as_str(), |b| {
        //init db
        let mut x = NaiveVerkleIO::new(format!("/tmp/verkledbs/{ts}").as_str());
        let mut db = VerkleKvStore::new(&mut x, 16);
        //todo: grow it to
        let batches : Vec<Vec<UserKeyValuePair>> = ((0..batch_count).map(|x|rand_key_value_pairs(batch_size)).collect());
        let mut target_version = db.get_latest_version_id();
        b.iter(|| {
            for batch in batches.iter() {
                target_version = db.batch_update(target_version,&batch);
            }
        })
    });
}

fn rand_key() -> UserKey {
    Alphanumeric.sample_string(&mut thread_rng(), 32).into_bytes()
}

fn rand_value() -> UserValue {
    Alphanumeric.sample_string(&mut thread_rng(), 256).into_bytes()
}

fn rand_key_value_pairs(count: usize) -> Vec<UserKeyValuePair> {
    let pairs = (0..count).map(|x|(rand_key(),rand_value())).collect();
    pairs
}


criterion_group!(
    name = benches;
    //config = Criterion::default().sample_size(10);
    config = Criterion::default();
    targets = bench_group);

criterion_main!(benches);
