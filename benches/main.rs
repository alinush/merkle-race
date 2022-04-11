use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, BenchmarkId,
    Criterion, Throughput,
};
use itertools::Itertools;
use merkle_race::max_leaves;
use merkle_race::merkle_crhf::new_merkle_sha3_256_from_height;
use more_asserts::assert_le;
use rand::{distributions::Alphanumeric, Rng};
use std::iter::zip;

const LEAF_LENGTH: usize = 32 + 64;

pub fn merkle_sha3_benchmark<M: Measurement>(
    c: &mut BenchmarkGroup<M>,
    arity: usize,
    height: usize,
    num_updates: usize,
) {
    let max_leaves = max_leaves(arity, height);

    let mut merkle = new_merkle_sha3_256_from_height(arity, height);

    let name_prefix = format!("arity-{}/height-{}", arity, height);

    c.throughput(Throughput::Elements(num_updates as u64));
    c.bench_with_input(
        //BenchmarkId::new("arity-".to_string() + arity.to_string().as_str() + "/height-" + height.to_string().as_str(),num_updates),
        BenchmarkId::new(name_prefix, num_updates),
        &num_updates,
        |b, &num_updates| {
            let updates: Vec<(usize, String)> = zip(
                (0..num_updates)
                    .map(|_| rand::thread_rng().gen_range(0..max_leaves))
                    .sorted()
                    .collect::<Vec<usize>>(),
                (0..num_updates)
                    .map(|_| {
                        rand::thread_rng()
                            .sample_iter(&Alphanumeric)
                            .take(LEAF_LENGTH)
                            .map(char::from)
                            .collect()
                    })
                    .collect::<Vec<String>>(),
            )
            .collect::<Vec<(usize, String)>>();
            assert_le!(num_updates, merkle.num_leaves());

            b.iter(|| merkle.update_leaves(&updates));
        },
    );
}

pub fn merkle_sha3_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_sha3");

    //merkle_sha3_benchmark(&mut group, 2, 10, 100);
    merkle_sha3_benchmark(&mut group, 2, 28, 100000);

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = merkle_sha3_group);
criterion_main!(benches);
