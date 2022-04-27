use criterion::{criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, Criterion, Throughput};
use rand::thread_rng;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_TABLE};
use curve25519_dalek::scalar::Scalar;
use merkle_race::verkle::hash_to_scalar;
use merkle_race::verkle_ristretto::CompressedRistretto;

pub fn hash_to_scalar_benchmark<M: Measurement>(
    c: &mut BenchmarkGroup<M>,
) {
    let mut rng = thread_rng();

    c.throughput(Throughput::Elements(1));
    c.bench_function("hash_to_scalar", move |b| {
        let p = CompressedRistretto((&RISTRETTO_BASEPOINT_TABLE * &Scalar::random(&mut rng)).compress());
        b.iter(||
            hash_to_scalar(&p)
        )
    });
}

pub fn bench_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("allbases-multiexp");

    hash_to_scalar_benchmark(&mut group);

    group.finish();
}

criterion_group!(
    name = benches;
    //config = Criterion::default().sample_size(10);
    config = Criterion::default();
    targets = bench_group);

criterion_main!(benches);
