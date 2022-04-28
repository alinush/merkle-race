use criterion::{criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, Criterion, Throughput};
use rand::{Rng, thread_rng};
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_TABLE};
use curve25519_dalek::scalar::Scalar;
use rust_incrhash::compressed_ristretto::CompRistBlakeIncHash;
use rust_incrhash::ristretto::RistBlakeIncHash;
use merkle_race::merkle_pp::{hash_child, MerkleppHashValue};
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

pub fn incrhash_benchmark<M: Measurement>(
    c: &mut BenchmarkGroup<M>,
) {
    let mut rng = thread_rng();

    c.throughput(Throughput::Elements(1));
    c.bench_function("incrhash", move |b| {
        let random_bytes: Vec<u8> =
            (0..32).map(|_| rng.gen::<u8>()).collect();
        let h = CompRistBlakeIncHash::from(random_bytes.as_slice());
        let hv = MerkleppHashValue::<CompRistBlakeIncHash>::Internal(h);
        let i = rng.gen::<u8>() as usize;

        b.iter(||
            hash_child::<CompRistBlakeIncHash, RistBlakeIncHash>(i, &hv)
        )
    });
}

pub fn bench_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("allbases-multiexp");

    hash_to_scalar_benchmark(&mut group);
    incrhash_benchmark(&mut group);

    group.finish();
}

criterion_group!(
    name = benches;
    //config = Criterion::default().sample_size(10);
    config = Criterion::default();
    targets = bench_group);

criterion_main!(benches);
