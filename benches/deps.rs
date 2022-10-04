use std::ops::Neg;
use criterion::{criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, BenchmarkId, Criterion, Throughput, BatchSize};
use curve25519_dalek_ng::constants;
use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek_ng::ristretto::{RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar;
use rand::distributions::{Alphanumeric, DistString};
use rand::thread_rng;
use sha2::Sha512;
use merkle_race::ipa_multipoint::hash_bytes_to_scalar_ng;
use merkle_race::polynomial::{poly_div, Polynomial};


fn single_exp_benches<M: Measurement>(g: &mut BenchmarkGroup<M>) {
    let mut rng = thread_rng();

    g.bench_function("scalar invert", |b| {
        let s = Scalar::random(&mut rng);
        b.iter(|| s.invert());
    });

    g.bench_function("scalar neg", |b| {
        let s = Scalar::random(&mut rng);
        b.iter(||s.neg());
    });

    g.bench_function("point to scalar hash",  |b| {
        let P = RistrettoPoint::random(&mut rng).compress();
        b.iter(|| hash_bytes_to_scalar_ng(P.as_bytes()));
    });

    g.bench_function("poly(1024) divided by poly(1)",  |b| {
        let p0 = Polynomial::rand(1024);
        let p1 = Polynomial::rand(1);
        b.iter(|| poly_div(&p0, &p1));
    });
}

pub fn func1(c: &mut Criterion) {
    let mut group = c.benchmark_group("deps");

    single_exp_benches(&mut group);

    group.finish();
}


criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = func1);
criterion_main!(benches);
