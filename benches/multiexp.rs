use std::iter::zip;
use criterion::{criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, BenchmarkId, Criterion, Throughput, BatchSize};
use rand::thread_rng;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{RistrettoPoint, VartimeRistrettoPrecomputation, VartimeRistrettoSubsetPrecomputation};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{VartimePrecomputedMultiscalarMul, VartimePrecomputedSubsetMultiscalarMul};
use rand::prelude::IteratorRandom;

fn construct_scalars(n: usize) -> Vec<Scalar> {
    let mut rng = thread_rng();
    (0..n).map(|_| Scalar::random(&mut rng)).collect()
}

fn construct_points(n: usize) -> Vec<RistrettoPoint> {
    let mut rng = thread_rng();
    (0..n)
        .map(|_| &Scalar::random(&mut rng) * &constants::RISTRETTO_BASEPOINT_TABLE)
        .collect()
}

pub fn somebases_multiexp_benchmark<M: Measurement>(
    c: &mut BenchmarkGroup<M>,
    total_size: usize,
    sample_size: usize,
) {
    c.throughput(Throughput::Elements(sample_size as u64));
    let static_points = construct_points(total_size);
    let precomp = VartimeRistrettoSubsetPrecomputation::new(&static_points);

    c.bench_with_input(
        BenchmarkId::new(total_size.to_string().as_str(), sample_size),
        &sample_size,
        |b, &sample_size| {
            b.iter_batched(
                || {
                    let non_zero = (0..total_size)
                        .choose_multiple(&mut rand::thread_rng(), sample_size);
                    let scalars = zip(non_zero,
                        construct_scalars(sample_size));

                    scalars
                },
                |scalars| {
                    let h: RistrettoPoint = precomp.vartime_subset_multiscalar_mul(scalars);
                    drop(h)
                },
                BatchSize::SmallInput,
            );
        },
    );
}

pub fn allbases_multiexp_benchmark<M: Measurement>(
    c: &mut BenchmarkGroup<M>,
    size: usize,
) {
    c.throughput(Throughput::Elements(size as u64));
    c.bench_with_input(
        BenchmarkId::from_parameter(size),
        &size,
        |b, &size| {
            let static_points = construct_points(size);
            let precomp = VartimeRistrettoPrecomputation::new(&static_points);
            b.iter_batched(
                || construct_scalars(size),
                |scalars| {
                    let h: RistrettoPoint = precomp.vartime_multiscalar_mul(scalars);
                    drop(h)
                },
                BatchSize::SmallInput,
            );
        },
    );
}

pub fn allbases_multiexp_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("allbases-multiexp");

    for size in 4..=8 {
        allbases_multiexp_benchmark(&mut group, size);
    }

    group.finish();
}


pub fn somebases_multiexp_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("somebases-multiexp");

    let total_size = 1024;
    let mut sample_size = 1;
    while sample_size <= total_size {
        somebases_multiexp_benchmark(&mut group, total_size, sample_size);
        sample_size *= 2;
    }

    group.finish();
}

criterion_group!(
    name = benches;
    //config = Criterion::default().sample_size(10);
    config = Criterion::default();
    targets = allbases_multiexp_group, somebases_multiexp_group);
criterion_main!(benches);
