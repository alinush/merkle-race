use bulletproofs::{BulletproofGens, LinearProof, PedersenGens};
use std::ops::{AddAssign, Div, Mul, Neg};
use crate::polynomial::{poly_div, Polynomial};
use core::iter;
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek::scalar::Scalar as Scalar0;
use curve25519_dalek_ng::traits::VartimeMultiscalarMul;
use merlin::Transcript;
use sha2::Sha512;

/*
what's the poly?
in a verkle tree we have f_root[0]=child0, f_root[1]=child1...
degree of f = arity of the tree.
A child is a scalar. A root is a point.
the lower root will be converted to a higher child using point to bytes to scalar hash.
so how many bits do a point take? 32
how many bits do a scalar take? 32

 */
type PolyFieldElement = Scalar;
type Commitment = RistrettoPoint;

type SingleProof = LinearProof;

fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    let mut out = Scalar::zero();
    if a.len() != b.len() {
        panic!("inner_product(a,b): lengths of vectors do not match");
    }
    for i in 0..a.len() {
        out += a[i] * b[i];
    }
    out
}

//Dependency shit.
pub fn hash_bytes_to_scalar_ng(bytes: &[u8]) -> Scalar {
    let v0 = Scalar0::hash_from_bytes::<Sha512>(bytes);
    Scalar::from_bits(v0.to_bytes())
}

pub fn gen_proof(polynomial: &Polynomial, x: Scalar, y: Scalar) -> LinearProof {
    let mut rng = rand::thread_rng();
    let n = 1024_usize;
    let bp_gens = BulletproofGens::new(n, 1);
    // Calls `.G()` on generators, which should be a pub(crate) function only.
    // For now, make that function public so it can be accessed from benches.
    // We don't want to use bp_gens directly because we don't need the H generators.
    let G: Vec<RistrettoPoint> = bp_gens.share(0).G(n).cloned().collect();

    let pedersen_gens = PedersenGens::default();
    let F = pedersen_gens.B;
    let B = pedersen_gens.B_blinding;

    // a and b are the vectors for which we want to prove c = <a,b>
    let a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    let b: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

    let mut transcript = Transcript::new(b"LinearProofBenchmark");

    // C = <a, G> + r * B + <a, b> * F
    let r: Scalar = Scalar::random(&mut rng);
    let c = inner_product(&a, &b);
    let C: CompressedRistretto = RistrettoPoint::vartime_multiscalar_mul(
        a.iter().chain(iter::once(&r)).chain(iter::once(&c)),
        G.iter().chain(iter::once(&B)).chain(iter::once(&F)),
    )
        .compress();

    LinearProof::create(
        &mut transcript,
        &mut rng,
        &C,
        r,
        a.clone(),
        b.clone(),
        G.clone(),
        &F,
        &B,
    )
}

pub struct MultiProof {
    D: Commitment,
    pi: SingleProof,
    y: Scalar,
    rho: SingleProof,
}

pub fn gen_multipoint_proof(
    commitments: &Vec<Commitment>,
    polynomials: &Vec<Polynomial>,
    z_values: &Vec<PolyFieldElement>,
    y_values: &Vec<PolyFieldElement>,
) -> MultiProof {
    assert_eq!(polynomials.len(), z_values.len());
    assert_eq!(y_values.len(), z_values.len());
    let n = polynomials.len();

    let r_base = hash_bytes_to_scalar_ng(format!("{commitments:?},{z_values:?},{y_values:?}").as_bytes());

    let mut r_values = Vec::with_capacity(n);
    r_values[0] = r_base;
    for i in 1..n {
        r_values[i] = r_values[i-1] * r_base;
    }

    let mut poly_g = Polynomial::zero();
    for i in 0..n {
        let mut numerator = polynomials[i].clone();
        numerator.add_clause(0, &y_values[i].neg());
        let mut denominator = Polynomial::zero();
        denominator.add_clause(1, &Scalar::one());
        denominator.add_clause(0, &z_values[i]);
        let (mut quotient, reminder) = poly_div(&numerator, &denominator);
        assert!(reminder.is_zero());
        quotient.mul_scalar(&r_values[i]);
        poly_g.add(&quotient);
    }
    let D = poly_g.gen_commitment();
    let dc = D.compress();

    let t = hash_bytes_to_scalar_ng(format!("{r_base:?},{dc:?}").as_bytes());

    let mut poly_g1 = Polynomial::zero();
    for i in 0..n {

        let mut item = polynomials[i].clone();
        let k = (t-z_values[i]).invert()*r_values[i];
        item.mul_scalar(&k);
        poly_g1.add(&item);
    }

    let y = poly_g1.evaluate(t);
    let pi = gen_proof(&poly_g1, t, y);
    let rho = gen_proof(&poly_g, t, poly_g.evaluate(t));

    MultiProof {
        D,
        pi,
        y,
        rho,
    }
}


#[test]
fn t1() {
    let mut x = Scalar::one();
    let b = Scalar::one()+Scalar::one();
    let mut i = 0;
    for i in 0..500 {
        x *= b;
        println!("i={i}, x={x:?}");
    }
}
