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
use once_cell::sync::Lazy;
use rand::thread_rng;

/*
what's the poly?
in a verkle tree we have f_root[0]=child0, f_root[1]=child1...
degree of f = arity of the tree.
A child is a scalar. A root is a point.
the lower root will be converted to a higher child using point to bytes to scalar hash.
so how many bits do a point take? 32
how many bits do a scalar take? 32

 */
pub type PolyFieldElement = Scalar;
pub type Commitment = RistrettoPoint;

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

pub static G: Lazy<Vec<RistrettoPoint>> = Lazy::new(|| {
    (0..1024).map(|_i|RistrettoPoint::random(&mut thread_rng())).collect()
});

pub static F: Lazy<RistrettoPoint> = Lazy::new(||RistrettoPoint::random(&mut thread_rng()));

pub static B: Lazy<RistrettoPoint> = Lazy::new(||RistrettoPoint::random(&mut thread_rng()));

pub fn gen_proof(polynomial:&Polynomial, r:&Scalar, commitment:&Commitment, x:Scalar, y:Scalar) -> LinearProof {
    let n = polynomial.degree()+1;

    // a
    let mut a: Vec<Scalar> = Vec::with_capacity(n);
    for i in 0..n {
        a[i] = polynomial.coefficient(i);
    }

    // b
    let mut b: Vec<Scalar> = Vec::with_capacity(n);
    b[0] = Scalar::one();
    for i in 1..n {
        b[i] = b[i-1]*x;
    }

    let mut transcript = Transcript::new(b"LinearProofBenchmark");

    let c = inner_product(&a, &b);
    let B_value = B.clone();
    let F_value = F.clone();
    let G_value = G.clone();

    // C = <a, G> + r * B + <a, b> * F = Commitment + <a,b>*F
    let C: CompressedRistretto = RistrettoPoint::vartime_multiscalar_mul(
        iter::once(&Scalar::one()).chain(iter::once(&c)),
        iter::once(commitment).chain(iter::once(&F_value)),
    ).compress();

    LinearProof::create(
        &mut transcript,
        &mut thread_rng(),
        &C,
        r.clone(),
        a,
        b,
        G_value,
        &F_value,
        &B_value,
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
    let g_com_r = poly_g.gen_random_factor();
    let D = poly_g.gen_commitment(&g_com_r);

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
    let g1_com_r = poly_g1.gen_random_factor();
    let g1_commitment = poly_g1.gen_commitment(&g1_com_r);

    let pi = gen_proof(&poly_g1, &g1_com_r, &g1_commitment, t, y);
    let rho = gen_proof(&poly_g, &g_com_r,&D, t, poly_g.evaluate(t));

    MultiProof {
        D,
        pi,
        y,
        rho,
    }
}


#[test]
fn test_gen_proof() {
    let poly = Polynomial::rand(1023);
    let r = poly.gen_random_factor();
    let commitment = poly.gen_commitment(&r);
    let x = Scalar::from(5_u8);
    let y = poly.evaluate(x.clone());
    let proof = gen_proof(&poly, &r, &commitment, x.clone(), y);
    println!("{proof:?}");
}
