use std::cmp::max;
use std::collections::btree_map::OccupiedEntry;
use std::collections::BTreeMap;
use std::ops::Neg;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar;
use rand::thread_rng;

#[derive(Clone)]
pub struct Polynomial {
    degree: usize,
    coefficients: BTreeMap<usize,Scalar>,
}

impl Polynomial {
    pub fn rand(degree: usize) -> Self {
        Self {
            degree,
            coefficients: (0..degree).map(|i|(i,Scalar::random(&mut thread_rng()))).collect(),
        }
    }

    pub fn zero() -> Self {
        Self {
            degree: 0,
            coefficients: BTreeMap::new(),
        }
    }

    pub fn is_zero(&self) -> bool {
        for (deg, coe) in self.coefficients.iter() {
            if Scalar::zero().eq(coe) {
                return false;
            }
        }
        true
    }

    pub fn coefficient(&self, deg: usize) -> Scalar {
        self.coefficients.get(&deg).map_or(Scalar::zero(), |y|y.clone())
    }

    pub fn degree(&self) -> usize {
        self.degree
    }

    pub fn add_clause(&mut self, degree: usize, coefficient: &Scalar) {
        self.degree = max(self.degree, degree);
        self.coefficients.entry(degree).and_modify(|v| *v+=*coefficient).or_insert(*coefficient);
        self.prune_zeros_update_degree();
    }

    pub fn mul_scalar(&mut self, k: &Scalar) {
        for (_d,c) in self.coefficients.iter_mut() {
            (*c) *= k;
        }
        self.prune_zeros_update_degree();
    }

    pub fn add(&mut self, another: &Self) {
        for (deg,coe) in another.coefficients.iter() {
            self.add_clause(*deg, coe);
        }
        self.prune_zeros_update_degree();
    }

    pub fn neg(&mut self) {
        for (deg, coe) in self.coefficients.iter_mut() {
            *coe = coe.neg();
        }
    }

    fn prune_zeros_update_degree(&mut self) {
        let mut new_degree = None;
        loop {
            let entry = self.coefficients.iter().rev().next();
            let (key_found, should_delete) = match entry {
                Some((deg,coef)) => {
                    (Some(deg.clone()), Scalar::zero().eq(&coef))
                }
                None => {
                    (None, false)
                }
            };

            if key_found.is_none() {
                break;
            }

            let k = key_found.unwrap();
            if should_delete {
                self.coefficients.remove(&k);
            } else {
                new_degree = Some(k);
                break;
            }
        }

        self.degree = new_degree.unwrap_or(0);
    }

    pub fn evaluate(&self, x:Scalar) -> Scalar {
        let mut ret = Scalar::zero();
        let mut running_pow = Scalar::one();
        let mut last_deg: usize = 0;
        for (deg,coe) in self.coefficients.iter() {
            for i in last_deg..*deg {
                running_pow *= x;
            }
            last_deg = *deg;
            ret += coe*running_pow;
        }
        ret
    }

    pub fn gen_commitment(&self) -> RistrettoPoint {
        unimplemented!()
        //todo: RistrettoPoint::multiscalar_mul();
    }
}

pub fn poly_mul(a:&Polynomial, b:&Polynomial) -> Polynomial {
    let mut ret = Polynomial::zero();
    for (d1,c1) in a.coefficients.iter() {
        for (d2,c2) in b.coefficients.iter() {
            ret.add_clause(d1+d2, &(c1*c2));
        }
    }
    ret
}

pub fn poly_div(a:&Polynomial, b:&Polynomial) -> (Polynomial, Polynomial) {
    let mut q = Polynomial::zero();
    let mut r = a.clone();
    while r.degree() >= b.degree() {
        let mut seg = Polynomial::zero();
        let coef = r.coefficient(r.degree())*b.coefficient(b.degree()).invert();
        seg.add_clause(r.degree()-b.degree(), &coef);
        let mut offsetter = poly_mul(&seg, &b);
        offsetter.neg();
        r.add(&offsetter);
        q.add(&seg);
    }
    (q,r)
}

#[test]
fn poly() {
    let mut p0 = Polynomial::zero();
    p0.add_clause(1, &Scalar::from(3_u64));
    p0.add_clause(0, &Scalar::from(1_u64));
    //p0(x)=3x+1

    assert_eq!(Scalar::from(16_u64), p0.evaluate(Scalar::from(5_u64)));
    assert_eq!(Scalar::from(28_u64), p0.evaluate(Scalar::from(9_u64)));

    let mut p0b = p0.clone();
    p0b.add_clause(0, &Scalar::one());
    //p0b(x)=3x+2

    let p1 = poly_mul(&p0, &p0b);//9xx+9x+2
    assert_eq!(Scalar::from(110_u64), p1.evaluate(Scalar::from(3_u64)));

    let mut p0c = p0b.clone();
    p0c.add_clause(0, &Scalar::one());//3x+3

    let mut p2 = poly_mul(&p1, &p0c);//(3x+1)(3x+2)(3x+3)
    assert_eq!(Scalar::from(1320_u64), p2.evaluate(Scalar::from(3_u64)));

    p2.add_clause(0, &Scalar::one());
    p2.add_clause(1, &Scalar::one());
    //(3x+1)(3x+2)(3x+3)+x+1

    let mut divisor = Polynomial::zero();
    divisor.add_clause(2, &Scalar::from(9_u64));
    divisor.add_clause(1, &Scalar::from(12_u64));
    divisor.add_clause(0, &Scalar::from(3_u64));
    //divisor=9xx+12x+3

    let (q,r) = poly_div(&p2, &divisor);
    //q(x)=3x+2
    //r(x)=x+1
    assert_eq!(Scalar::from(2_u64), q.evaluate(Scalar::zero()));
    assert_eq!(Scalar::from(5_u64), q.evaluate(Scalar::one()));
    assert_eq!(Scalar::from(1_u64), r.evaluate(Scalar::zero()));
    assert_eq!(Scalar::from(2_u64), r.evaluate(Scalar::one()));
}
