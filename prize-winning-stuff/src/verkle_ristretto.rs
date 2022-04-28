use std::borrow::Borrow;
use std::fmt::{Display, Formatter};
use std::ops::{Add, AddAssign, Mul};
use curve25519_dalek::ristretto::{
    CompressedRistretto as DalekComprRistrPoint,
    RistrettoPoint as DalekRistrPoint,
    VartimeRistrettoSubsetPrecomputation as DalekVartimeRistrettoSubsetPrecomputation,
    RistrettoBasepointTable as DalekRistrBasepointTable,
};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, VartimePrecomputedSubsetMultiscalarMul};
use serde::Serialize;

// TODO(Alin): I could not figure out a better way than to wrap all the Ristretto things from
// curve25519-dalek in order to generically enable adding fast points to compressed points inside
// the VerkleHasher in verkle.rs

#[derive(Clone, Default, Serialize)]
pub struct RistrettoPoint(pub DalekRistrPoint);

// impl Deref for RistrettoPoint {
//     type Target = DalekRistrPoint;
//
//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }

#[derive(Clone, Default, Serialize)]
pub struct CompressedRistretto(pub DalekComprRistrPoint);

// impl Deref for CompressedRistretto {
//     type Target = DalekComprRistrPoint;
//
//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }

pub struct VartimeRistrettoSubsetPrecomputation(pub DalekVartimeRistrettoSubsetPrecomputation);

#[derive(Clone)]
pub struct RistrettoBasepointTable(pub DalekRistrBasepointTable);

impl Identity for RistrettoPoint {
    fn identity() -> Self {
        RistrettoPoint(DalekRistrPoint::identity())
    }
}

impl Identity for CompressedRistretto {
    fn identity() -> Self {
        CompressedRistretto(DalekComprRistrPoint::identity())
    }
}

impl VartimePrecomputedSubsetMultiscalarMul for VartimeRistrettoSubsetPrecomputation {
    type Point = RistrettoPoint;

    fn new<I>(static_points: I) -> Self
        where
            I: IntoIterator,
            I::Item: Borrow<Self::Point>
    {
        Self(DalekVartimeRistrettoSubsetPrecomputation::new(static_points.into_iter().map(|p| p.borrow().0)))
    }

    fn vartime_subset_multiscalar_mul<I, S>(&self, static_scalars: I) -> Self::Point
        where
            I: IntoIterator<Item = (usize, S)>,
            S: Borrow<Scalar>
    {
        RistrettoPoint(self.0.vartime_subset_multiscalar_mul(static_scalars))
    }
}

impl Display for RistrettoPoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.compress().as_bytes()))
    }
}

impl Display for CompressedRistretto {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
         write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

// NOTE(Alin): We define a += operator since we need to update a CompressedRistretto by adding a RistrettoPoint to it
impl<'b> AddAssign<&'b RistrettoPoint> for CompressedRistretto {
    fn add_assign(&mut self, rhs: &RistrettoPoint) {
        let mut decompressed = self.0.decompress().unwrap();
        decompressed += rhs.0;
        self.0 = decompressed.compress();
    }
}

define_add_assign_variants!(
    LHS = CompressedRistretto,
    RHS = RistrettoPoint);

impl<'b> AddAssign<&'b RistrettoPoint> for RistrettoPoint {
    fn add_assign(&mut self, rhs: &RistrettoPoint) {
        self.0 += rhs.0;
    }
}

define_add_assign_variants!(
    LHS = RistrettoPoint,
    RHS = RistrettoPoint);

impl<'a, 'b> Add<&'b RistrettoPoint> for &'a CompressedRistretto {
    type Output = CompressedRistretto;

    fn add(self, rhs: &'b RistrettoPoint) -> CompressedRistretto {
        let mut decompressed = self.0.decompress().unwrap();
        decompressed += rhs.0;

        CompressedRistretto(decompressed.compress())
    }
}

define_add_variants!(
    LHS = CompressedRistretto,
    RHS = RistrettoPoint,
    Output = CompressedRistretto);

impl<'a, 'b> Mul<&'b Scalar> for &'a RistrettoBasepointTable {
    type Output = RistrettoPoint;

    fn mul(self, scalar: &'b Scalar) -> RistrettoPoint {
        RistrettoPoint(&self.0 * scalar)
    }
}

impl<'a, 'b> Mul<&'a RistrettoBasepointTable> for &'b Scalar {
    type Output = RistrettoPoint;

    fn mul(self, basepoint_table: &'a RistrettoBasepointTable) -> RistrettoPoint {
        RistrettoPoint(self * &basepoint_table.0)
    }
}

define_mul_variants!(
    LHS = RistrettoBasepointTable,
    RHS = Scalar,
    Output = RistrettoPoint
);


pub trait CreateFromPoint {
    type Point;

    fn create(point: &Self::Point) -> Self;
}

pub trait Compressable {
    type CompressedPoint;

    fn compress(self: &Self) -> Self::CompressedPoint;
}

impl RistrettoBasepointTable {
    pub fn basepoint(&self) -> RistrettoPoint {
        RistrettoPoint(self.0.basepoint())
    }
}

impl CreateFromPoint for RistrettoBasepointTable {
    type Point = RistrettoPoint;

    fn create(point: &Self::Point) -> Self {
        RistrettoBasepointTable(DalekRistrBasepointTable::create(&point.0))
    }
}

impl Compressable for RistrettoPoint {
    type CompressedPoint = CompressedRistretto;

    fn compress(self: &RistrettoPoint) -> Self::CompressedPoint {
        CompressedRistretto(self.0.compress())
    }
}