#[cfg(test)]
pub mod test_utils;

mod batch_inversion;
mod domain;
mod kzg;
mod polynomial;

pub type G1Point = blstrs::G1Affine;
pub type G2Point = blstrs::G2Affine;
pub type Scalar = blstrs::Scalar;
pub type KZGCommitment = G1Point;

// The number of bytes needed to represent a scalar
pub const SCALAR_SERIALIZED_SIZE: usize = 32;
// The number of bytes needed to represent a compressed G1 point
pub const G1_POINT_SERIALIZED_SIZE: usize = 48;
// The number of bytes needed to represent a compressed G2 point
pub const G2_POINT_SERIALIZED_SIZE: usize = 96;

// TODO: we can just make this the default type
pub(crate) type G1Projective = blstrs::G1Projective;

pub use domain::Domain;
pub use kzg::{
    proof::{KZGWitness, Proof},
    srs::PublicParameters,
};
pub use polynomial::Polynomial;
