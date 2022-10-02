use crate::{G1Point, Polynomial, PublicParameters, RootsOfUnity, Scalar};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{PrimeField, UniformRand};

pub fn random_polynomial(length: usize) -> Polynomial {
    Polynomial::new(random_vector(length))
}
pub fn random_vector(length: usize) -> Vec<Scalar> {
    (0..length)
        .map(|_| Scalar::rand(&mut rand::thread_rng()))
        .collect()
}

pub fn random_g1() -> G1Point {
    let rand_scalar = Scalar::rand(&mut rand::thread_rng());
    G1Point::prime_subgroup_generator()
        .mul(rand_scalar.into_repr())
        .into_affine()
}

pub fn test_setup(size: usize) -> (PublicParameters, RootsOfUnity) {
    let public_parameters = PublicParameters::from_secret(123456789, size);
    let domain = RootsOfUnity::new(size);
    (public_parameters, domain)
}
