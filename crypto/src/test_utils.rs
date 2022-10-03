#[cfg(any(feature = "insecure", test))]
use crate::{PublicParameters, RootsOfUnity};

use crate::{polynomial::Polynomial, G1Point, Scalar};
use ff::Field;
use group::prime::PrimeCurveAffine;
use std::ops::Mul;

pub fn random_polynomial(length: usize) -> Polynomial {
    Polynomial::new(random_vector(length))
}
pub fn random_vector(length: usize) -> Vec<Scalar> {
    (0..length)
        .map(|_| Scalar::random(&mut rand::thread_rng()))
        .collect()
}

pub fn random_g1() -> G1Point {
    let rand_scalar = Scalar::random(&mut rand::thread_rng());
    G1Point::generator().mul(rand_scalar).into()
}

#[cfg(any(feature = "insecure", test))]
pub fn test_setup(size: usize) -> (PublicParameters, RootsOfUnity) {
    let public_parameters = PublicParameters::from_secret(123456789, size);
    let domain = RootsOfUnity::new(size);
    (public_parameters, domain)
}
