use crate::{Domain, PublicParameters};

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

pub(crate) fn test_setup(size: usize) -> (PublicParameters, Domain) {
    let domain = Domain::new(size);
    let public_parameters = PublicParameters::from_secret_insecure(123456789, &domain);
    (public_parameters, domain)
}
