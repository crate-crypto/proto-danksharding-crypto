use std::ops::Index;

use crate::{batch_inversion::batch_inverse, Domain, Scalar};
use group::ff::Field;

#[derive(Debug, Clone)]
// Polynomial representation in evaluation form
// The domain is not saved with the struct to save memory
pub struct Polynomial {
    pub evaluations: Vec<Scalar>,
}

impl PartialEq for Polynomial {
    fn eq(&self, other: &Self) -> bool {
        self.evaluations == other.evaluations
    }
}

impl Index<usize> for &Polynomial {
    type Output = Scalar;

    fn index(&self, i: usize) -> &Self::Output {
        &self.evaluations[i]
    }
}

impl Polynomial {
    /// Panics, if the number of evaluations is 0 or not a power of two
    /// 0 is not a power of two, so we can remove it
    pub fn new(evaluations: Vec<Scalar>) -> Polynomial {
        // We could return an Option, users of the library
        // who consume this API directly, will be forced to unwrap.
        //
        // We may change it in the future, as the further up the stack
        // we put the unwrap, the more visible this is.

        assert!(
            evaluations.len().is_power_of_two(),
            "the domain size must be a power of two, size is : {}",
            evaluations.len()
        );

        Polynomial { evaluations }
    }

    pub fn evaluate(&self, z: Scalar, domain: &Domain) -> Scalar {
        assert_eq!(
            self.num_evaluations(),
            domain.size(),
            "the size of the domain being used != the domain size of the polynomial"
        );

        match domain.find(&z) {
            Some(index_in_domain) => self.evaluations[index_in_domain],
            None => self.evaluate_outside_of_domain(z, domain),
        }
    }

    // Using the barycentric formula, one can evaluate a polynomial
    // in evaluation form, on a point `z` that is not inside of its domain
    fn evaluate_outside_of_domain(&self, z: Scalar, domain: &Domain) -> Scalar {
        let domain_size = domain.size();

        let mut denominator: Vec<_> = domain.roots().iter().map(|root_i| z - root_i).collect();
        batch_inverse(&mut denominator);

        let mut result = Scalar::zero();
        // TODO Use zip here on evals, domain and denominator
        for i in 0..domain_size {
            result += (self.evaluations[i] * domain[i]) * denominator[i];
        }
        result * (z.pow_vartime(&[domain_size as u64]) - Scalar::one()) * domain.domain_size_inv
    }

    fn num_evaluations(&self) -> usize {
        self.evaluations.len()
    }
}
