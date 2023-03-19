use crate::{inverse, RootsOfUnity, Scalar};
use group::ff::Field;
#[cfg(feature = "rayon")]
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
use std::ops::{Add, Mul};

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

    // The size of the domain that the polynomial was
    // evaluated over
    pub fn domain_size(&self) -> usize {
        self.evaluations.len()
    }

    // Using the barycentric formula, one can evaluate a polynomial
    // in evaluation form, on a point `z` that is not inside of its domain
    pub fn evaluate_outside_of_domain(&self, z: Scalar, domain: &RootsOfUnity) -> Scalar {
        let domain_size = self.domain_size();

        assert_eq!(
            domain_size,
            domain.size(),
            "the size of the domain being used != the domain size of the polynomial"
        );

        // Check that we are evaluating on a point outside of the domain
        //
        // TODO: should this be an assert or should it just choose the `i'th` point in the evaluations
        // TODO: its technically not an error, just very unlikely to happen
        assert!(
            !domain.contains(&z),
            "the evaluation point is inside of the domain, this method is for points outside of the domain"
        );

        let mut result = Scalar::zero();
        for i in 0..domain_size {
            let denominator = inverse(z - domain[i]);
            result += (self.evaluations[i] * domain[i]) * denominator;
        }
        result * (z.pow_vartime(&[domain_size as u64]) - Scalar::one()) * domain.inverse_domain_size
    }
}
