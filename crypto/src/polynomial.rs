use crate::{inverse, RootsOfUnity, Scalar};
use group::ff::Field;
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

impl Mul<Scalar> for &Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: Scalar) -> Self::Output {
        scale_polynomial(self, rhs)
    }
}

impl Add for &Polynomial {
    type Output = Polynomial;

    fn add(self, rhs: Self) -> Self::Output {
        polynomial_addition(self, rhs)
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

    // Compute the linear combination between
    // each column of the matrix with `scalars`: return the resulting vector.
    // TODO: this documentation was taken from the specs, it's only clear after looking at the code
    // TODO so modify the documentation to be clearer if possible.
    pub(crate) fn matrix_lincomb(matrix: &[Polynomial], scalars: &[Scalar]) -> Polynomial {
        // TODO: Are we missing an assert to ensure that each sub vector is the same length
        // TODO as scalar?

        let row_len = matrix
            .first()
            .expect("expected at least one row in the matrix")
            .domain_size();

        #[cfg(feature = "parallel")]
        let result = matrix
            .into_par_iter()
            .zip(scalars)
            .map(|(vector, scalar)| vector * *scalar)
            .fold(
                || vec![Scalar::zero(); row_len],
                |sum, val| {
                    sum.into_iter()
                        .zip(val.evaluations)
                        .map(|(a_i, b_i)| a_i + b_i)
                        .collect()
                },
            )
            .reduce(
                || vec![Scalar::zero(); row_len],
                |sum, val| {
                    sum.into_iter()
                        .zip(val)
                        .map(|(a_i, b_i)| a_i + b_i)
                        .collect()
                },
            );

        #[cfg(not(feature = "parallel"))]
        let result = matrix
            .into_iter()
            .zip(scalars)
            .map(|(vector, scalar)| vector * *scalar)
            .fold(vec![Scalar::zero(); row_len], |sum, val| {
                sum.into_iter()
                    .zip(val.evaluations)
                    .map(|(a_i, b_i)| a_i + b_i)
                    .collect()
            });

        Polynomial::new(result)
    }
}

fn scale_polynomial(poly: &Polynomial, scalar: Scalar) -> Polynomial {
    Polynomial::new(
        poly.evaluations
            .par_iter()
            .map(|element| *element * scalar)
            .collect(),
    )
}
fn polynomial_addition(lhs: &Polynomial, rhs: &Polynomial) -> Polynomial {
    Polynomial::new(
        lhs.evaluations
            .par_iter()
            .zip(&rhs.evaluations)
            .map(|(a, b)| *a + *b)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use ff::Field;

    use super::{Polynomial, Scalar};
    use crate::test_utils::{random_polynomial, random_vector};

    #[test]
    fn matrix_vector_lin_comb() {
        let num_columns = 2usize.pow(12);
        let num_rows = 45;

        let scalars = random_vector(num_columns);
        let matrix = vec![random_polynomial(num_columns); num_rows];

        let got = Polynomial::matrix_lincomb(&matrix, &scalars);
        let expected = matrix_lincomb_slow(&matrix, &scalars);
        assert_eq!(got, expected);
    }

    // This is a more readable version of matrix_lincomb
    // we don't care about performance here
    fn matrix_lincomb_slow(matrix: &[Polynomial], scalars: &[Scalar]) -> Polynomial {
        let row_len = scalars.len();

        let mut result: Vec<Scalar> = vec![Scalar::zero(); row_len];

        for (row_vector, scalar) in matrix.into_iter().zip(scalars) {
            for (index, vector_element) in row_vector.evaluations.iter().enumerate() {
                result[index] = result[index] + (*scalar * vector_element)
            }
        }

        Polynomial::new(result)
    }
}
