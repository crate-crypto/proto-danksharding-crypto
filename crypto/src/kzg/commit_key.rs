use crate::{batch_inverse, g1_lincomb, polynomial::Polynomial, G1Point, RootsOfUnity, Scalar};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

// The key that is used to commit to polynomials in monomial form
//
/// Group elements of the form `{ \tau^i G }`
///  Where:
/// - `i` ranges from 0 to `degree`.
/// - `G` is some generator of the group
pub struct CommitKey {
    inner: Vec<G1Point>,
}

impl CommitKey {
    pub fn new(points: Vec<G1Point>) -> CommitKey {
        assert!(
            !points.is_empty(),
            "cannot initialise `CommitKey` with no points"
        );
        CommitKey { inner: points }
    }
    // Note: There is no commit method for CommitKey in monomial basis
    // as this is not used

    pub fn into_lagrange(self) -> CommitKeyLagrange {
        _ = self.inner;
        todo!("add a method that converts the commit key from monomial to lagrange basis")
    }
}

// The key that is used to commit to polynomials in lagrange form
//
/// Group elements of the form `{ \L_i(\tau) * G }`
/// Where :
/// - `i` ranges from 0 to `degree`
/// -  L_i is the i'th lagrange polynomial
/// - `G` is some generator of the group
pub struct CommitKeyLagrange {
    pub inner: Vec<G1Point>,
}

impl CommitKeyLagrange {
    pub fn new(points: Vec<G1Point>) -> CommitKeyLagrange {
        assert!(points.len() > 1);
        CommitKeyLagrange { inner: points }
    }

    /// Commit to `polynomial` in lagrange form
    pub fn commit(&self, polynomial: &Polynomial) -> G1Point {
        g1_lincomb(&self.inner, &polynomial.evaluations)
    }

    /// Commit to multiple polynomials in lagrange form
    pub fn commit_multiple(&self, polynomials: &[Polynomial]) -> Vec<G1Point> {
        polynomials
            .into_par_iter()
            .map(|poly| self.commit(poly))
            .collect()
    }
    /// Returns the maximum degree polynomial that one can commit to
    /// Since we are in lagrange basis, it is the number of points minus one
    ///
    /// Example: Given f(z) = z^2 , the number of evaluation points needed
    /// to represent f(z) is 3, but its degree is 2
    pub fn max_degree(&self) -> usize {
        self.inner.len() - 1
    }

    /// Computes the quotient polynomial for a kzg proof
    ///
    /// The state being proved is p(z) = y
    /// Where:
    /// - `z` is the point being passed as input
    pub(crate) fn compute_quotient(
        &self,
        poly: &Polynomial,
        input_point: Scalar,
        output_point: Scalar,
        domain: &RootsOfUnity,
    ) -> Polynomial {
        // Compute the denominator and store it in the quotient vector, to avoid re-allocation
        let mut quotient: Vec<_> = domain
            .roots()
            .iter()
            .map(|domain_element| *domain_element - input_point)
            .collect();
        batch_inverse(&mut quotient);

        // Compute the numerator polynomial and multiply it by the quotient which holds the
        // denominator
        for (quotient_i, eval_i) in quotient.iter_mut().zip(&poly.evaluations) {
            *quotient_i = (*eval_i - output_point) * *quotient_i
        }

        // Simple way to do this
        // let domain_size = domain.len();
        // let mut quotient = vec![Fr::zero(); domain_size];
        // for i in 0..domain_size {
        // let denominator = inverse(domain[i] - point);
        //     quotient[i] = (poly.evaluations[i] - output) * denominator
        // }
        // quotient

        Polynomial::new(quotient)
    }
}
