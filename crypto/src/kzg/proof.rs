/// This is the traditional KZG proof algorithm
/// that follows from the KZG paper.
///
/// It is left unmodified and is its own
/// isolated module.
use super::{commit_key::CommitKeyLagrange, opening_key::OpeningKey, quotient_poly};
use crate::{Domain, G1Point, Polynomial, Scalar};

// Commitment to the quotient polynomial
pub type KZGWitness = G1Point;

pub struct Proof {
    // Commitment to the polynomial that we have created a
    // KZG proof for.
    pub polynomial_commitment: G1Point,

    // Commitment to the `witness` or quotient polynomial
    pub quotient_commitment: KZGWitness,

    pub output_point: Scalar,
}

impl Proof {
    pub fn create(
        commit_key: &CommitKeyLagrange,
        poly: &Polynomial,
        poly_comm: G1Point,
        input_point: Scalar,
        domain: &Domain,
    ) -> Proof {
        let output_point = poly.evaluate(input_point, domain);

        let quotient = quotient_poly::compute(poly, input_point, output_point, domain);

        let quotient_comm = commit_key.commit(&quotient);

        Proof {
            polynomial_commitment: poly_comm,
            quotient_commitment: quotient_comm,
            output_point,
        }
    }

    pub fn verify(&self, input_point: Scalar, opening_key: &OpeningKey) -> bool {
        opening_key.verify(
            input_point,
            self.output_point,
            self.polynomial_commitment,
            self.quotient_commitment,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{random_polynomial, test_setup};

    #[test]
    fn valid_proof_smoke() {
        // Setup parameters
        //
        let size = 2usize.pow(8);
        let (public_parameters, domain) = test_setup(size);

        let poly = random_polynomial(size);
        let input_point = Scalar::from(123456u64);

        let poly_comm = public_parameters.commit_key.commit(&poly);

        let proof = Proof::create(
            &public_parameters.commit_key,
            &poly,
            poly_comm,
            input_point,
            &domain,
        );
        assert!(proof.verify(input_point, &public_parameters.opening_key));
        assert!(!proof.verify(input_point + input_point, &public_parameters.opening_key));
    }
}
