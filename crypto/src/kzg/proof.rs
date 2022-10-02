/// This is the traditional KZG proof algorithm
/// that follows from the paper.
///
/// It is left unmodified and is its own
/// isolated module. It is used as a sub-protocol for
/// the aggregated kzg proof algorithm
use super::{commit_key::CommitKeyLagrange, opening_key::OpeningKey};
use crate::{G1Point, Polynomial, RootsOfUnity, Scalar};

// Commitment to the quotient polynomial
pub type KZGWitness = G1Point;

pub struct KZGProof {
    // Commitment to the polynomial that we have created a
    // KZG proof for.
    pub polynomial_commitment: G1Point,

    // Commitment to the `witness` or quotient polynomial
    pub quotient_commitment: KZGWitness,

    pub output_point: Scalar,
}

impl KZGProof {
    pub fn create(
        commit_key: &CommitKeyLagrange,
        poly: &Polynomial,
        poly_comm: G1Point,
        input_point: Scalar,
        domain: &RootsOfUnity,
    ) -> KZGProof {
        let output_point = poly.evaluate_outside_of_domain(input_point, domain);

        let quotient = commit_key.compute_quotient(poly, input_point, output_point, domain);

        let quotient_comm = commit_key.commit(&quotient);

        KZGProof {
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

        let proof = KZGProof::create(
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
