/// This is the aggregated kzg proof algorithm.
/// It proves that `p_i(z) = y_i
/// Where:
/// - `i` ranges from 0 to some arbitrary value
/// - `p_i` is the i'th polynomial in lagrange basis
/// - `y_i` is the output `p_i` on a point `z`
/// Note:  that all polynomials are evaluated over the same point  
///
/// Moreover, the context here for aggregation is unconventional.
/// The verifier indeed has the polynomials,
/// and is therefore able to evaluate them. The polynomials
/// could be incorrect and so the verifier uses trusted commitments
/// to verify whether the polynomials are consistent with the commitments.
use super::{commit_key::CommitKeyLagrange, opening_key::OpeningKey, proof::KZGWitness};
use crate::{
    g1_lincomb, kzg::transcript::Transcript, polynomial::Polynomial, G1Point, KZGProof,
    RootsOfUnity, Scalar,
};
use ark_ff::One;

pub struct AggregatedKZG {
    polys: Vec<Polynomial>,
    poly_comms: Vec<G1Point>,
}

impl AggregatedKZG {
    pub fn empty() -> AggregatedKZG {
        AggregatedKZG {
            polys: Vec::new(),
            poly_comms: Vec::new(),
        }
    }

    pub fn from_polys(polys: Vec<Polynomial>, poly_comms: Vec<G1Point>) -> AggregatedKZG {
        assert_eq!(polys.len(), poly_comms.len());

        AggregatedKZG { polys, poly_comms }
    }

    pub fn add(&mut self, poly: Polynomial, comm: G1Point) {
        self.polys.push(poly);
        self.poly_comms.push(comm)
    }
}

impl AggregatedKZG {
    pub fn create(&self, commit_key: &CommitKeyLagrange, domain: &RootsOfUnity) -> KZGWitness {
        let mut transcript = Transcript::new();

        // First aggregate the polynomials together
        //
        let (aggregated_poly, aggregated_comm) =
            compute_aggregate_poly_and_comm(&mut transcript, &self.polys, &self.poly_comms);

        // Add the aggregated polynomial and its commitment to the transcript
        // TODO(Note): Deviates from the spec as it would require ssz in crypto lib
        transcript.append_polynomial(&aggregated_poly);
        transcript.append_g1_point(&aggregated_comm);

        // Generate a challenge
        let x = transcript.challenge_scalar();

        let proof = KZGProof::create(commit_key, &aggregated_poly, aggregated_comm, x, domain);

        // Since the verifier knows the polynomials,
        // they are able to compute the input and output point.
        // They also have the polynomial commitment and
        // therefore the prover only needs to return the witness to the verifier
        proof.quotient_commitment
    }

    pub fn verify(
        &self,
        opening_key: &OpeningKey,
        quotient_commitment: KZGWitness,
        domain: &RootsOfUnity,
    ) -> bool {
        let mut transcript = Transcript::new();

        // First aggregate the polynomials together
        //
        let (aggregated_poly, aggregated_comm) =
            compute_aggregate_poly_and_comm(&mut transcript, &self.polys, &self.poly_comms);

        // Add the aggregated polynomial and its commitment to the transcript
        // TODO(Note): Deviates from the spec as it would require ssz in crypto lib
        transcript.append_polynomial(&aggregated_poly);
        transcript.append_g1_point(&aggregated_comm);

        // Generate a challenge
        let x = transcript.challenge_scalar();

        // Evaluate the aggregated polynomial
        let y = aggregated_poly.evaluate_outside_of_domain(x, domain);

        let proof = KZGProof {
            polynomial_commitment: aggregated_comm,
            quotient_commitment,
            output_point: y,
        };

        proof.verify(x, opening_key)
    }
}

pub fn compute_aggregate_poly_and_comm<'a>(
    transcript: &mut Transcript,
    polys: &[Polynomial],
    poly_comms: &[G1Point],
) -> (Polynomial, G1Point) {
    assert_eq!(polys.len(), poly_comms.len());

    // TODO(Note): Deviates from the spec as it would require ssz in crypto lib
    // Add each polynomial into the transcript
    for poly in polys {
        transcript.append_polynomial(poly);
    }
    // Add each commitment for the polynomial
    for comm in poly_comms {
        transcript.append_g1_point(comm);
    }

    let challenge = transcript.challenge_scalar();
    let powers = compute_powers(challenge, poly_comms.len() as u64);

    let aggregated_poly = Polynomial::matrix_lincomb(polys, &powers);

    // Linearly combine the commitments using the challenges
    // The result is a commitment to the aggregated polynomial
    let aggregated_poly_comm = g1_lincomb(&poly_comms, &powers);

    (aggregated_poly, aggregated_poly_comm)
}

fn compute_powers(x: Scalar, n: u64) -> Vec<Scalar> {
    let mut current_power = Scalar::one();
    let mut powers = Vec::with_capacity(n as usize);

    for _ in 0..n {
        powers.push(current_power);
        current_power *= x;
    }

    powers
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{random_polynomial, test_setup};
    use ark_ff::Field;

    #[test]
    fn valid_proof_smoke() {
        // Setup parameters
        //
        let num_polynomials = 100;
        let vector_size = 2usize.pow(8);
        let (public_parameters, domain) = test_setup(vector_size);

        let polys = vec![random_polynomial(vector_size); num_polynomials];
        let poly_comms: Vec<G1Point> = polys
            .iter()
            .map(|poly| public_parameters.commit_key.commit(poly))
            .collect();

        // Provers View
        let kzg_witness = {
            let aggregated_kzg = AggregatedKZG::from_polys(polys.clone(), poly_comms.clone());
            aggregated_kzg.create(&public_parameters.commit_key, &domain)
        };

        // Verifiers View
        let ok = {
            let aggregated_kzg = AggregatedKZG::from_polys(polys.clone(), poly_comms.clone());
            aggregated_kzg.verify(&public_parameters.opening_key, kzg_witness, &domain)
        };

        assert!(ok);
    }

    #[test]
    fn powers_smoke() {
        let n = 123;
        let base = Scalar::from(456u64);
        let powers = compute_powers(base, n);

        for i in 0..n {
            assert_eq!(powers[i as usize], base.pow(&[i]));
        }
    }
}
