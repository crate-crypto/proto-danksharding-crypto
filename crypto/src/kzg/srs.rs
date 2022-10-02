use super::{
    commit_key::{CommitKey, CommitKeyLagrange},
    opening_key::OpeningKey,
};
use crate::{G1Point, G2Point, Scalar};

// This is the SRS both in monomial and lagrange form
//
// The lagrange form is used to avoid the need to do
// an inverse fft to commit to polynomials
pub struct PublicParameters {
    pub commit_key: CommitKeyLagrange,
    pub opening_key: OpeningKey,
}
impl PublicParameters {
    #[cfg(any(feature = "insecure", test))]
    pub fn from_secret(tau: u64, num_g1: usize) -> Self {
        use group::prime::PrimeCurveAffine;

        let tau_fr = Scalar::from(tau);
        let g1_gen = G1Point::generator();
        let g2_gen = G2Point::generator();
        let tau_g2_gen = (g2_gen * tau_fr).into();
        let powers_of_tau_g1 = Self::compute_lagrange_srs(num_g1, tau, g1_gen);

        PublicParameters {
            commit_key: CommitKeyLagrange {
                inner: powers_of_tau_g1,
            },
            opening_key: OpeningKey::new(g1_gen, g2_gen, tau_g2_gen),
        }
    }

    #[cfg(any(feature = "insecure", test))]
    // This is an insecure way to generate the lagrange form of the SRS
    fn compute_lagrange_srs(max_degree: usize, tau: u64, g: G1Point) -> Vec<G1Point> {
        let lagrange_coeffs = crate::arkworks::evaluate_lagrange_coefficients(max_degree, tau);
        // Commit to each lagrange coefficient
        lagrange_coeffs
            .into_iter()
            .map(|l_s| g * l_s)
            .map(|point| point.into())
            .collect()
    }

    // Use this function once the trusted setup has been completed
    pub fn from_monomial_srs(
        g1s: Vec<G1Point>,
        g1_gen: G1Point,
        g2_gen: G2Point,
        tau_g2_gen: G2Point,
    ) -> Self {
        let commit_key_lagrange = CommitKey::new(g1s).into_lagrange();
        let opening_key = OpeningKey::new(g1_gen, g2_gen, tau_g2_gen);
        PublicParameters {
            commit_key: commit_key_lagrange,
            opening_key,
        }
    }
}
