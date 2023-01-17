use crate::{G1Point, G2Point, Scalar};
use blstrs::G2Prepared;
use blstrs::*;
use group::Curve;
use pairing_lib::group::Group;
use pairing_lib::{MillerLoopResult, MultiMillerLoop};

/// Opening Key is used to verify opening proofs made about a committed polynomial.
#[derive(Clone, Debug)]
pub struct OpeningKey {
    /// The generator of G1 used in the setup
    pub g1_gen: G1Point,
    /// The generator of G2 used in the setup
    pub g2_gen: G2Point,
    /// \tau times the generator of G2.
    pub tau_g2_gen: G2Point,
    /// The generator of G2, prepared for use in pairings.
    pub prepared_g2: G2Prepared,
    /// \tau times the above generator of G2, prepared for use in pairings.
    pub prepared_beta_g2: G2Prepared,
}

impl OpeningKey {
    pub fn new(g1_gen: G1Point, g2_gen: G2Point, tau_g2_gen: G2Point) -> OpeningKey {
        // Store cached elements for verifying multiple proofs.

        let prepared_g2 = G2Prepared::from(g2_gen);
        let prepared_beta_g2 = G2Prepared::from(tau_g2_gen);

        OpeningKey {
            g1_gen,
            g2_gen,
            tau_g2_gen,
            prepared_g2,
            prepared_beta_g2,
        }
    }

    /// Checks that a polynomial `p` was evaluated at a point `z` and returned the value specified `y`.
    /// ie. y = p(z).
    pub fn verify(
        &self,
        input_point: Scalar,
        output_point: Scalar,
        poly_comm: G1Point,
        witness_comm: G1Point,
    ) -> bool {
        // TODO: .into is doing an inversion. Check if batch normalisation saves anything here
        // codepath : G1Projective::batch_normalize(p, q)
        let inner_a: G1Point = (poly_comm - (self.g1_gen * output_point)).into();
        let inner_b: G2Point = (self.tau_g2_gen - (self.g2_gen * input_point)).into();
        let prepared_inner_b = G2Prepared::from(-inner_b);

        let pairing = Bls12::multi_miller_loop(&[
            (&inner_a, &self.prepared_g2),
            (&witness_comm, &prepared_inner_b),
        ])
        .final_exponentiation();

        pairing.is_identity().into()
    }
}
