use ark_bls12_381::{Bls12_381, Parameters};
use ark_ec::{bls12::G2Prepared as GenericG2Prepared, AffineCurve, PairingEngine};
use ark_ff::{One, PrimeField};

use crate::{G1Point, G2Point, Scalar};

pub type G2Prepared = GenericG2Prepared<Parameters>;

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
        // TODO: The readability for this is not that great to be honest.
        //
        // TODO: This should improve with the newer version of arkworks
        // TODO: it has not been added yet

        // P - y
        let inner_a: G1Point =
            (poly_comm.into_projective() - &(self.g1_gen.mul(output_point.into_repr()))).into();

        // X - z
        let inner_b: G2Point = (self.tau_g2_gen.into_projective()
            - &(self.g2_gen.mul(input_point.into_repr())))
            .into();

        let prepared_inner_b = G2Prepared::from(-inner_b);

        let pairing = Bls12_381::product_of_pairings(&[
            (inner_a.into(), self.prepared_g2.clone()),
            (witness_comm.into(), prepared_inner_b.clone()),
        ]);

        pairing.is_one()
    }
}
