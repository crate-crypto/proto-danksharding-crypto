#[cfg(test)]
mod test_utils;

mod bls_point_encoding;
pub mod constants;
mod kzg;
mod polynomial;
mod roots_of_unity;
use ark_bls12_381::{Fr, G1Affine, G2Affine};
pub type G1Point = G1Affine;
pub type G2Point = G2Affine;
pub type Scalar = Fr;
pub type KZGCommitment = G1Point;

pub use kzg::{
    aggregated_proof::AggregatedKZG,
    proof::{KZGProof, KZGWitness},
    srs::PublicParameters,
};
pub use polynomial::Polynomial;
pub use roots_of_unity::RootsOfUnity;

pub(crate) fn batch_inverse(elements: &mut [Fr]) {
    use ark_ff::batch_inversion;
    batch_inversion(elements)
}

// Invert a field element, returning 0 if the element
// is not invertible
pub(crate) fn inverse(x: Fr) -> Fr {
    use ark_ff::{Field, Zero};
    x.inverse().unwrap_or(Fr::zero())
}

// A multi-scalar multiplication
pub fn g1_lincomb(points: &[G1Affine], scalars: &[Fr]) -> G1Affine {
    use ark_ec::msm::VariableBaseMSM;
    use ark_ec::ProjectiveCurve;
    use ark_ff::PrimeField;
    use rayon::iter::{IntoParallelIterator, ParallelIterator};
    // TODO: Spec says we should panic, but as a lib its better to return result

    assert_eq!(points.len(), scalars.len());

    let bigints: Vec<_> = scalars.into_par_iter().map(|s| s.into_repr()).collect();
    VariableBaseMSM::multi_scalar_mul(&points, &bigints).into_affine()
}
