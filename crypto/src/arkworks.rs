// We use arkworks to fill in some convenience methods
// that is not offered by blstrs. These are common methods
// that one can simply implement in blstrs
//
// We then convert an arkworks structure into a blstrs structure

use ark_bls12_381::Fr as ArkworksScalar;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use blstrs::Scalar as BlsScalar;

pub fn generate_domain_parameters(size: usize) -> (Vec<BlsScalar>, BlsScalar) {
    let domain: Radix2EvaluationDomain<ArkworksScalar> = Radix2EvaluationDomain::new(size).unwrap();

    // Generate the domain elements
    let omegas: Vec<_> = domain
        .elements()
        .map(|element| convert_arkworks_scalar_to_blst_scalar(element))
        .collect();

    let size_inv = convert_arkworks_scalar_to_blst_scalar(domain.size_inv);
    (omegas, size_inv)
}
// The blst library only allows reduced scalars
// We use arkworks to reduce it
pub fn unreduced_bytes_to_scalar(hash: &[u8]) -> BlsScalar {
    let scalar = ArkworksScalar::from_le_bytes_mod_order(hash);
    convert_arkworks_scalar_to_blst_scalar(scalar)
}

pub fn evaluate_lagrange_coefficients(size: usize, tau: u64) -> Vec<BlsScalar> {
    use ark_poly::GeneralEvaluationDomain;

    let domain: GeneralEvaluationDomain<ArkworksScalar> =
        GeneralEvaluationDomain::new(size).unwrap();

    // Evaluate lagrange at the secret scalar `tau`
    let lagrange_coeffs = domain.evaluate_all_lagrange_coefficients(ArkworksScalar::from(tau));

    lagrange_coeffs
        .into_iter()
        .map(|element| convert_arkworks_scalar_to_blst_scalar(element))
        .collect()
}

fn convert_arkworks_scalar_to_blst_scalar(scalar: ArkworksScalar) -> BlsScalar {
    // Takes scalar out of montgomery form and get its internal repr
    let repr = scalar.into_repr().0;

    BlsScalar::from_u64s_le(&repr).unwrap()
}

#[test]
fn interop() {
    let ark_minus_one = -ArkworksScalar::from(1u64);
    let expected_bls_minus_one = -BlsScalar::from(1u64);

    let got_bls_minus_one = convert_arkworks_scalar_to_blst_scalar(ark_minus_one);

    assert_eq!(expected_bls_minus_one, got_bls_minus_one)
}
