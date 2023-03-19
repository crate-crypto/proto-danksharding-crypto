use crate::{batch_inversion::batch_inverse, Domain, Polynomial, Scalar};
use ff::Field;

/// Computes the quotient polynomial for a kzg proof
///
/// The state being proved is p(z) = y
/// Where:
/// - `z` is the point being passed as input
pub(crate) fn compute(
    poly: &Polynomial,
    input_point: Scalar,
    output_point: Scalar,
    domain: &Domain,
) -> Polynomial {
    match domain.find(&input_point) {
        Some(index_in_domain) => {
            compute_quotient_in_domain(poly, index_in_domain, output_point, domain)
        }
        None => compute_quotient_outside_domain(poly, input_point, output_point, domain),
    }
}

pub(crate) fn compute_quotient_in_domain(
    poly: &Polynomial,
    index_in_domain: usize,
    output_point: Scalar,
    domain: &Domain,
) -> Polynomial {
    let polynomial_shifted: Vec<_> = poly
        .evaluations
        .iter()
        .map(|evaluation| evaluation - output_point)
        .collect();

    let input_point = domain[index_in_domain];
    let mut denominator_poly: Vec<_> = domain
        .roots()
        .iter()
        .map(|root| root - input_point)
        .collect();
    denominator_poly[index_in_domain] = Scalar::one();
    batch_inverse(&mut denominator_poly);

    let mut quotient_poly = vec![Scalar::zero(); domain.size()];
    for i in 0..domain.size() {
        if i == index_in_domain {
            quotient_poly[i] =
                compute_quotient_eval_within_domain(poly, index_in_domain, output_point, domain)
        } else {
            quotient_poly[i] = polynomial_shifted[i] * denominator_poly[i]
        }
    }

    Polynomial::new(quotient_poly)
}

fn compute_quotient_eval_within_domain(
    poly: &Polynomial,
    index_in_domain: usize,
    output_point: Scalar,
    domain: &Domain,
) -> Scalar {
    // TODO Assumes that index_in_domain is in the domain
    // TODO: should we use a special Index struct/enum to encode this?
    let input_point = domain[index_in_domain];

    // TODO: optimize with batch_inverse
    let mut result = Scalar::zero();
    for (index, root) in domain.roots().iter().enumerate() {
        if index == index_in_domain {
            continue;
        }

        let f_i = poly[index] - output_point;
        let numerator = f_i * root;
        let denominator = input_point * (input_point - root);
        result += numerator * denominator.invert().unwrap()
    }

    todo!()
}
pub(crate) fn compute_quotient_outside_domain(
    poly: &Polynomial,
    input_point: Scalar,
    output_point: Scalar,
    domain: &Domain,
) -> Polynomial {
    // Compute the denominator and store it in the quotient vector, to avoid re-allocation
    let mut quotient: Vec<_> = domain
        .roots()
        .iter()
        .map(|domain_element| *domain_element - input_point)
        .collect();
    // This should not panic, since we assume `input_point` is not in the domain
    batch_inverse(&mut quotient);

    // Compute the numerator polynomial and multiply it by the quotient which holds the
    // denominator
    quotient
        .iter_mut()
        .zip(&poly.evaluations)
        .for_each(|(quotient_i, eval_i)| *quotient_i = (*eval_i - output_point) * *quotient_i);

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
