use crate::{G1Point, G1Projective, Scalar};
use ff::{Field, PrimeField};
use group::{prime::PrimeCurveAffine, Curve, Group};
use std::ops::Index;

#[derive(Debug, Clone)]
pub struct Domain {
    // roots of unity
    pub roots: Vec<Scalar>,
    // Domain size as a scalar
    pub domain_size: Scalar,
    // Inverse of the domain size as a scalar
    pub domain_size_inv: Scalar,
    // Generator for this domain
    // Element has order `domain_size`
    pub generator: Scalar,
    // Inverse of the generator
    // This is useful for IFFT
    pub generator_inv: Scalar,
}

impl Domain {
    pub fn new(size: usize) -> Domain {
        // We are using roots of unity, so the
        // size of the domain will be padded to
        // the next power of two
        let size = if size.is_power_of_two() {
            size
        } else {
            size.next_power_of_two()
        };

        let generator = Self::compute_generator_for_size(size);
        let generator_inv = generator.invert().unwrap(); // Generator should not be zero

        let size_as_scalar = Scalar::from(size as u64);
        let size_as_scalar_inv = size_as_scalar.invert().unwrap();

        let mut roots = Vec::with_capacity(size);
        roots.push(Scalar::one());

        for i in 1..size {
            let prev_root = roots[i - 1];
            roots.push(prev_root * generator)
        }

        Self {
            roots,
            domain_size: size_as_scalar,
            domain_size_inv: size_as_scalar_inv,
            generator,
            generator_inv,
        }
    }

    fn largest_root_of_unity() -> Scalar {
        Scalar::from_str_vartime(
            "10238227357739495823651030575849232062558860180284477541189508159991286009131",
        )
        .unwrap()
    }

    fn compute_generator_for_size(size: usize) -> Scalar {
        assert!(size.is_power_of_two());

        let log_size_of_group = size.trailing_zeros();
        if log_size_of_group > Domain::two_adicity() {
            panic!("two adicity is 32 but group size needed is 2^{log_size_of_group}");
        }

        // We now want to compute the generator which has order `size`
        let exponent: u64 = 1 << (Domain::two_adicity() as u64 - log_size_of_group as u64);

        Domain::largest_root_of_unity().pow_vartime(&[exponent])
    }

    const fn two_adicity() -> u32 {
        32
    }

    pub fn size(&self) -> usize {
        self.roots.len()
    }

    pub fn contains(&self, element: &Scalar) -> bool {
        self.find(element).is_some()
    }
    pub fn find(&self, element: &Scalar) -> Option<usize> {
        self.roots.iter().position(|root_i| root_i == element)
    }

    pub fn roots(&self) -> &[Scalar] {
        &self.roots
    }

    pub(crate) fn ifft_g1(&self, points: Vec<G1Point>) -> Vec<G1Point> {
        if points.len() != self.size() {
            panic!(
                "number of points {}, must equal the domain size {}",
                points.len(),
                self.size()
            )
        }

        let points_proj: Vec<_> = points
            .into_iter()
            .map(|point_aff| G1Projective::from(point_aff))
            .collect();

        let mut ifft_g1 = fft_g1(self.generator_inv, &points_proj);

        for element in ifft_g1.iter_mut() {
            *element = *element * self.domain_size_inv
        }

        let mut affine = vec![G1Point::identity(); ifft_g1.len()];
        G1Projective::batch_normalize(&ifft_g1, &mut affine);
        return affine;
    }
}

impl Index<usize> for &Domain {
    type Output = Scalar;

    fn index(&self, i: usize) -> &Self::Output {
        &self.roots[i]
    }
}

fn fft_g1(nth_root_of_unity: Scalar, points: &[G1Projective]) -> Vec<G1Projective> {
    let n = points.len();
    if n == 1 {
        return points.to_vec();
    }

    let (even, odd) = take_even_odd(points);

    // Compute a root with half the order
    let gen_squared = nth_root_of_unity.square();

    let fft_even = fft_g1(gen_squared, &even);
    let fft_odd = fft_g1(gen_squared, &odd);

    let mut input_point = Scalar::one();
    let mut evaluations = vec![G1Projective::identity(); n];

    for k in 0..n / 2 {
        let tmp = fft_odd[k] * input_point;
        evaluations[k] = G1Projective::from(fft_even[k]) + tmp;
        evaluations[k + n / 2] = fft_even[k] - tmp;

        input_point = input_point * nth_root_of_unity;
    }

    evaluations
}
fn take_even_odd<T: Clone>(list: &[T]) -> (Vec<T>, Vec<T>) {
    let mut even = Vec::with_capacity(list.len() / 2);
    let mut odd = Vec::with_capacity(list.len() / 2);

    for (index, value) in list.iter().enumerate() {
        if index % 2 == 0 {
            even.push(value.clone())
        } else {
            odd.push(value.clone())
        }
    }

    (even, odd)
}

#[test]
fn largest_group_has_correct_order() {
    let root = Domain::largest_root_of_unity();
    let order = 2u64.pow(Domain::two_adicity());

    assert_eq!(root.pow_vartime(&[order]), Scalar::one())
}
