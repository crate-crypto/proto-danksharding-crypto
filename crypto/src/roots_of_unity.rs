use crate::Scalar;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use std::ops::Index;

#[derive(Debug, Clone)]
pub struct RootsOfUnity {
    // roots of unity
    pub inner: Vec<Scalar>,
    // Inverse of the domain size
    pub inverse_domain_size: Scalar,
}

impl RootsOfUnity {
    pub fn new(size: usize) -> RootsOfUnity {
        assert!(
            size.is_power_of_two(),
            "size must explicitly be a power of two"
        );

        let domain: Radix2EvaluationDomain<Scalar> = Radix2EvaluationDomain::new(size).unwrap();

        RootsOfUnity {
            inner: domain.elements().collect(),
            inverse_domain_size: domain.size_inv,
        }
    }

    pub fn roots(&self) -> &[Scalar] {
        &self.inner
    }

    pub fn size(&self) -> usize {
        self.inner.len()
    }

    pub fn contains(&self, element: &Scalar) -> bool {
        self.inner.contains(element)
    }
}

impl Index<usize> for &RootsOfUnity {
    type Output = Scalar;

    fn index(&self, i: usize) -> &Self::Output {
        &self.inner[i]
    }
}
