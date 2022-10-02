use crate::Scalar;
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

        let (domain, size_inv) = crate::arkworks::generate_domain_parameters(size);

        RootsOfUnity {
            inner: domain,
            inverse_domain_size: size_inv,
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
