use crypto::{PublicParameters, RootsOfUnity};

/// There are some structures which need to be permuted.
/// We implement this trait on such structures
/// This allows us to leave the cryptography untouched
/// since this permutation does not modify the cryptographic
/// algorithms
pub trait Permutable {
    type PermutedType;

    fn permute(self) -> Self::PermutedType;
}

impl Permutable for RootsOfUnity {
    type PermutedType = RootsOfUnity;
    fn permute(self) -> Self::PermutedType {
        let permutation = bit_reversal_permutation(&self.inner);
        RootsOfUnity {
            inner: permutation,
            inverse_domain_size: self.inverse_domain_size,
        }
    }
}

impl Permutable for PublicParameters {
    type PermutedType = PublicParameters;
    fn permute(mut self) -> Self::PermutedType {
        // Permute the lagrange vectors in the commitment key
        self.commit_key.inner = bit_reversal_permutation(&self.commit_key.inner);
        self
    }
}

// Check if ``value`` is a power of two integer.
fn is_power_of_two(value: u64) -> bool {
    value.is_power_of_two()
}

fn reverse_bits(num: u64, order: u64) -> u64 {
    if !is_power_of_two(order) {
        panic!("order is not a power of two")
    }

    num.reverse_bits() >> (65 - min_num_bits_needed(order))
}
// minimum number of bits needed to represent an integer
fn min_num_bits_needed(num: u64) -> u32 {
    64 - num.leading_zeros()
}

// Return a copy with bit-reversed permutation. This operation is idempotent.
// Since this operation is done once at startup, we don't care about optimising it as much
pub fn bit_reversal_permutation<T: Clone>(vector: &[T]) -> Vec<T> {
    (0..vector.len())
        .map(|i| reverse_bits(i as u64, vector.len() as u64))
        .map(|p_i| vector[p_i as usize].clone())
        .collect()
}

#[test]
fn is_pow_two() {
    // This test is not worth having in the rust lib
    // because there is a tested method for this in the stdlib
    //
    // If you are implementing it yourself, then this will be useful

    // Edge case
    assert!(!is_power_of_two(0));

    assert!(is_power_of_two(1));
    assert!(is_power_of_two(2));

    for i in 2..usize::BITS {
        let pow_2 = 2u64.pow(i);
        assert!(is_power_of_two(pow_2));
        assert!(!is_power_of_two(pow_2 - 1));
        assert!(!is_power_of_two(pow_2 + 1))
    }
}
