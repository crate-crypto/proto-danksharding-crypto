use crypto::{PublicParameters, RootsOfUnity};
//
// TODO: currently the permutation is not doing anything
// TODO: first need to test the methods being used
//
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
        self
        // let permutation = bit_reversal_permutation(&self.inner);
        // RootsOfUnity {
        //     inner: permutation,
        //     inverse_domain_size: self.inverse_domain_size,
        // }
    }
}

impl Permutable for PublicParameters {
    type PermutedType = PublicParameters;
    fn permute(self) -> Self::PermutedType {
        self
        // Permute the lagrange vectors in the commitment key
        // self.commit_key.inner = bit_reversal_permutation(&self.commit_key.inner);
        // self
    }
}

// Check if ``value`` is a power of two integer.
fn is_power_of_two(value: usize) -> bool {
    value.is_power_of_two()
}

// Note: We do not care about the speed of this function at all.
// Since it is only ran on startup.
fn reverse_bits(n: usize, order: usize) -> usize {
    // This assert avoids the edge case of order == 0
    // when getting the bit size of order - 1
    //
    // Since this code is only executed on startup
    // panicking here is fine
    assert!(is_power_of_two(order));

    let n_as_bits = to_bits(n as u32);
    let num_bits_needed = to_bits((order - 1) as u32).len();

    let mut n_as_bits = n_as_bits[0..num_bits_needed].to_vec();
    // Reverses the order of bit vector
    n_as_bits.reverse();

    from_bits(n_as_bits) as usize
}

// Return a copy with bit-reversed permutation. This operation is idempotent.
// Since this operation is done once at startup, we don't care about optimising it as much
pub fn bit_reversal_permutation<T: Clone>(vector: &[T]) -> Vec<T> {
    (0..vector.len())
        .map(|i| reverse_bits(i, vector.len()))
        .map(|p_i| vector[p_i].clone())
        .collect()
}

// Converts a number to bits and truncates any prepending zeroes
fn to_bits(x: u32) -> Vec<bool> {
    let num_bits = u32::BITS;
    let bits: Vec<_> = (1..=num_bits).map(|i| x & (1u32 << i) != 0).collect();

    // Truncate prepending zero bits
    let mut index_first_bit_set = None;
    for (index, bit) in bits.iter().enumerate() {
        if *bit == true {
            index_first_bit_set = Some(index);
            break;
        }
    }

    match index_first_bit_set {
        Some(index) => bits[index..].to_vec(),
        None => {
            // This means that no bts were set, ie its 0
            vec![false]
        }
    }
}
fn from_bits(bit_vec: Vec<bool>) -> u32 {
    let mut result = 0u32;

    let base = 2u32;
    for (index, bit) in bit_vec.into_iter().enumerate() {
        result += base.pow(index as u32) * (bit as u32);
    }

    result
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
        let pow_2 = 2usize.pow(i);
        assert!(is_power_of_two(pow_2));
        assert!(!is_power_of_two(pow_2 - 1));
        assert!(!is_power_of_two(pow_2 + 1))
    }
}
