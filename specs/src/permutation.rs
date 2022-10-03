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
fn is_power_of_two(value: usize) -> bool {
    value.is_power_of_two()
}

// This method mimics what the python method does
// but it has hidden behavior if you are not familiar with
// c how c string formats work
// Note: We do not care about the speed of this function at all.
// Since it is only ran on startup.
fn reverse_bits(num: usize, order: usize) -> usize {
    // This assert avoids the edge case of order == 0
    // when getting the bit size of order - 1
    //
    // Since this code is only executed on startup
    // panicking here is fine
    assert!(is_power_of_two(order));

    let num: usize = num
        .try_into()
        .expect("cannot convert num to a 32 bit integer");
    let order: usize = order
        .try_into()
        .expect("cannot convert order to a 32 bit integer");

    // First find out how many bits of number we need to consider
    let num_bits_needed = num_bits_needed((order - 1) as u32);

    // b - Tells the formatter to format the number as a binary string
    // 0 - Tells the formatter to pad the binary string with zeroes
    // 0$ - This is a placeholder for the width of the resulting binary string.
    // the 0 tells the formatter to get the value frm the first argument
    // to the macro. In this case, num_bits_needed
    //
    // Note: If the width is less than the number of bits needed
    // to represent the number, then it will print out all of its bits
    let num_as_binary_string = format!("{num:00$b}", num_bits_needed);

    // Reverse the order of the binary string
    let rev_num_as_binary_string = rev_str(num_as_binary_string);

    // Interpret the binary string as number
    usize::from_str_radix(&rev_num_as_binary_string, 2).unwrap()
}
// Returns how many bits are needed to represent a number
// Look at the bit representation of 32 bit number and it is 32
// minus the number of leading zeroes
fn num_bits_needed(number: u32) -> usize {
    (u32::BITS - number.leading_zeros()) as usize
}

fn rev_str(v: String) -> String {
    let mut chars: Vec<_> = v.chars().collect();
    chars.reverse();
    chars.into_iter().collect()
}

// Return a copy with bit-reversed permutation. This operation is idempotent.
// Since this operation is done once at startup, we don't care about optimising it as much
pub fn bit_reversal_permutation<T: Clone>(vector: &[T]) -> Vec<T> {
    (0..vector.len())
        .map(|i| reverse_bits(i, vector.len()))
        .map(|p_i| vector[p_i].clone())
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
        let pow_2 = 2usize.pow(i);
        assert!(is_power_of_two(pow_2));
        assert!(!is_power_of_two(pow_2 - 1));
        assert!(!is_power_of_two(pow_2 + 1))
    }
}
