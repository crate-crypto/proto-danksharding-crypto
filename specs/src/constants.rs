/// Each blob will hold 2^12 field elements
pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;

// The maximum amount of blobs to be expected in a block
pub const MAX_BLOBS_PER_BLOCK: usize = 16;

#[cfg(feature = "insecure")]
/// While the trusted setup has not been completed
/// This is the tau value that will be used as a mock
/// It is not secure to use this in production.
pub const SECRET_TAU: u64 = 1337;
