/// Each blob will hold 2^12 field elements.
pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;

/// Each field element will be 32 bytes in size.
pub const FIELD_ELEMENT_SIZE: usize = 32;

/// While the trusted setup has not been completed
/// This is the tau value that will be used as a mock
/// It is not secure to use this in production.
pub const SECRET_TAU: u64 = 1337;
