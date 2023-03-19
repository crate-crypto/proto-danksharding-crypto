pub mod constants;
mod permutation;

use crypto::{
    Domain, G1Point, Polynomial, PublicParameters, G1_POINT_SERIALIZED_SIZE, SCALAR_SERIALIZED_SIZE,
};
use permutation::Permutable;

// What this library calls a `KZGWitness` the spec calls a `KZGProof`

pub struct Context {
    public_parameters: PublicParameters,
    domain: Domain,
}

use crypto::Scalar;

pub type BlobBytes = Vec<u8>;
pub type SerialisedScalar = [u8; SCALAR_SERIALIZED_SIZE];
pub type SerialisedPoint = [u8; G1_POINT_SERIALIZED_SIZE];
pub type KZGCommitmentBytes = SerialisedPoint;
pub type KZGWitnessBytes = SerialisedPoint;

impl Context {
    pub fn new_insecure() -> Self {
        let num_g1 = constants::FIELD_ELEMENTS_PER_BLOB;

        let secret = constants::SECRET_TAU;

        let domain = Domain::new(num_g1);
        let public_parameters = PublicParameters::from_secret_insecure(secret, &domain);

        Context {
            public_parameters: public_parameters.permute(),
            domain: domain.permute(),
        }
    }

    pub fn from_json_str(_trusted_setup_json: String) -> Self {
        todo!("The trusted setup has not been completed. For testing use the `insecure` method")
    }

    pub fn blob_to_kzg_commitment(&self, blob_bytes: BlobBytes) -> Option<KZGCommitmentBytes> {
        let polynomial = blob_bytes_to_polynomial(blob_bytes)?;

        let commitment = self.public_parameters.commit_key.commit(&polynomial);

        Some(commitment.to_compressed())
    }

    pub fn verify_kzg_proof(
        &self,
        commitment: KZGCommitmentBytes,
        input_point: SerialisedScalar,
        claimed_value: SerialisedScalar,
        proof: KZGWitnessBytes,
    ) -> Option<bool> {
        let input_point = bytes_to_scalar(&input_point)?;
        let claimed_value = bytes_to_scalar(&claimed_value)?;
        let poly_commitment = bytes_to_point(&commitment)?;
        let quotient_commitment = bytes_to_point(&proof)?;

        Some(self.public_parameters.opening_key.verify(
            input_point,
            claimed_value,
            poly_commitment,
            quotient_commitment,
        ))
    }
    pub fn compute_kzg_proof() {
        todo!("this is a helper method for the verification method")
    }
}

fn blob_bytes_to_polynomial(bytes: Vec<u8>) -> Option<Polynomial> {
    if bytes.len() % SCALAR_SERIALIZED_SIZE != 0 {
        return None;
    }

    if bytes.is_empty() {
        todo!("need to check strategy to handle empty blobs")
    }

    let num_scalars = bytes.len() / SCALAR_SERIALIZED_SIZE;

    let mut polynomial_inner = Vec::with_capacity(num_scalars);
    let iter = bytes.chunks_exact(SCALAR_SERIALIZED_SIZE);
    for chunk in iter {
        let chunk32: SerialisedScalar = chunk
            .try_into()
            .expect("infallible: since the length of the bytes vector is a multiple of 32");
        polynomial_inner.push(bytes_to_scalar(&chunk32)?)
    }

    Polynomial::new(polynomial_inner).into()
}
fn bytes_to_point(point_bytes: &SerialisedPoint) -> Option<G1Point> {
    let ct_point = G1Point::from_compressed(&point_bytes);
    bool::from(ct_point.is_some()).then(|| ct_point.unwrap())
}
fn bytes_to_scalar(scalar_bytes: &SerialisedScalar) -> Option<Scalar> {
    let ct_scalar = Scalar::from_bytes_le(scalar_bytes);
    bool::from(ct_scalar.is_some()).then(|| ct_scalar.unwrap())
}
