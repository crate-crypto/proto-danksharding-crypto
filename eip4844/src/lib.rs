pub mod constants;
mod permutation;

use crypto::{
    AggregatedKZG, G1Point, Polynomial, PublicParameters, RootsOfUnity, G1_POINT_SERIALIZED_SIZE,
    SCALAR_SERIALIZED_SIZE,
};
use permutation::Permutable;

// What this library calls a `KZGWitness` the spec calls a `KZGProof`

pub struct Context {
    public_parameters: PublicParameters,
    roots_of_unity: RootsOfUnity,
}

use crypto::Scalar;

pub type BlobBytes = Vec<u8>;
pub type SerialisedScalar = [u8; SCALAR_SERIALIZED_SIZE];
pub type SerialisedPoint = [u8; G1_POINT_SERIALIZED_SIZE];
pub type KZGCommitmentBytes = SerialisedPoint;
pub type KZGWitnessBytes = SerialisedPoint;

impl Context {
    #[cfg(feature = "insecure")]
    pub fn new_insecure() -> Self {
        let num_g1 = constants::FIELD_ELEMENTS_PER_BLOB;

        let secret = constants::SECRET_TAU;

        let public_parameters = PublicParameters::from_secret(secret, num_g1).permute();
        let roots_of_unity = RootsOfUnity::new(num_g1).permute();

        Context {
            public_parameters,
            roots_of_unity,
        }
    }

    pub fn from_json_str(_trusted_setup_json: String) -> Self {
        todo!("The trusted setup has not been completed. For testing use the `insecure` method")
    }

    // TODO: We can remove this from the public API
    pub fn blob_to_kzg_commitment(&self, blob_bytes: BlobBytes) -> Option<KZGCommitmentBytes> {
        let commitments = self.blobs_to_kzg_commitments(vec![blob_bytes])?;
        Some(commitments[0])
    }

    pub fn blobs_to_kzg_commitments(
        &self,
        blobs_bytes: Vec<BlobBytes>,
    ) -> Option<Vec<KZGCommitmentBytes>> {
        let polynomials = blobs_to_polynomials(blobs_bytes)?;

        let commitments: Vec<_> = self
            .public_parameters
            .commit_key
            .commit_multiple(&polynomials)
            .into_iter()
            .map(|comm| comm.to_compressed())
            .collect();

        Some(commitments)
    }

    pub fn compute_aggregated_kzg_proof(
        &self,
        blobs_bytes: Vec<BlobBytes>,
    ) -> Option<(KZGWitnessBytes, Vec<KZGCommitmentBytes>)> {
        let polynomials = blobs_to_polynomials(blobs_bytes)?;

        let blob_comms = self
            .public_parameters
            .commit_key
            .commit_multiple(&polynomials);

        let blob_comms_bytes: Vec<_> = blob_comms
            .iter()
            .map(|point| point.to_compressed())
            .collect();

        let aggregate_kzg = AggregatedKZG::from_polys(polynomials, blob_comms);

        let witness =
            aggregate_kzg.create(&self.public_parameters.commit_key, &self.roots_of_unity);

        Some((witness.to_compressed(), blob_comms_bytes))
    }

    pub fn verify_aggregated_kzg_proof(
        &self,
        blobs_bytes: Vec<BlobBytes>,
        blob_comms_bytes: Vec<KZGCommitmentBytes>,
        // This is known as `kzg_aggregated_proof` in the specs
        witness_comm_bytes: KZGWitnessBytes,
    ) -> Option<bool> {
        let polynomials = blobs_to_polynomials(blobs_bytes)?;
        let num_polys = polynomials.len();

        let mut poly_comms = Vec::with_capacity(num_polys);
        for comm_bytes in blob_comms_bytes {
            poly_comms.push(bytes_to_point(&comm_bytes)?)
        }

        let witness_comm = bytes_to_point(&witness_comm_bytes)?;

        let aggregate_kzg = AggregatedKZG::from_polys(polynomials, poly_comms);
        Some(aggregate_kzg.verify(
            &self.public_parameters.opening_key,
            witness_comm,
            &self.roots_of_unity,
        ))
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

fn blobs_to_polynomials(blobs_bytes: Vec<BlobBytes>) -> Option<Vec<Polynomial>> {
    let num_blobs = blobs_bytes.len();
    let mut polynomials = Vec::with_capacity(num_blobs);

    for blob_byte in blobs_bytes {
        polynomials.push(blob_bytes_to_polynomial(blob_byte)?);
    }

    Some(polynomials)
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
#[cfg(test)]
mod tests {
    use super::Context;
    use serde::Deserialize;
    #[derive(Debug, Deserialize)]
    struct BlobCommitTestCase {
        Blob: String,
        Commitment: String,
    }
    #[derive(Debug, Deserialize)]
    struct BlobCommit {
        BlobDegree: u64,
        NumTestCases: u64,
        TestCases: Vec<BlobCommitTestCase>,
    }
    #[derive(Debug, Deserialize)]
    struct AggTestCase {
        NumPolys: u64,
        PolyDegree: u64,
        Polynomials: Vec<String>,
        Proof: String,
        Commitments: Vec<String>,
    }
    #[derive(Debug, Deserialize)]
    struct AggProof {
        NumTestCases: u64,
        TestCases: Vec<AggTestCase>,
    }

    #[test]
    fn blob_commit_json_test() {
        let file = std::fs::File::open("./src/public_blob_commit.json").unwrap();
        let json: BlobCommit = serde_json::from_reader(file).expect("JSON was not well-formatted");

        let context = Context::new_insecure();
        for tc in json.TestCases {
            let blob_bytes = hex::decode(tc.Blob).unwrap();
            let comm = context.blob_to_kzg_commitment(blob_bytes).unwrap();

            let mut expected_comm = [0u8; 48];
            hex::decode_to_slice(tc.Commitment, &mut expected_comm[..]).unwrap();

            assert_eq!(expected_comm, comm)
        }
    }
    #[test]
    fn agg_proof_json_test() {
        let file = std::fs::File::open("./src/public_agg_proof.json").unwrap();
        let json: AggProof = serde_json::from_reader(file).expect("JSON was not well-formatted");

        let context = Context::new_insecure();
        for tc in json.TestCases {
            let mut blobs_bytes = Vec::new();
            for poly_str in tc.Polynomials {
                let blob_byte = hex::decode(poly_str).unwrap();
                blobs_bytes.push(blob_byte)
            }
            let (kzg_proof, comms_bytes) =
                context.compute_aggregated_kzg_proof(blobs_bytes).unwrap();
            assert_eq!(tc.Proof, hex::encode(kzg_proof));

            for (expected_comm, got_comm) in tc.Commitments.into_iter().zip(comms_bytes) {
                assert_eq!(expected_comm, hex::encode(got_comm))
            }
        }
    }
}
