pub mod constants;
mod permutation;

use crypto::{
    AggregatedKZG, G1Point, KZGCommitment, KZGWitness, Polynomial, PublicParameters, RootsOfUnity,
};
use permutation::Permutable;

// What this library calls a `KZGWitness` the spec calls a `KZGProof`

pub struct Context {
    public_parameters: PublicParameters,
    roots_of_unity: RootsOfUnity,
}

pub use crypto::Scalar;

pub type Blob = Polynomial;
pub type Blobs = Vec<Polynomial>;

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

    pub fn new(_trusted_setup_json: String) -> Self {
        todo!("The trusted setup has not been completed. For testing use the `insecure` method")
    }

    // Taken from specs
    pub fn blob_to_kzg_commitment(&self, blob: &Blob) -> KZGCommitment {
        self.public_parameters.commit_key.commit(blob)
    }

    // Additional:
    // This method is here for two reasons:
    // - This pattern of committing to multiple blobs is in the specs
    // - CGO imposes a cost to calling a function.
    pub fn blobs_to_kzg_commitments(&self, blobs: &[Blob]) -> Vec<KZGCommitment> {
        self.public_parameters.commit_key.commit_multiple(blobs)
    }

    // This is `compute_proof_from_blobs`
    // Can change name back to this, it's only named this
    // so one can notice that its counter part is `verify_aggregated_kzg_proof`
    pub fn compute_aggregated_kzg_proof(&self, blobs: Vec<Blob>) -> KZGWitness {
        let blob_comms = self.blobs_to_kzg_commitments(&blobs);

        let aggregate_kzg = AggregatedKZG::from_polys(blobs, blob_comms);

        let witness =
            aggregate_kzg.create(&self.public_parameters.commit_key, &self.roots_of_unity);

        witness
    }
    // This is the crypto part from `validate_blobs_sidecar`
    //
    // The code would then look like:
    /*
        pub fn validate_blobs_sidecar(..) {
            # Blockchain checks go here
            validate_blobs(aggregated_poly, )
        }
    */
    pub fn verify_aggregated_kzg_proof(
        &self,
        blobs: Vec<Blob>,
        blob_comms: Vec<G1Point>,
        // This is known as `kzg_aggregated_proof` in the specs
        witness_comm: KZGWitness,
    ) -> bool {
        let aggregate_kzg = AggregatedKZG::from_polys(blobs, blob_comms);
        aggregate_kzg.verify(
            &self.public_parameters.opening_key,
            witness_comm,
            &self.roots_of_unity,
        )
    }

    // pub fn compute_kzg_proof(&self, poly: &Blob, input_point: Scalar) -> KZGProof {
    //     let proof = CryptoKZGProof::create_without_poly_commitment(
    //         &self.public_parameters.commit_key,
    //         poly,
    //         input_point,
    //         &self.roots_of_unity.domain(),
    //     );

    //     // Return only the commitment to the witness to be spec compliant
    //     proof.quotient_commitment
    // }
    // pub fn verify_kzg_proof(&self) {}
    // pub fn evaluate_polynomial_in_evaluation_form(&self) {}
}
