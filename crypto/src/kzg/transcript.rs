use crate::{G1Point, Polynomial, Scalar};

/// Transcript is an abstraction over the Fiat-Shamir
/// heuristic
///
/// To be interopable with the specs, we do not include the usual domain separators
pub struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    pub fn new() -> Transcript {
        Transcript { bytes: Vec::new() }
    }

    fn append_bytes(&mut self, to_append: &[u8]) {
        self.bytes.extend(to_append)
    }

    pub fn append_polynomial(&mut self, poly: &Polynomial) {
        for eval in &poly.evaluations {
            let fr_bytes = eval.to_bytes_be();
            self.append_bytes(&fr_bytes)
        }
    }

    pub fn append_g1_point(&mut self, point: &G1Point) {
        self.append_bytes(&point.to_compressed());
    }

    pub fn challenge_scalar(&mut self) -> Scalar {
        use sha2::Digest;

        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.bytes);

        let hash_output = hasher.finalize();

        // Clear the buffer to be interopable with the specs
        self.bytes.clear();

        crate::arkworks::unreduced_bytes_to_scalar(&hash_output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{random_g1, random_polynomial};

    #[test]
    fn transcript_smoke() {
        let mut prover_transcript = Transcript::new();
        let mut verifier_transcript = Transcript::new();

        let rand_g1 = random_g1();
        let rand_polynomial = random_polynomial(2usize.pow(8));

        prover_transcript.append_bytes(&[1, 2, 3, 4, 5]);
        prover_transcript.append_g1_point(&rand_g1);
        prover_transcript.append_polynomial(&rand_polynomial);

        verifier_transcript.append_bytes(&[1, 2, 3, 4, 5]);
        verifier_transcript.append_g1_point(&rand_g1);
        verifier_transcript.append_polynomial(&rand_polynomial);

        let prover_challenge = prover_transcript.challenge_scalar();
        let verifier_challenge = verifier_transcript.challenge_scalar();

        // Both prover and verifier added the same messages
        // into their respective transcripts so they should squeeze out
        // the same challenge
        assert_eq!(prover_challenge, verifier_challenge);

        prover_transcript.append_bytes(&[1, 2, 3]);
        verifier_transcript.append_bytes(&[4, 5, 6]);

        let prover_challenge = prover_transcript.challenge_scalar();
        let verifier_challenge = verifier_transcript.challenge_scalar();

        assert_ne!(prover_challenge, verifier_challenge);
    }
    #[test]
    fn byte_extensions() {
        let mut prover_transcript = Transcript::new();
        let mut verifier_transcript = Transcript::new();

        prover_transcript.append_bytes(&[1, 2, 3, 4, 5, 6]);

        verifier_transcript.append_bytes(&[1, 2, 3]);
        verifier_transcript.append_bytes(&[4, 5, 6]);

        let prover_challenge = prover_transcript.challenge_scalar();
        let verifier_challenge = verifier_transcript.challenge_scalar();

        // This particular implementation of the transcript does not have domain separation
        // and simply concatenates the messages together
        // Hence, the prover and verifier will output the same challenge
        assert_eq!(prover_challenge, verifier_challenge);
    }
}
