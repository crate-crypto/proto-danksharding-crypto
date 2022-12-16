use sha2::{
    digest::{FixedOutput, FixedOutputReset},
    Digest,
};

use crate::{G1Point, Polynomial, Scalar};

/// Transcript is an abstraction over the Fiat-Shamir
/// heuristic
///
/// To be interopable with the specs, we do not include the usual domain separators
pub struct Transcript {
    bytes: Vec<u8>,
    hashFn: sha2::Sha256,
}

// The number of bytes the hash function being used
// will need to represent the digest
const HASH_OUTPUT_SIZE: usize = 32;

// Domain separator to identify the protocol
pub const DOM_SEP_PROTOCOL: &str = "FSBLOBVERIFY_V1_";

impl Transcript {
    pub fn new() -> Transcript {
        Transcript {
            bytes: Vec::new(),
            hashFn: sha2::Sha256::new(),
        }
    }
    pub fn with_protocol_name(label: &'static str) -> Transcript {
        Transcript {
            bytes: label.as_bytes().to_vec(),
            hashFn: sha2::Sha256::new(),
        }
    }
    // hash bytes and reset hasher's internal state
    fn hash(&mut self, bytes: &[u8]) -> [u8; HASH_OUTPUT_SIZE] {
        self.hashFn.update(bytes);
        self.hashFn.finalize_fixed_reset().into()
    }

    // hash the transcripts internal state and reset the hasher's internal state
    fn hash_transcript(&mut self) -> [u8; HASH_OUTPUT_SIZE] {
        self.hashFn.update(&self.bytes);
        self.hashFn.finalize_fixed_reset().into()
    }

    fn append_bytes(&mut self, to_append: &[u8]) {
        self.bytes.extend(to_append)
    }

    pub fn append_polynomial(&mut self, poly: &Polynomial) {
        for eval in &poly.evaluations {
            let fr_bytes = eval.to_bytes_le();
            self.append_bytes(&fr_bytes)
        }
    }

    pub fn append_g1_point(&mut self, point: &G1Point) {
        self.append_bytes(&point.to_compressed());
    }

    pub fn append_polys_points(&mut self, polys: &[Polynomial], points: &[G1Point]) {
        let num_points = points.len();
        let num_polys = polys.len();
        if num_points != num_polys {
            panic!("number of points must equal the number of polynomials")
        }

        if num_points == 0 {
            panic!("number of points/polys must not be zero")
        }

        let poly_degree = polys[0].evaluations.len() as u64;
        self.append_bytes(&poly_degree.to_le_bytes());
        self.append_bytes(&(num_polys as u64).to_le_bytes());

        for poly in polys {
            self.append_polynomial(poly)
        }
        for point in points {
            self.append_g1_point(point)
        }
    }

    pub fn challenge_scalars(&mut self, num_challenges: u8) -> Vec<Scalar> {
        use ff::Field;

        // Compress the state
        let compressed_state = self.hash_transcript();

        let mut challenges = vec![Scalar::zero(); num_challenges as usize];
        for challenge_index in 0..num_challenges {
            let mut hash_input = compressed_state.clone().to_vec();
            hash_input.push(challenge_index);

            let challenge_hash = self.hash(&hash_input);

            challenges[challenge_index as usize] =
                crate::arkworks::unreduced_bytes_to_scalar(&challenge_hash)
        }

        self.bytes = compressed_state.to_vec();

        challenges
    }

    pub(crate) fn challenge_scalar(&mut self) -> Scalar {
        let scalars = self.challenge_scalars(1);
        scalars[0]
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

#[cfg(test)]
mod interop_tests {
    use group::{prime::PrimeCurveAffine, Group};

    use super::*;

    #[test]
    fn interop_basic_1() {
        let mut transcript = Transcript::with_protocol_name(DOM_SEP_PROTOCOL);
        let got = transcript_hex_challenge(&mut transcript);
        let expected = "585f39007d35d5dd2235c9ac951750bed15c5cf8fdbc685b81df8af7069bb26b";
        assert_eq!(got, expected);
    }

    fn transcript_hex_challenge(transcript: &mut Transcript) -> String {
        hex::encode(transcript.challenge_scalar().to_bytes_be())
    }

    #[test]
    fn interop_basic_2() {
        let mut transcript = Transcript::with_protocol_name(DOM_SEP_PROTOCOL);
        let poly_degree = 4096;
        let polynomial = Polynomial::new(vec![Scalar::from(0); poly_degree]);
        transcript.append_polynomial(&polynomial);

        let got = transcript_hex_challenge(&mut transcript);
        let expected = "655a158aa61ac277153c3aab84610b9079de88f075ee28396e89583957dcbdd4";
        assert_eq!(got, expected);
    }

    #[test]
    fn interop_basic_3() {
        let mut transcript = Transcript::with_protocol_name(DOM_SEP_PROTOCOL);
        let poly_degree = 4096;
        let num_polynomials = 10;

        let mut polynomials = Vec::with_capacity(num_polynomials);
        for i in 0..num_polynomials {
            polynomials.push(offset_poly(i as u64, poly_degree))
        }

        for poly in polynomials {
            transcript.append_polynomial(&poly);
        }

        let got = transcript_hex_challenge(&mut transcript);
        let expected = "151f8938fef5de0b713101ab1c24195a23933de54753dba0945f759e5eccd36d";
        assert_eq!(got, expected);
    }

    #[test]
    fn interop_basic_4() {
        let mut transcript = Transcript::with_protocol_name(DOM_SEP_PROTOCOL);
        let num_points = 123;

        for point in test_points(num_points) {
            transcript.append_g1_point(&point);
        }
        let expected = "226f81ef676186ea38e0c05efcb2f923f2fdb7542de3355d4ec11511579cea91";
        test_challenge(&mut transcript, expected)
    }

    #[test]
    fn interop_basic_5() {
        let mut transcript = Transcript::with_protocol_name(DOM_SEP_PROTOCOL);
        let num_points = 123;
        let poly_degree = 4096;

        let points = test_points(num_points);
        let polys = test_polys(num_points, poly_degree);

        transcript.append_polys_points(&polys, &points);

        let expected = "2f15f4e189fbe0f295e1261c940dc5363fddc7b32230092e2d7548caf012f550";
        test_challenge(&mut transcript, expected)
    }

    fn offset_poly(offset: u64, poly_degree: u64) -> Polynomial {
        let evals = (0..poly_degree).map(|i| Scalar::from(i + offset)).collect();
        Polynomial::new(evals)
    }

    fn test_polys(num_polys: usize, poly_degree: usize) -> Vec<Polynomial> {
        let mut polynomials = Vec::with_capacity(num_polys);
        for i in 0..num_polys {
            polynomials.push(offset_poly(i as u64, poly_degree as u64))
        }
        return polynomials;
    }
    fn test_points(num_points: usize) -> Vec<G1Point> {
        let mut result: Vec<G1Point> = Vec::new();

        let mut g1_gen = crate::G1Projective::generator();
        for i in 0..num_points {
            result.push(g1_gen.into());
            g1_gen = g1_gen.double()
        }

        return result;
    }

    fn test_challenge(transcript: &mut Transcript, expected: &'static str) {
        let got = transcript_hex_challenge(transcript);
        assert_eq!(got, expected);
    }
}
