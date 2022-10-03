# Proto-Danksharding Cryptography

## Usage 

```rust
// Create a context. This is insecure as it uses a \tau
// which is known
let context = Context::new_insecure();

// Prover
let blobs = ...
let proof = context.compute_aggregated_kzg_proof(blobs);

// Verifier
//
let blob_comms = context.blobs_to_kzg_commitments(blobs);
let valid = context.verify_aggregated_kzg_proof(blobs, blob_comms, proof);
assert!(valid)
``

## Benchmarks

- `cargo bench --features insecure`

## Specs 

<https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/validator.md#compute_proof_from_blobs>

