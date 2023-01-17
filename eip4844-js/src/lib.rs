use js_sys::{Array, Uint8Array};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
mod utils;

#[wasm_bindgen]
pub struct Context(eip4844::Context);

#[wasm_bindgen]
pub enum ContextError {
    FailedToCommit,
}

impl From<ContextError> for JsValue {
    fn from(value: ContextError) -> Self {
        match value {
            ContextError::FailedToCommit => JsValue::from_str("failed to commit"),
        }
    }
}

#[wasm_bindgen]
impl Context {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Context {
        utils::set_panic_hook();
        Context(eip4844::Context::new_insecure())
    }

    pub fn blob_to_kzg_commitment(&self, blob_bytes: Uint8Array) -> Option<Uint8Array> {
        let blob_bytes = blob_bytes.to_vec();
        let comm_bytes = self.0.blob_to_kzg_commitment(blob_bytes)?;
        Some(Uint8Array::from(comm_bytes.as_slice()))
    }

    pub fn compute_aggregated_kzg_proof(&self, blobs_bytes: Array) -> Option<Array> {
        let blobs_bytes = js_blobs_to_rust_blobs(blobs_bytes);

        let (proof, comms) = self.0.compute_aggregated_kzg_proof(blobs_bytes)?;

        Some(rust_aggregated_proof_data_to_js_aggregated_proof_data(
            proof, comms,
        ))
    }

    pub fn verify_aggregated_kzg_proof(
        &self,
        blobs_bytes: Array,
        blob_comms_bytes: Array,
        witness_comm_bytes: Uint8Array,
    ) -> Option<bool> {
        let blobs_bytes = js_blobs_to_rust_blobs(blobs_bytes);
        let blob_comms_bytes = js_commitments_to_rust_commitments(blob_comms_bytes)?;
        let witness_comm_bytes = js_bytes_to_rust_commitment(witness_comm_bytes)?;

        self.0
            .verify_aggregated_kzg_proof(blobs_bytes, blob_comms_bytes, witness_comm_bytes)
    }

    pub fn verify_kzg_proof(
        &self,
        commitment: Uint8Array,
        input_point: Uint8Array,
        claimed_value: Uint8Array,
        proof: Uint8Array,
    ) -> Option<bool> {
        let commitment = js_bytes_to_rust_commitment(commitment)?;
        let input_point = js_bytes_to_rust_scalar(input_point)?;
        let claimed_value = js_bytes_to_rust_scalar(claimed_value)?;
        let proof = js_bytes_to_rust_commitment(proof)?;

        self.0
            .verify_kzg_proof(commitment, input_point, claimed_value, proof)
    }

    // TODO: This does not give a result in the generated typescript
    // lets call it so it returns a value to see what actually happens
    // -- From docs, it should throw, so we should catch this in JS
    /// @throws {Err}
    pub fn throws_hello(value: u8) -> Result<u8, ContextError> {
        if value % 2 == 0 {
            Ok(value)
        } else {
            Err(ContextError::FailedToCommit)
        }
    }
}

// conversion methods to convert between javascript types and rust types
fn js_blobs_to_rust_blobs(arr: Array) -> Vec<eip4844::BlobBytes> {
    arr.entries()
        .into_iter()
        .map(|entry| {
            let entry = entry.unwrap();
            Uint8Array::from(entry).to_vec()
        })
        .collect()
}
fn rust_blobs_to_js_blobs(blob_bytes: Vec<eip4844::BlobBytes>) -> Array {
    let mut arr = Array::new_with_length(blob_bytes.len() as u32);
    for (index, blob) in blob_bytes.into_iter().enumerate() {
        arr.set(index as u32, Uint8Array::from(blob.as_slice()).into())
    }
    arr
}
fn js_commitments_to_rust_commitments(comms: Array) -> Option<Vec<eip4844::SerialisedPoint>> {
    let mut commitments = Vec::with_capacity(comms.length() as usize);

    for entry in comms.entries() {
        let comm_js = entry.unwrap();
        let bytes = Uint8Array::from(comm_js);
        commitments.push(js_bytes_to_rust_commitment(bytes)?)
    }

    Some(commitments)
}
fn rust_commitments_to_js_commitments(comms: Vec<eip4844::SerialisedPoint>) -> Array {
    let arr = Array::new_with_length(comms.len() as u32);
    for (index, comm) in comms.into_iter().enumerate() {
        arr.set(index as u32, Uint8Array::from(comm.as_slice()).into())
    }
    arr
}
fn js_bytes_to_rust_commitment(bytes: Uint8Array) -> Option<eip4844::SerialisedPoint> {
    Uint8Array::from(bytes).to_vec().try_into().ok()
}
fn js_bytes_to_rust_scalar(bytes: Uint8Array) -> Option<eip4844::SerialisedScalar> {
    Uint8Array::from(bytes).to_vec().try_into().ok()
}

fn rust_aggregated_proof_data_to_js_aggregated_proof_data(
    proof: eip4844::KZGWitnessBytes,
    commitments: Vec<eip4844::KZGCommitmentBytes>,
) -> Array {
    // Javascript doesn't support tuples, so we use Arrays

    // First item is the proof and second item are the commitments
    let arr = Array::new_with_length(2);

    arr.set(0, Uint8Array::from(proof.as_slice()).into());

    let comm_arr = Array::new_with_length(commitments.len() as u32);
    for (index, comm) in commitments.into_iter().enumerate() {
        comm_arr.set(index as u32, Uint8Array::from(comm.as_slice()).into())
    }
    // Second item is the array of commitments
    arr.set(1, comm_arr.into());

    arr
}
