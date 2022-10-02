use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ff::Field;
use specs::{
    constants::{FIELD_ELEMENTS_PER_BLOB, MAX_BLOBS_PER_BLOCK},
    Blob, Context, Scalar,
};

#[inline]
fn fibonacci(n: u64) -> u64 {
    match n {
        0 => 1,
        1 => 1,
        n => fibonacci(n - 1) + fibonacci(n - 2),
    }
}

fn random_blob() -> Blob {
    let mut elements = vec![Scalar::random(&mut rand::thread_rng()); FIELD_ELEMENTS_PER_BLOB];
    Blob::new(elements)
}

fn random_blobs() -> Vec<Blob> {
    (0..MAX_BLOBS_PER_BLOCK)
        .into_iter()
        .map(|_| random_blob())
        .collect()
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("compute aggregate kzg", |b| {
        b.iter_with_setup(
            || {
                let context = Context::new_insecure();
                let blobs = random_blobs();
                (blobs, context)
            },
            |(blobs, context)| context.compute_aggregated_kzg_proof(blobs),
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
