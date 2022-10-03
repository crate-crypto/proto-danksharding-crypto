use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crypto::{
    test_utils::{random_polynomial, test_setup},
    AggregatedKZG, Polynomial,
};

fn random_matrix(poly_length: usize, num_polynomials: usize) -> Vec<Polynomial> {
    (0..num_polynomials)
        .into_iter()
        .map(|_| random_polynomial(poly_length))
        .collect()
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("compute aggregate kzg proof, no commitment", |b| {
        let poly_length = 2usize.pow(12);
        let num_polynomials = 16;

        b.iter_with_setup(
            || {
                let polys = random_matrix(poly_length, num_polynomials);
                let (pp, domain) = test_setup(poly_length);
                let poly_comms = pp.commit_key.commit_multiple(&polys);
                let agg = AggregatedKZG::from_polys(polys, poly_comms);

                (agg, pp.commit_key, domain)
            },
            |(agg, commit_key, domain)| agg.create(&commit_key, &domain),
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
