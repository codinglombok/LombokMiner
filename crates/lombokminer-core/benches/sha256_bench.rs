use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lombokminer_core::hash::{sha256d, sha256_midstate, sha256_from_midstate};

fn bench_sha256d_80(c: &mut Criterion) {
    let data = [0x42u8; 80];
    c.bench_function("sha256d_80", |b| {
        b.iter(|| sha256d(black_box(&data)))
    });
}

fn bench_midstate(c: &mut Criterion) {
    let header = [0x42u8; 80];
    let first: [u8; 64] = header[..64].try_into().unwrap();
    let last: [u8; 16] = header[64..].try_into().unwrap();
    let midstate = sha256_midstate(&first);

    c.bench_function("sha256d_from_midstate", |b| {
        b.iter(|| sha256_from_midstate(black_box(&midstate), black_box(&last)))
    });
}

criterion_group!(benches, bench_sha256d_80, bench_midstate);
criterion_main!(benches);
