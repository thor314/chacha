#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
// https://bheisler.github.io/criterion.rs/book/index.html

use cipher::{KeyIvInit, StreamCipher};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tkcrypto::chacha::*;

const MB: usize = 1024*1024;

pub fn bench(c: &mut Criterion) {
  // encrypt a MB of data
  let key = Default::default();
  let iv = Default::default();
  let mut cipher = ChaCha20::new(&key, &iv);
  let mut buf = vec![1u8; MB];

  c.bench_function("bench", |b| b.iter(|| cipher.apply_keystream(black_box(&mut buf))));
}

criterion_group!(benches, bench);
criterion_main!(benches);
