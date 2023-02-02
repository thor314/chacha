#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
// https://bheisler.github.io/criterion.rs/book/index.html

use cipher::{KeyIvInit, StreamCipher};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tkcrypto::chacha::*;

const KB: usize = 1024;

pub fn bench(c: &mut Criterion) {
  let key = Default::default();
  let iv = Default::default();
  let mut cipher = ChaCha8::new(&key, &iv);
  let mut buf = vec![1u8; KB];

  c.bench_function("bench", |b| b.iter(|| cipher.apply_keystream(black_box(&mut buf))));
}

criterion_group!(benches, bench);
criterion_main!(benches);
