//! ChaCha, mostly ported from https://github.com/RustCrypto/stream-ciphers.
//! Main differences: Use min_const_generics wherever possible, and implement portable_simd.
//! We can't use min_const_generics for fulfilling associated types in traits, so those must remain
//! GenericArray.

use cipher::{
  BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, StreamCipherCore, StreamCipherCoreWrapper,
  StreamCipherSeekCore,
};
use generic_array::GenericArray;
use secrecy::DebugSecret;
use typenum::{U12, U32, U64};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// State initialization constant ("expand 32-byte k")
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Number of 32-bit words in the ChaCha state
const STATE_WORDS: usize = 16;

/// Block type used by all ChaCha variants. Must be GenericArray to satisfy trait bounds.
type Block = GenericArray<u8, U64>;

/// Key type used by all ChaCha variants. Must be GenericArray to satisfy trait bounds.
pub type Key = GenericArray<u8, U32>;

/// Nonce type used by ChaCha variants. Must be GenericArray to satisfy trait bounds.
pub type Nonce = GenericArray<u8, U12>;

/// ChaCha8 stream cipher (reduced-round variant of [`ChaCha20`] with 8 rounds)
pub type ChaCha8 = StreamCipherCoreWrapper<ChaChaCore<4>>;

/// ChaCha12 stream cipher (reduced-round variant of [`ChaCha20`] with 12 rounds)
pub type ChaCha12 = StreamCipherCoreWrapper<ChaChaCore<6>>;

/// ChaCha20 stream cipher (RFC 8439 version with 96-bit nonce)
pub type ChaCha20 = StreamCipherCoreWrapper<ChaChaCore<10>>;

/// Chacha core, generic over the number of rounds.
#[derive(ZeroizeOnDrop, Zeroize)]
pub struct ChaChaCore<const R: usize> {
  /// Internal 16-word state
  state: [u32; STATE_WORDS],
}

/// Redact core, which contains the secret key, from debug logs
impl<const R: usize> DebugSecret for ChaChaCore<R> {}

/// Key Initialization
impl<const R: usize> KeySizeUser for ChaChaCore<R> {
  type KeySize = U32;
}

/// Initial Value / Nonce Initialization
impl<const R: usize> IvSizeUser for ChaChaCore<R> {
  type IvSize = U12;
}

/// ChaChaCore processes data in blocks
impl<const R: usize> BlockSizeUser for ChaChaCore<R> {
  type BlockSize = U64;
}

/// Initialization vector (nonce) used by [`IvSizeUser`] implementors.
impl<const R: usize> KeyIvInit for ChaChaCore<R> {
  #[inline]
  fn new(key: &Key, iv: &Nonce) -> Self {
    let mut state = [0u32; STATE_WORDS];
    state[0..4].copy_from_slice(&CONSTANTS);
    let key_chunks = key.chunks_exact(4);
    for (val, chunk) in state[4..12].iter_mut().zip(key_chunks) {
      // casts &[u8] to &[u8; 4]
      *val = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    let iv_chunks = iv.chunks_exact(4);
    for (val, chunk) in state[13..16].iter_mut().zip(iv_chunks) {
      *val = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    Self { state }
  }
}

impl<const R: usize> StreamCipherCore for ChaChaCore<R> {
  /// Return number of remaining blocks before cipher wraps around.
  ///
  /// Returns `None` if number of remaining blocks can not be computed
  /// (e.g. in ciphers based on the sponge construction) or it's too big
  /// to fit into `usize`.
  ///
  /// This method returns `None` after the cipher has been called 2^32 times.
  #[inline]
  fn remaining_blocks(&self) -> Option<usize> {
    let rem = u32::MAX - self.get_block_pos();
    rem.try_into().ok()
  }

  /// Process data using backend provided to the rank-2 closure.
  fn process_with_backend(&mut self, f: impl cipher::StreamClosure<BlockSize = Self::BlockSize>) {
    cfg_if::cfg_if! {
      if #[cfg(feature = "simd")] {
        f.call(&mut portable_simd::Backend(self));
      } else if #[cfg(feature = "avx2")] {
        unsafe { avx2::inner::<R, _>(&mut self.state, f); }
      } else if #[cfg(feature = "sse2")] {
        unsafe { sse2::inner::<R, _>(&mut self.state, f); }
      } else {
        f.call(&mut software::Backend(self));
      }
    }
  }
}

impl<const R: usize> StreamCipherSeekCore for ChaChaCore<R> {
  type Counter = u32;

  #[inline]
  fn get_block_pos(&self) -> Self::Counter { self.state[12] }

  #[inline]
  fn set_block_pos(&mut self, pos: Self::Counter) { self.state[12] = pos; }
}

// ~5.2ms to encrypt 1MB of data
mod software {
  use cipher::{BlockSizeUser, ParBlocksSizeUser, StreamBackend};
  use typenum::consts::{U1, U64};

  use super::{Block, ChaChaCore, STATE_WORDS};

  pub(super) struct Backend<'a, const R: usize>(pub(super) &'a mut ChaChaCore<R>);

  impl<'a, const R: usize> BlockSizeUser for Backend<'a, R> {
    type BlockSize = U64;
  }
  impl<'a, const R: usize> ParBlocksSizeUser for Backend<'a, R> {
    type ParBlocksSize = U1;
  }

  impl<'a, const R: usize> StreamBackend for Backend<'a, R> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block) {
      let res = run_rounds::<R>(&self.0.state);
      self.0.state[12] = self.0.state[12].wrapping_add(1);

      for (chunk, val) in block.array_chunks_mut::<4>().zip(res.iter()) {
        chunk.copy_from_slice(&val.to_le_bytes());
      }
    }
  }

  #[inline(always)]
  fn run_rounds<const R: usize>(state: &[u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut res = *state;

    for _ in 0..R {
      quarter_round(0, 4, 8, 12, &mut res);
      quarter_round(1, 5, 9, 13, &mut res);
      quarter_round(2, 6, 10, 14, &mut res);
      quarter_round(3, 7, 11, 15, &mut res);

      quarter_round(0, 5, 10, 15, &mut res);
      quarter_round(1, 6, 11, 12, &mut res);
      quarter_round(2, 7, 8, 13, &mut res);
      quarter_round(3, 4, 9, 14, &mut res);
    }

    for (s1, s0) in res.iter_mut().zip(state.iter()) {
      *s1 = s1.wrapping_add(*s0);
    }
    res
  }

  /// The ChaCha20 quarter round function
  fn quarter_round(a: usize, b: usize, c: usize, d: usize, state: &mut [u32; STATE_WORDS]) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
  }
}

// note: 1.4x faster than software backend on x86_64
// 3.4ms to encrypt 1mb of data
#[cfg(feature = "simd")]
mod portable_simd {
  use core::simd::{simd_swizzle, u32x16, u32x4};

  use cipher::{BlockSizeUser, ParBlocksSizeUser, StreamBackend};
  use typenum::{U4, U64};

  use super::{Block, ChaChaCore, STATE_WORDS};

  pub(super) struct Backend<'a, const R: usize>(pub(super) &'a mut ChaChaCore<R>);

  impl<'a, const R: usize> BlockSizeUser for Backend<'a, R> {
    type BlockSize = U64;
  }
  impl<'a, const R: usize> ParBlocksSizeUser for Backend<'a, R> {
    type ParBlocksSize = U4;
  }

  impl<'a, const R: usize> StreamBackend for Backend<'a, R> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block) {
      let res = run_rounds::<R>(&self.0.state);
      self.0.state[12] = self.0.state[12].wrapping_add(1);

      for (chunk, val) in block.array_chunks_mut::<4>().zip(res.iter()) {
        chunk.copy_from_slice(&val.to_le_bytes());
      }
    }
  }

  #[inline(always)]
  fn run_rounds<const R: usize>(state: &[u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut vectors = [u32x4::default(); 4];
    for (i, chunk) in (*state).into_iter().array_chunks::<4>().enumerate() {
      vectors[i] = u32x4::from_array(chunk);
    }

    for _ in 0..R {
      round(&mut vectors);
      vectors[1] = vectors[1].rotate_lanes_left::<1>();
      vectors[3] = vectors[3].rotate_lanes_left::<3>();
      vectors[2] = vectors[2].rotate_lanes_left::<2>();
      round(&mut vectors);
      vectors[1] = vectors[1].rotate_lanes_right::<1>();
      vectors[2] = vectors[2].rotate_lanes_right::<2>();
      vectors[3] = vectors[3].rotate_lanes_right::<3>();
    }

    let mut res = [0; STATE_WORDS];
    vectors
      .iter_mut()
      .enumerate()
      .for_each(|(i, v)| res[(4 * i)..(4 * i + 4)].copy_from_slice(v.as_array()));

    for (s1, s0) in res.iter_mut().zip(state.iter()) {
      *s1 = s1.wrapping_add(*s0);
    }
    res
  }

  fn round(vectors: &mut [u32x4; 4]) {
    vectors[0] += vectors[1];
    vectors[3] ^= vectors[0];
    vectors[3] = u32x4::from_array(vectors[3].as_mut_array().map(|el| el.rotate_left(16)));

    vectors[2] += vectors[3];
    vectors[1] ^= vectors[2];
    vectors[1] = u32x4::from_array(vectors[1].as_mut_array().map(|el| el.rotate_left(12)));

    vectors[0] += vectors[1];
    vectors[3] ^= vectors[0];
    vectors[3] = u32x4::from_array(vectors[3].as_mut_array().map(|el| el.rotate_left(8)));

    vectors[2] += vectors[3];
    vectors[1] ^= vectors[2];
    vectors[1] = u32x4::from_array(vectors[1].as_mut_array().map(|el| el.rotate_left(7)));
  }

  mod slower {
    //! experiments that didn't pan out

    // failed experiment for speeding up bit-rotation
    // static S25: Lazy<u32x4> = Lazy::new(|| u32x4::splat(25));
    // static S24: Lazy<u32x4> = Lazy::new(|| u32x4::splat(24));
    // static S20: Lazy<u32x4> = Lazy::new(|| u32x4::splat(20));
    // static S16: Lazy<u32x4> = Lazy::new(|| u32x4::splat(16));
    // static S12: Lazy<u32x4> = Lazy::new(|| u32x4::splat(12));
    // static S8: Lazy<u32x4> = Lazy::new(|| u32x4::splat(8));
    // static S7: Lazy<u32x4> = Lazy::new(|| u32x4::splat(7));

    #![allow(dead_code)]
    use super::*;
    #[inline(always)]
    pub fn _run_rounds<const R: usize>(state: &[u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
      let lanes = u32x16::from_array(*state);
      let mut v0: u32x4 = simd_swizzle!(lanes, [0, 1, 2, 3]);
      let mut v1: u32x4 = simd_swizzle!(lanes, [4, 5, 6, 7]);
      let mut v2: u32x4 = simd_swizzle!(lanes, [8, 9, 10, 11]);
      let mut v3: u32x4 = simd_swizzle!(lanes, [12, 13, 14, 15]);

      // dbg!(v0, v1, v2, v3);
      for _ in 0..R {
        (v0, v1, v2, v3) = round(v0, v1, v2, v3);
        v1 = v1.rotate_lanes_left::<1>();
        v2 = v2.rotate_lanes_left::<2>();
        v3 = v3.rotate_lanes_left::<3>();
        (v0, v1, v2, v3) = round(v0, v1, v2, v3);
        v1 = v1.rotate_lanes_right::<1>();
        v2 = v2.rotate_lanes_right::<2>();
        v3 = v3.rotate_lanes_right::<3>();
      }

      // let mut res = [0; 16];
      // for ((val, idx), state_idx) in
      //   [v0, v1, v2, v3].into_iter().flat_map(|v|
      // v.to_array()).zip(res.iter_mut()).zip(state.iter()) {
      //   *idx = val.wrapping_add(*state_idx);
      // }
      // res

      // this is 40% slower...*shrug*
      // let mut res = *state;
      // for (r, x) in res.iter_mut().zip(vectors.iter().flat_map(|v| v.as_array())) {
      //   *r = r.wrapping_add(*x);
      // }

      let mut res = [0; STATE_WORDS];
      for (vec, chunk) in [v0, v1, v2, v3].into_iter().zip(res.array_chunks_mut::<4>()) {
        chunk.copy_from_slice(vec.as_array());
      }

      for (s1, s0) in res.iter_mut().zip(state.iter()) {
        *s1 = s1.wrapping_add(*s0);
      }
      res
    }

    fn round(
      mut v0: u32x4,
      mut v1: u32x4,
      mut v2: u32x4,
      mut v3: u32x4,
    ) -> (u32x4, u32x4, u32x4, u32x4) {
      v0 += v1;
      v3 ^= v0;
      v3 = u32x4::from_array(v3.as_mut_array().map(|el| el.rotate_left(16)));
      // there doesn't seem to be an efficient way to map bit-rotation across Simd types
      // v3 = (v3 << *S16) ^ (v3 >> *S16); // muuuch slower (2micros -> 4)

      v2 += v3;
      v1 ^= v2;
      v1 = u32x4::from_array(v1.as_mut_array().map(|el| el.rotate_left(12)));
      // v3 = (v3 << *S12) ^ (v3 >> *S20);

      v0 += v1;
      v3 ^= v0;
      v3 = u32x4::from_array(v3.as_mut_array().map(|el| el.rotate_left(8)));
      // v3 = (v3 << *S8) ^ (v3 >> *S24);

      v2 += v3;
      v1 ^= v2;
      v1 = u32x4::from_array(v1.as_mut_array().map(|el| el.rotate_left(7)));
      // v3 = (v3 << *S7) ^ (v3 >> *S25);
      (v0, v1, v2, v3)
    }
  }
}

// Code beneath this point is only included for benchmark comparison purposes, and is entirely
// copied from Rust Crypto, with a couple tweaks for const generics
//
// 1.7ms (about 3x faster than software)
#[cfg(feature = "sse2")]
mod sse2 {
  #[cfg(target_arch = "x86")] use core::arch::x86::*;
  #[cfg(target_arch = "x86_64")] use core::arch::x86_64::*;

  use cipher::{
    consts::{U1, U64},
    BlockSizeUser, ParBlocksSizeUser, StreamBackend, StreamClosure,
  };

  use super::{Block, STATE_WORDS};

  #[inline]
  #[target_feature(enable = "sse2")]
  #[allow(dead_code)]
  pub(crate) unsafe fn inner<const R: usize, F>(state: &mut [u32; STATE_WORDS], f: F)
  where F: StreamClosure<BlockSize = U64> {
    let state_ptr = state.as_ptr() as *const __m128i;
    let mut backend = Backend::<R> {
      v: [
        _mm_loadu_si128(state_ptr.add(0)),
        _mm_loadu_si128(state_ptr.add(1)),
        _mm_loadu_si128(state_ptr.add(2)),
        _mm_loadu_si128(state_ptr.add(3)),
      ],
    };

    f.call(&mut backend);

    state[12] = _mm_cvtsi128_si32(backend.v[3]) as u32;
  }

  struct Backend<const R: usize> {
    v: [__m128i; 4],
  }

  impl<const R: usize> BlockSizeUser for Backend<R> {
    type BlockSize = U64;
  }

  impl<const R: usize> ParBlocksSizeUser for Backend<R> {
    type ParBlocksSize = U1;
  }

  impl<const R: usize> StreamBackend for Backend<R> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block) {
      unsafe {
        let res = rounds::<R>(&self.v);
        self.v[3] = _mm_add_epi32(self.v[3], _mm_set_epi32(0, 0, 0, 1));

        let block_ptr = block.as_mut_ptr() as *mut __m128i;
        (0..4).for_each(|i| {
          _mm_storeu_si128(block_ptr.add(i), res[i]);
        });
      }
    }
  }

  #[inline]
  #[target_feature(enable = "sse2")]
  unsafe fn rounds<const R: usize>(v: &[__m128i; 4]) -> [__m128i; 4] {
    let mut res = *v;
    for _ in 0..R {
      // experiments::_double_quarter_round(&mut res);
      double_quarter_round(&mut res);
    }

    for i in 0..4 {
      res[i] = _mm_add_epi32(res[i], v[i]);
    }

    res
  }

  #[inline]
  #[target_feature(enable = "sse2")]
  unsafe fn double_quarter_round(v: &mut [__m128i; 4]) {
    add_xor_rot(v);
    rows_to_cols(v);
    add_xor_rot(v);
    cols_to_rows(v);
  }

  /// The goal of this function is to transform the state words from:
  /// ```text
  /// [a0, a1, a2, a3]    [ 0,  1,  2,  3]
  /// [b0, b1, b2, b3] == [ 4,  5,  6,  7]
  /// [c0, c1, c2, c3]    [ 8,  9, 10, 11]
  /// [d0, d1, d2, d3]    [12, 13, 14, 15]
  /// ```
  ///
  /// to:
  /// ```text
  /// [a0, a1, a2, a3]    [ 0,  1,  2,  3]
  /// [b1, b2, b3, b0] == [ 5,  6,  7,  4]
  /// [c2, c3, c0, c1]    [10, 11,  8,  9]
  /// [d3, d0, d1, d2]    [15, 12, 13, 14]
  /// ```
  ///
  /// so that we can apply [`add_xor_rot`] to the resulting columns, and have it compute the
  /// "diagonal rounds" (as defined in RFC 7539) in parallel. In practice, this shuffle is
  /// non-optimal: the last state word to be altered in `add_xor_rot` is `b`, so the shuffle
  /// blocks on the result of `b` being calculated.
  ///
  /// We can optimize this by observing that the four quarter rounds in `add_xor_rot` are
  /// data-independent: they only access a single column of the state, and thus the order of
  /// the columns does not matter. We therefore instead shuffle the other three state words,
  /// to obtain the following equivalent layout:
  /// ```text
  /// [a3, a0, a1, a2]    [ 3,  0,  1,  2]
  /// [b0, b1, b2, b3] == [ 4,  5,  6,  7]
  /// [c1, c2, c3, c0]    [ 9, 10, 11,  8]
  /// [d2, d3, d0, d1]    [14, 15, 12, 13]
  /// ```
  ///
  /// See https://github.com/sneves/blake2-avx2/pull/4 for additional details. The earliest
  /// known occurrence of this optimization is in floodyberry's SSE4 ChaCha code from 2014:
  /// - https://github.com/floodyberry/chacha-opt/blob/0ab65cb99f5016633b652edebaf3691ceb4ff753/chacha_blocks_ssse3-64.S#L639-L643
  #[inline]
  #[target_feature(enable = "sse2")]
  unsafe fn rows_to_cols([a, _, c, d]: &mut [__m128i; 4]) {
    // c >>>= 32; d >>>= 64; a >>>= 96;
    *c = _mm_shuffle_epi32(*c, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    *d = _mm_shuffle_epi32(*d, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    *a = _mm_shuffle_epi32(*a, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
  }

  /// The goal of this function is to transform the state words from:
  /// ```text
  /// [a3, a0, a1, a2]    [ 3,  0,  1,  2]
  /// [b0, b1, b2, b3] == [ 4,  5,  6,  7]
  /// [c1, c2, c3, c0]    [ 9, 10, 11,  8]
  /// [d2, d3, d0, d1]    [14, 15, 12, 13]
  /// ```
  ///
  /// to:
  /// ```text
  /// [a0, a1, a2, a3]    [ 0,  1,  2,  3]
  /// [b0, b1, b2, b3] == [ 4,  5,  6,  7]
  /// [c0, c1, c2, c3]    [ 8,  9, 10, 11]
  /// [d0, d1, d2, d3]    [12, 13, 14, 15]
  /// ```
  ///
  /// reversing the transformation of [`rows_to_cols`].
  #[inline]
  #[target_feature(enable = "sse2")]
  unsafe fn cols_to_rows([a, _, c, d]: &mut [__m128i; 4]) {
    // c <<<= 32; d <<<= 64; a <<<= 96;
    *c = _mm_shuffle_epi32(*c, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    *d = _mm_shuffle_epi32(*d, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    *a = _mm_shuffle_epi32(*a, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
  }

  #[inline]
  #[target_feature(enable = "sse2")]
  unsafe fn add_xor_rot([a, b, c, d]: &mut [__m128i; 4]) {
    // a += b; d ^= a; d <<<= (16, 16, 16, 16);
    *a = _mm_add_epi32(*a, *b);
    *d = _mm_xor_si128(*d, *a);
    *d = _mm_xor_si128(_mm_slli_epi32(*d, 16), _mm_srli_epi32(*d, 16));

    // c += d; b ^= c; b <<<= (12, 12, 12, 12);
    *c = _mm_add_epi32(*c, *d);
    *b = _mm_xor_si128(*b, *c);
    *b = _mm_xor_si128(_mm_slli_epi32(*b, 12), _mm_srli_epi32(*b, 20));

    // a += b; d ^= a; d <<<= (8, 8, 8, 8);
    *a = _mm_add_epi32(*a, *b);
    *d = _mm_xor_si128(*d, *a);
    *d = _mm_xor_si128(_mm_slli_epi32(*d, 8), _mm_srli_epi32(*d, 24));

    // c += d; b ^= c; b <<<= (7, 7, 7, 7);
    *c = _mm_add_epi32(*c, *d);
    *b = _mm_xor_si128(*b, *c);
    *b = _mm_xor_si128(_mm_slli_epi32(*b, 7), _mm_srli_epi32(*b, 25));
  }

  mod experiments {
    #![allow(dead_code)]
    use super::*;
    #[inline]
    #[target_feature(enable = "sse2")]
    pub unsafe fn _double_quarter_round(v: &mut [__m128i; 4]) {
      _add_xor_rot(v);
      _rows_to_cols(v);
      _add_xor_rot(v);
      _cols_to_rows(v);
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn _rows_to_cols([_, b, c, d]: &mut [__m128i; 4]) {
      *b = _mm_shuffle_epi32(*c, 0b_00_11_10_01); // shift left 1
      *c = _mm_shuffle_epi32(*c, 0b_01_00_11_10); // shift 2
      *d = _mm_shuffle_epi32(*c, 0b_10_01_00_11); // shift 3
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn _cols_to_rows([_, b, c, d]: &mut [__m128i; 4]) {
      *b = _mm_shuffle_epi32(*c, 0b_10_01_00_11); // shift right 1
      *c = _mm_shuffle_epi32(*c, 0b_01_00_11_10); // shift 2
      *d = _mm_shuffle_epi32(*c, 0b_00_11_10_01); // shift 3
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn _add_xor_rot([a, b, c, d]: &mut [__m128i; 4]) {
      // a += b; d ^= a; d <<<= (16, 16, 16, 16);
      *a = _mm_add_epi32(*a, *b);
      *d = _mm_xor_si128(*d, *a);
      *d = _mm_xor_si128(_mm_slli_epi32(*d, 16), _mm_srli_epi32(*d, 16));

      // c += d; b ^= c; b <<<= (12, 12, 12, 12);
      *c = _mm_add_epi32(*c, *d);
      *b = _mm_xor_si128(*b, *c);
      *b = _mm_xor_si128(_mm_slli_epi32(*b, 12), _mm_srli_epi32(*b, 20));

      // a += b; d ^= a; d <<<= (8, 8, 8, 8);
      *a = _mm_add_epi32(*a, *b);
      *d = _mm_xor_si128(*d, *a);
      *d = _mm_xor_si128(_mm_slli_epi32(*d, 8), _mm_srli_epi32(*d, 24));

      // c += d; b ^= c; b <<<= (7, 7, 7, 7);
      *c = _mm_add_epi32(*c, *d);
      *b = _mm_xor_si128(*b, *c);
      *b = _mm_xor_si128(_mm_slli_epi32(*b, 7), _mm_srli_epi32(*b, 25));
    }
  }
}

// 597us (about 9x faster than software)
#[cfg(feature = "avx2")]
mod avx2 {
  #[cfg(target_arch = "x86")] use core::arch::x86::*;
  #[cfg(target_arch = "x86_64")] use core::arch::x86_64::*;

  use cipher::{
    consts::{U4, U64},
    BlockSizeUser, ParBlocks, ParBlocksSizeUser, StreamBackend, StreamClosure,
  };

  use super::{Block, STATE_WORDS};

  /// Number of blocks processed in parallel.
  const PAR_BLOCKS: usize = 4;
  /// Number of `__m256i` to store parallel blocks.
  const N: usize = PAR_BLOCKS / 2;

  #[inline]
  #[target_feature(enable = "avx2")]
  #[allow(dead_code)]
  pub(crate) unsafe fn inner<const R: usize, F>(state: &mut [u32; STATE_WORDS], f: F)
  where F: StreamClosure<BlockSize = U64> {
    let state_ptr = state.as_ptr() as *const __m128i;
    let v = [
      _mm256_broadcastsi128_si256(_mm_loadu_si128(state_ptr.add(0))),
      _mm256_broadcastsi128_si256(_mm_loadu_si128(state_ptr.add(1))),
      _mm256_broadcastsi128_si256(_mm_loadu_si128(state_ptr.add(2))),
    ];
    let mut c = _mm256_broadcastsi128_si256(_mm_loadu_si128(state_ptr.add(3)));
    c = _mm256_add_epi32(c, _mm256_set_epi32(0, 0, 0, 1, 0, 0, 0, 0));
    let mut ctr = [c; N];
    (0..N).for_each(|i| {
      ctr[i] = c;
      c = _mm256_add_epi32(c, _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 2));
    });
    let mut backend = Backend::<R> { v, ctr };

    f.call(&mut backend);

    state[12] = _mm256_extract_epi32(backend.ctr[0], 0) as u32;
  }

  struct Backend<const R: usize> {
    v:   [__m256i; 3],
    ctr: [__m256i; N],
  }

  impl<const R: usize> BlockSizeUser for Backend<R> {
    type BlockSize = U64;
  }

  impl<const R: usize> ParBlocksSizeUser for Backend<R> {
    type ParBlocksSize = U4;
  }

  impl<const R: usize> StreamBackend for Backend<R> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block) {
      unsafe {
        let res = rounds::<R>(&self.v, &self.ctr);
        for c in self.ctr.iter_mut() {
          *c = _mm256_add_epi32(*c, _mm256_set_epi32(0, 0, 0, 1, 0, 0, 0, 1));
        }

        let res0: [__m128i; 8] = core::mem::transmute(res[0]);

        let block_ptr = block.as_mut_ptr() as *mut __m128i;
        for i in 0..4 {
          _mm_storeu_si128(block_ptr.add(i), res0[2 * i]);
        }
      }
    }

    #[inline(always)]
    fn gen_par_ks_blocks(&mut self, blocks: &mut ParBlocks<Self>) {
      unsafe {
        let vs = rounds::<R>(&self.v, &self.ctr);

        let pb = PAR_BLOCKS as i32;
        for c in self.ctr.iter_mut() {
          *c = _mm256_add_epi32(*c, _mm256_set_epi32(0, 0, 0, pb, 0, 0, 0, pb));
        }

        let mut block_ptr = blocks.as_mut_ptr() as *mut __m128i;
        for v in vs {
          let t: [__m128i; 8] = core::mem::transmute(v);
          for i in 0..4 {
            _mm_storeu_si128(block_ptr.add(i), t[2 * i]);
            _mm_storeu_si128(block_ptr.add(4 + i), t[2 * i + 1]);
          }
          block_ptr = block_ptr.add(8);
        }
      }
    }
  }

  #[inline]
  #[target_feature(enable = "avx2")]
  unsafe fn rounds<const R: usize>(v: &[__m256i; 3], c: &[__m256i; N]) -> [[__m256i; 4]; N] {
    let mut vs: [[__m256i; 4]; N] = [[_mm256_setzero_si256(); 4]; N];
    for i in 0..N {
      vs[i] = [v[0], v[1], v[2], c[i]];
    }
    for _ in 0..R {
      double_quarter_round(&mut vs);
    }

    for i in 0..N {
      (0..3).for_each(|j| vs[i][j] = _mm256_add_epi32(vs[i][j], v[j]));
      vs[i][3] = _mm256_add_epi32(vs[i][3], c[i]);
    }

    vs
  }

  #[inline]
  #[target_feature(enable = "avx2")]
  unsafe fn double_quarter_round(v: &mut [[__m256i; 4]; N]) {
    add_xor_rot(v);
    rows_to_cols(v);
    add_xor_rot(v);
    cols_to_rows(v);
  }

  /// The goal of this function is to transform the state words from:
  /// ```text
  /// [a0, a1, a2, a3]    [ 0,  1,  2,  3]
  /// [b0, b1, b2, b3] == [ 4,  5,  6,  7]
  /// [c0, c1, c2, c3]    [ 8,  9, 10, 11]
  /// [d0, d1, d2, d3]    [12, 13, 14, 15]
  /// ```
  ///
  /// to:
  /// ```text
  /// [a0, a1, a2, a3]    [ 0,  1,  2,  3]
  /// [b1, b2, b3, b0] == [ 5,  6,  7,  4]
  /// [c2, c3, c0, c1]    [10, 11,  8,  9]
  /// [d3, d0, d1, d2]    [15, 12, 13, 14]
  /// ```
  ///
  /// so that we can apply [`add_xor_rot`] to the resulting columns, and have it compute the
  /// "diagonal rounds" (as defined in RFC 7539) in parallel. In practice, this shuffle is
  /// non-optimal: the last state word to be altered in `add_xor_rot` is `b`, so the shuffle
  /// blocks on the result of `b` being calculated.
  ///
  /// We can optimize this by observing that the four quarter rounds in `add_xor_rot` are
  /// data-independent: they only access a single column of the state, and thus the order of
  /// the columns does not matter. We therefore instead shuffle the other three state words,
  /// to obtain the following equivalent layout:
  /// ```text
  /// [a3, a0, a1, a2]    [ 3,  0,  1,  2]
  /// [b0, b1, b2, b3] == [ 4,  5,  6,  7]
  /// [c1, c2, c3, c0]    [ 9, 10, 11,  8]
  /// [d2, d3, d0, d1]    [14, 15, 12, 13]
  /// ```
  ///
  /// See https://github.com/sneves/blake2-avx2/pull/4 for additional details. The earliest
  /// known occurrence of this optimization is in floodyberry's SSE4 ChaCha code from 2014:
  /// - https://github.com/floodyberry/chacha-opt/blob/0ab65cb99f5016633b652edebaf3691ceb4ff753/chacha_blocks_ssse3-64.S#L639-L643
  #[inline]
  #[target_feature(enable = "avx2")]
  unsafe fn rows_to_cols(vs: &mut [[__m256i; 4]; N]) {
    // c >>>= 32; d >>>= 64; a >>>= 96;
    for [a, _, c, d] in vs {
      *c = _mm256_shuffle_epi32(*c, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
      *d = _mm256_shuffle_epi32(*d, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
      *a = _mm256_shuffle_epi32(*a, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    }
  }

  /// The goal of this function is to transform the state words from:
  /// ```text
  /// [a3, a0, a1, a2]    [ 3,  0,  1,  2]
  /// [b0, b1, b2, b3] == [ 4,  5,  6,  7]
  /// [c1, c2, c3, c0]    [ 9, 10, 11,  8]
  /// [d2, d3, d0, d1]    [14, 15, 12, 13]
  /// ```
  ///
  /// to:
  /// ```text
  /// [a0, a1, a2, a3]    [ 0,  1,  2,  3]
  /// [b0, b1, b2, b3] == [ 4,  5,  6,  7]
  /// [c0, c1, c2, c3]    [ 8,  9, 10, 11]
  /// [d0, d1, d2, d3]    [12, 13, 14, 15]
  /// ```
  ///
  /// reversing the transformation of [`rows_to_cols`].
  #[inline]
  #[target_feature(enable = "avx2")]
  unsafe fn cols_to_rows(vs: &mut [[__m256i; 4]; N]) {
    // c <<<= 32; d <<<= 64; a <<<= 96;
    for [a, _, c, d] in vs {
      *c = _mm256_shuffle_epi32(*c, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
      *d = _mm256_shuffle_epi32(*d, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
      *a = _mm256_shuffle_epi32(*a, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    }
  }

  #[inline]
  #[target_feature(enable = "avx2")]
  unsafe fn add_xor_rot(vs: &mut [[__m256i; 4]; N]) {
    let rol16_mask = _mm256_set_epi64x(
      0x0d0c_0f0e_0908_0b0a,
      0x0504_0706_0100_0302,
      0x0d0c_0f0e_0908_0b0a,
      0x0504_0706_0100_0302,
    );
    let rol8_mask = _mm256_set_epi64x(
      0x0e0d_0c0f_0a09_080b,
      0x0605_0407_0201_0003,
      0x0e0d_0c0f_0a09_080b,
      0x0605_0407_0201_0003,
    );

    // a += b; d ^= a; d <<<= (16, 16, 16, 16);
    for [a, b, _, d] in vs.iter_mut() {
      *a = _mm256_add_epi32(*a, *b);
      *d = _mm256_xor_si256(*d, *a);
      *d = _mm256_shuffle_epi8(*d, rol16_mask);
    }

    // c += d; b ^= c; b <<<= (12, 12, 12, 12);
    for [_, b, c, d] in vs.iter_mut() {
      *c = _mm256_add_epi32(*c, *d);
      *b = _mm256_xor_si256(*b, *c);
      *b = _mm256_xor_si256(_mm256_slli_epi32(*b, 12), _mm256_srli_epi32(*b, 20));
    }

    // a += b; d ^= a; d <<<= (8, 8, 8, 8);
    for [a, b, _, d] in vs.iter_mut() {
      *a = _mm256_add_epi32(*a, *b);
      *d = _mm256_xor_si256(*d, *a);
      *d = _mm256_shuffle_epi8(*d, rol8_mask);
    }

    // c += d; b ^= c; b <<<= (7, 7, 7, 7);
    for [_, b, c, d] in vs.iter_mut() {
      *c = _mm256_add_epi32(*c, *d);
      *b = _mm256_xor_si256(*b, *c);
      *b = _mm256_xor_si256(_mm256_slli_epi32(*b, 7), _mm256_srli_epi32(*b, 25));
    }
  }
}
