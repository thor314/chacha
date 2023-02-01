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
// use typenum::consts::{U12, U32, U64};
// use typenum::{U12, U32, U64, U4, U6, U10};
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
    // cfg_if::cfg_if! {
    //   if #[cfg(feature = "simd")] {
    f.call(&mut portable_simd::Backend(self));
    //   } else {
    //     f.call(&mut software::Backend(self));
    //   }
    // }
  }
}

impl<const R: usize> StreamCipherSeekCore for ChaChaCore<R> {
  type Counter = u32;

  #[inline]
  fn get_block_pos(&self) -> Self::Counter { self.state[12] }

  #[inline]
  fn set_block_pos(&mut self, pos: Self::Counter) { self.state[12] = pos; }
}

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

      for (chunk, val) in block.chunks_exact_mut(4).zip(res.iter()) {
        chunk.copy_from_slice(&val.to_le_bytes());
      }
    }
  }

  #[inline(always)]
  fn run_rounds<const R: usize>(state: &[u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut res = *state;

    for _ in 0..R {
      // column rounds
      quarter_round(0, 4, 8, 12, &mut res);
      quarter_round(1, 5, 9, 13, &mut res);
      quarter_round(2, 6, 10, 14, &mut res);
      quarter_round(3, 7, 11, 15, &mut res);
      // diagonal rounds
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

// // TODO(TK): uncomment
// #[cfg(feature = "simd")]
mod portable_simd {
  use std::simd::u32x4;

  use cipher::{BlockSizeUser, ParBlocksSizeUser, StreamBackend};
  use once_cell::sync::Lazy;
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
    let res = *state;

    let mut chunks = res.array_chunks::<4>();
    let a = u32x4::from_array(*chunks.next().unwrap());
    let b = u32x4::from_array(*chunks.next().unwrap());
    let c = u32x4::from_array(*chunks.next().unwrap());
    let d = u32x4::from_array(*chunks.next().unwrap());
    let old = [a, b, c, d];

    let aa = a;
    let bb = b.rotate_lanes_left::<1>();
    let cc = c.rotate_lanes_left::<2>();
    let dd = d.rotate_lanes_left::<3>();

    for _ in 0..R {
      round(a, b, c, d); // vertical
      round(aa, bb, cc, dd); // diagonal
    }

    let mut out = [0; 16];
    for (i, v) in
      [a, b, c, d].into_iter().zip(old).flat_map(|(s, old)| *(s + old).as_array()).enumerate()
    {
      out[i] = v;
    }
    out
  }

  static S7: Lazy<u32x4> = Lazy::new(|| u32x4::splat(7));
  static S8: Lazy<u32x4> = Lazy::new(|| u32x4::splat(8));
  static S12: Lazy<u32x4> = Lazy::new(|| u32x4::splat(12));
  static S16: Lazy<u32x4> = Lazy::new(|| u32x4::splat(16));

  /// The ChaCha20 quarter round function
  #[allow(unused_assignments)]
  fn round(mut a: u32x4, mut b: u32x4, mut c: u32x4, mut d: u32x4) {
    // simd addition opreations are inherently wrapping
    a += b;
    d = (d ^ a) << *S16;

    c += d;
    b = (b ^ c) << *S12;

    a += b;
    d = (d ^ a) << *S8;

    c += d;
    b = (b ^ c) << *S7;
  }
  #[cfg(test)]
  mod test {
    use cipher::{KeyIvInit, StreamCipher};
    use hex_literal::hex;

    use super::*;
    use crate::chacha::{ChaCha20, Key, Nonce};

    // ChaCha20 test vectors from:
    // <https://datatracker.ietf.org/doc/html/rfc8439#section-2.4.2>

    const KEY: [u8; 32] = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    const IV: [u8; 12] = hex!("000000000000004a00000000");

    const PLAINTEXT: [u8; 114] = hex!(
      "
        4c616469657320616e642047656e746c
        656d656e206f662074686520636c6173
        73206f66202739393a20496620492063
        6f756c64206f6666657220796f75206f
        6e6c79206f6e652074697020666f7220
        746865206675747572652c2073756e73
        637265656e20776f756c642062652069
        742e
        "
    );

    const KEYSTREAM: [u8; 114] = hex!(
      "
        224f51f3401bd9e12fde276fb8631ded8c131f823d2c06
        e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b
        9334794cba40c63e34cdea212c4cf07d41b769a6749f3f
        630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53a
        c40c5945398b6eda1a832c89c167eacd901d7e2bf363
        "
    );

    const CIPHERTEXT: [u8; 114] = hex!(
      "
        6e2e359a2568f98041ba0728dd0d6981
        e97e7aec1d4360c20a27afccfd9fae0b
        f91b65c5524733ab8f593dabcd62b357
        1639d624e65152ab8f530c359f0861d8
        07ca0dbf500d6a6156a38e088a22b65e
        52bc514d16ccf806818ce91ab7793736
        5af90bbf74a35be6b40b8eedf2785e42
        874d
        "
    );

    #[test]
    fn chacha20_keystream() {
      let mut cipher = ChaCha20::new(&Key::from(KEY), &Nonce::from(IV));

      // The test vectors omit the first 64-bytes of the keystream
      let mut prefix = [0u8; 64];
      cipher.apply_keystream(&mut prefix);

      let mut buf = [0u8; 114];
      cipher.apply_keystream(&mut buf);
      assert_eq!(&buf[..], &KEYSTREAM[..]);
    }

    #[test]
    fn chacha20_encryption() {
      let mut cipher = ChaCha20::new(&Key::from(KEY), &Nonce::from(IV));
      let mut buf = PLAINTEXT;

      // The test vectors omit the first 64-bytes of the keystream
      let mut prefix = [0u8; 64];
      cipher.apply_keystream(&mut prefix);

      cipher.apply_keystream(&mut buf);
      assert_eq!(&buf[..], &CIPHERTEXT[..]);
    }
  }
}
