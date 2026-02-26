//! For LICENSE check out https://github.com/0xPARC/plonky2-crypto-gadgets/blob/main/LICENSE
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![allow(dead_code)] // TMP

pub mod circuit_aes;
pub mod circuit_gcm;
pub mod constants;
pub mod native_aes;
pub mod native_gcm;

/// D defines the extension degree of the field used in the Plonky2 proofs (quadratic extension).
pub const D: usize = 2;

pub use circuit_gcm::AesGcmTarget;

// expose pre-defined configurations (AES-128, AES-192, AES-256):

pub type AesGcm128Target<const L: usize> = AesGcmTarget<4, 4, 10, L, false>;
pub const KEY_LEN_128: usize = 4 * 4;

pub const KEY_LEN_192: usize = 6 * 4;
pub type AesGcm192Target<const L: usize> = AesGcmTarget<6, 4, 12, L, false>;

pub const KEY_LEN_256: usize = 8 * 4;
pub type AesGcm256Target<const L: usize> = AesGcmTarget<8, 4, 14, L, false>;
