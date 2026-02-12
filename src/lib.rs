//! For LICENSE check out https://github.com/0xPARC/plonky2-aes/blob/main/LICENSE
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
