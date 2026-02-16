//! For LICENSE check out https://github.com/0xPARC/plonky2-aes/blob/main/LICENSE
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![allow(dead_code)] // TMP

mod circuit_aes;
mod constants;
mod native_aes;
mod native_gcm;

/// D defines the extension degree of the field used in the Plonky2 proofs (quadratic extension).
pub const D: usize = 2;
