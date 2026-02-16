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

use circuit_aes::ByteArrayTarget as ByteTarget;
use circuit_gcm::encrypt_target;
use native_gcm::TAG_LEN;
use plonky2::{
    field::goldilocks_field::GoldilocksField as F, plonk::circuit_builder::CircuitBuilder,
};

pub fn aes128_encrypt_target<const L: usize>(
    builder: &mut CircuitBuilder<F, D>,
    key: [ByteTarget; 4 * 4],
    nonce: &[ByteTarget; 12],
    pt: &[ByteTarget; L],
) -> ([ByteTarget; L], [ByteTarget; TAG_LEN / 8]) {
    encrypt_target::<4, 4, 10, L, false>(builder, key, &nonce, &pt)
}

pub fn aes192_encrypt_target<const L: usize>(
    builder: &mut CircuitBuilder<F, D>,
    key: [ByteTarget; 6 * 4],
    nonce: &[ByteTarget; 12],
    pt: &[ByteTarget; L],
) -> ([ByteTarget; L], [ByteTarget; TAG_LEN / 8]) {
    encrypt_target::<6, 4, 12, L, false>(builder, key, &nonce, &pt)
}

pub fn aes256_encrypt_target<const L: usize>(
    builder: &mut CircuitBuilder<F, D>,
    key: [ByteTarget; 8 * 4],
    nonce: &[ByteTarget; 12],
    pt: &[ByteTarget; L],
) -> ([ByteTarget; L], [ByteTarget; TAG_LEN / 8]) {
    encrypt_target::<8, 4, 14, L, false>(builder, key, &nonce, &pt)
}
