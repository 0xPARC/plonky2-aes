//! Run: `cargo run --release --example aes_gcm_256`
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField as F,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
        config::PoseidonGoldilocksConfig,
    },
};
use plonky2_aes::{AesGcm256Target, D, KEY_LEN_256};

fn main() -> Result<()> {
    // max size (bytes) of plaintext supported by the instantiation of the circuit
    const L: usize = 42;

    let key: &[u8; KEY_LEN_256] = &[123; KEY_LEN_256];
    let nonce: &[u8; 12] = &[111; 12];
    let pt: &[u8; L] = &[231u8; L]; // plaintext

    // use external rust library to compute the ciphertext & tag
    let nonce_ext = aes_gcm::Nonce::from_slice(nonce);
    use aes_gcm::{KeyInit, aead::Aead}; // needed traits
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(key.as_slice()).unwrap();
    let encrypt_res = cipher.encrypt(nonce_ext, pt.as_ref()).unwrap();
    let ct = &encrypt_res[..L]; // ciphertext
    let tag = &encrypt_res[L..];

    // alternatively we could use this repo's rust implementation (only for tests)
    // let (ct, tag) = plonky2_aes::native_gcm::encrypt::<8, 4, 14>(key, nonce, pt);

    // circuit declaration
    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let aes_targets = AesGcm256Target::<L>::build(&mut builder);

    println!(
        "AES-GCM-256 circuit (L:{}) num_gates: {}",
        L,
        builder.num_gates()
    );

    let data = builder.build::<PoseidonGoldilocksConfig>();

    // set values to circuit
    let mut pw = PartialWitness::<F>::new();
    aes_targets.set_targets(&mut pw, key, nonce, pt, ct, tag)?;

    let proof = data.prove(pw)?;
    data.verify(proof)
}
