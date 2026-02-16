//! Run in real mode: `cargo run --release --example aes_gcm_256`
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
    const L: usize = 42; // size (bytes) of plaintext to encrypt

    let key: &[u8; KEY_LEN_256] = &[42; KEY_LEN_256];
    let nonce: &[u8; 12] = &[111; 12];
    let pt: &[u8; L] = &[42u8; L];

    let (ct, tag) = plonky2_aes::native_gcm::encrypt::<8, 4, 14>(key, nonce, pt);

    // Circuit declaration
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let aes_targets = AesGcm256Target::<L>::new_virtual(&mut builder);
    aes_targets.build_circuit(&mut builder);

    println!(
        "AES-GCM-256 circuit (L:{}) num_gates: {}",
        L,
        builder.num_gates()
    );

    let data = builder.build::<PoseidonGoldilocksConfig>();

    // set values to circuit
    let mut pw = PartialWitness::<F>::new();
    aes_targets.set_targets(&mut pw, key, nonce, pt, &ct, &tag)?;

    let proof = data.prove(pw)?;
    data.verify(proof)
}
