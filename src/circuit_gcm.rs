//! For LICENSE check out https://github.com/0xPARC/plonky2-aes/blob/main/LICENSE

use std::{array, sync::Arc};

use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField as F, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    circuit_aes::{xor, ByteArrayTarget as ByteTarget, CircuitBuilderAESState, StateTarget},
    D,
};

/// L: max size of plaintext to cipher.
fn gctr_target<const NR: usize, const L: usize>(
    builder: &mut CircuitBuilder<F, D>,
    sbox_lut_idx: usize,
    mix_matrix: [[ByteTarget; 4]; 4],
    key: [[ByteTarget; 4]; 4 * (NR + 1)],
    icb: &[ByteTarget; 16],
    x: &[ByteTarget; L],
) -> [ByteTarget; L] {
    let n = ((L * 8) as f64 / 128_f64).ceil() as usize;

    let mut y: [ByteTarget; L] = x.clone();
    let mut cb_i = *icb;

    let zero_byte = builder.zero_byte();
    for (i, x_i_raw) in x.chunks(16).enumerate() {
        if i > 0 {
            cb_i = inc32_target(builder, cb_i);
        }

        let l = x_i_raw.len().min(16);
        let mut x_i = [zero_byte; 16];
        x_i[..l].copy_from_slice(x_i_raw);

        let ciph_cb_i = builder
            .encrypt_block::<NR>(sbox_lut_idx, mix_matrix, StateTarget::from_flat(cb_i), key)
            .flatten();

        let (y_i, n_bytes) = if i < n && x_i_raw.len() == 16 {
            (xor_blocks(builder, x_i, ciph_cb_i), 16)
        } else {
            // last chunk, might be smaller than 16 bytes (L%16 bytes)
            let msb_res = msb_t(builder, L % 16, ciph_cb_i.as_slice());
            let l = msb_res.len().min(16);
            let mut m: [ByteTarget; 16] = [zero_byte; 16];
            m[..l].copy_from_slice(&msb_res);
            (xor_blocks(builder, x_i, m), l)
        };
        y[i * 16..i * 16 + n_bytes].clone_from_slice(&y_i[..n_bytes]);
    }
    y
}

pub fn inc32_target(
    builder: &mut CircuitBuilder<F, D>,
    block: [ByteTarget; 16],
) -> [ByteTarget; 16] {
    let mut r = block;

    let mut carry = BoolTarget::new_unsafe(builder.one());
    for byte_index in (12..16).rev() {
        for bit_index in 0..8 {
            let a = block[byte_index][bit_index];
            // builder.assert_bool(a); // TODO we can assume it's valid bool, skip check

            let sum = xor(builder, a, carry);

            let carry_out = builder.and(a, carry);

            r[byte_index][bit_index] = sum;
            carry = carry_out;
        }
    }
    r
}

fn xor_byte(builder: &mut CircuitBuilder<F, D>, b1: ByteTarget, b2: ByteTarget) -> ByteTarget {
    array::from_fn(|i| xor(builder, b1[i], b2[i]))
}

fn xor_blocks(
    builder: &mut CircuitBuilder<F, D>,
    b1: [ByteTarget; 16],
    b2: [ByteTarget; 16],
) -> [ByteTarget; 16] {
    array::from_fn(|i| xor_byte(builder, b1[i], b2[i]))
}

pub fn msb_t(
    builder: &mut CircuitBuilder<F, D>,
    t_bytes: usize,
    block: &[ByteTarget],
) -> Vec<ByteTarget> {
    let t = t_bytes * 8;

    let full_bytes = t / 8;
    let rem_bits = t % 8;

    let mut out: Vec<ByteTarget> = Vec::new();

    for i in 0..full_bytes {
        out.push(block[i]);
    }

    let zero_bool = BoolTarget::new_unsafe(builder.zero());
    if rem_bits != 0 {
        let mut partial = [zero_bool; 8];

        for bit in 0..8 {
            if bit < rem_bits {
                partial[bit] = block[full_bytes][bit];
            } else {
                partial[bit] = zero_bool;
            }
        }

        out.push(partial);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::array;

    use anyhow::Result;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField as F, types::Field},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use rand::RngExt;

    use super::*;
    use crate::{
        circuit_aes::{sbox_lut, state_mix_matrix_bits, PartialWitnessByteArray},
        native_aes::key_expansion,
        native_gcm::gctr,
    };

    use super::D;

    #[test]
    fn test_gctr() -> Result<()> {
        // AES-GCM-128
        test_gctr_opt::<4, 4, 10, 13>()?;
        test_gctr_opt::<4, 4, 10, 17>()?;

        // AES-GCM-256
        test_gctr_opt::<8, 4, 14, 13>()?;

        Ok(())
    }

    fn test_gctr_opt<const NK: usize, const NB: usize, const NR: usize, const L: usize>(
    ) -> Result<()>
    where
        [(); 4 * (NR + 1)]:,
        [(); NK * NB]:,
    {
        let key: &[u8; NK * NB] = &[42; NK * NB];
        let expanded_key = key_expansion::<NK, NB, NR>(key);
        let nonce: &[u8; 12] = &[111; 12];
        let icb: &[u8; 16] = &[222; 16];
        let pt: &[u8; L] = &[42u8; L];

        let expected = gctr(expanded_key, &icb, pt);

        // Circuit declaration
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let key_target: [ByteTarget; NK * NB] =
            array::from_fn(|_| array::from_fn(|_| builder.add_virtual_bool_target_safe()));
        let nonce_target: [ByteTarget; 12] =
            array::from_fn(|_| array::from_fn(|_| builder.add_virtual_bool_target_safe()));
        let icb_target: [ByteTarget; 16] =
            array::from_fn(|_| array::from_fn(|_| builder.add_virtual_bool_target_safe()));
        let pt_target: [ByteTarget; L] =
            array::from_fn(|_| array::from_fn(|_| builder.add_virtual_bool_target_safe()));
        let sbox_lut = sbox_lut(&mut builder);
        let mix_matrix = state_mix_matrix_bits(&mut builder);

        let key_expanded_target = builder.key_expansion::<NK, NB, NR>(sbox_lut, key_target);
        let gctr_out_target = gctr_target::<NR, L>(
            &mut builder,
            sbox_lut,
            mix_matrix,
            key_expanded_target,
            &icb_target,
            &pt_target,
        );

        println!(
            "encrypt_block (NK:{}, NB:{}, NR:{}, L:{}) num_gates: {}",
            NK,
            NB,
            NR,
            L,
            builder.num_gates()
        );
        let data = builder.build::<PoseidonGoldilocksConfig>();

        // set values to circuit
        let mut pw = PartialWitness::<F>::new();
        std::iter::zip(key_target, key).try_for_each(|(t, v)| pw.set_byte_array_target(t, *v))?;
        std::iter::zip(nonce_target, nonce)
            .try_for_each(|(t, v)| pw.set_byte_array_target(t, *v))?;
        std::iter::zip(icb_target, icb).try_for_each(|(t, v)| pw.set_byte_array_target(t, *v))?;
        std::iter::zip(pt_target, pt).try_for_each(|(t, v)| pw.set_byte_array_target(t, *v))?;

        std::iter::zip(gctr_out_target, expected)
            .try_for_each(|(t, v)| pw.set_byte_array_target(t, v))?;

        let proof = data.prove(pw)?;
        data.verify(proof)
    }
}
