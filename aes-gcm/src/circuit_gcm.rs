//! For LICENSE check out https://github.com/0xPARC/plonky2-crypto-gadgets/blob/main/LICENSE
//!
//! Plonky2 circuit implementation of
//! [AES-GCM (Galois Counter Mode)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).

use std::{array, sync::Arc};

use anyhow::Result;
use plonky2::{
    field::{goldilocks_field::GoldilocksField as F, types::Field},
    iop::{target::BoolTarget, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    D,
    circuit_aes::{
        ByteTarget, CircuitBuilderAESState, PartialWitnessByteArray, StateTarget, byte_xor,
        byte_xor_lut, gf_2_8_mul_lut, sbox_lut, state_mix_matrix_bits,
    },
    constants::TAG_LEN,
};

pub struct AesGcmTarget<
    const NK: usize,
    const NB: usize,
    const NR: usize,
    // L: max size of plaintext to cipher.
    const L: usize,
    const TAG: bool,
> where
    [(); NK * NB]:,
    [(); 4 * (NR + 1)]:,
{
    key: [ByteTarget; NK * NB],
    nonce: [ByteTarget; 12],
    pt: [ByteTarget; L],

    ct: [ByteTarget; L],
    tag: [ByteTarget; TAG_LEN / 8],
}

impl<const NK: usize, const NB: usize, const NR: usize, const L: usize, const TAG: bool>
    AesGcmTarget<NK, NB, NR, L, TAG>
where
    [(); NK * NB]:,
    [(); 4 * (NR + 1)]:,
{
    pub fn build(builder: &mut CircuitBuilder<F, D>) -> Self {
        // add targets
        let key: [ByteTarget; NK * NB] = array::from_fn(|_| builder.add_virtual_target());
        let nonce: [ByteTarget; 12] = array::from_fn(|_| builder.add_virtual_target());
        let pt: [ByteTarget; L] = array::from_fn(|_| builder.add_virtual_target());

        let tag: [ByteTarget; TAG_LEN / 8] = array::from_fn(|_| builder.add_virtual_target());

        let sbox_lut = sbox_lut(builder);
        let xor_lut = byte_xor_lut(builder);
        let gf_2_8_mul_lut = gf_2_8_mul_lut(builder);
        let mix_matrix = state_mix_matrix_bits(builder);

        let a: &[ByteTarget] = &[]; // additional authenticated data

        let expanded_key = builder.key_expansion::<NK, NB, NR>(xor_lut, sbox_lut, key);

        let empty_state = builder.empty_state();

        // 1. CIPH_K
        let h = builder
            .encrypt_block::<NR>(
                xor_lut,
                gf_2_8_mul_lut,
                sbox_lut,
                mix_matrix,
                empty_state,
                expanded_key,
            )
            .flatten();

        // 2. J_0
        let zero_byte = builder.zero_byte();
        let one_byte = builder.one();
        let j0: [ByteTarget; 16] = if nonce.len() * 8 == 96 {
            // J_0 = IV || 0^31 || 1
            let mut out = [zero_byte; 16];
            out[..12].copy_from_slice(nonce.as_slice());
            out[12..16].copy_from_slice(&[zero_byte, zero_byte, zero_byte, one_byte]);
            out
        } else {
            panic!("unsupported at initial version; nonce.len()=12 (96 bits)");
        };

        // 3. C=GCTR()
        let inc32_j0 = inc32_target(builder, j0);
        let ct = gctr_target::<NR, L>(
            builder,
            (xor_lut, gf_2_8_mul_lut, sbox_lut),
            mix_matrix,
            expanded_key,
            &inc32_j0,
            &pt,
        );

        // the rest of the logic is for the tag; for some use cases we might skip it
        // (saving a notable amount of gates, about double)
        if !TAG {
            return Self {
                key,
                nonce,
                pt,
                ct,
                tag,
            };
        }

        // 4. u, v
        let u: usize = 16 * (L as f64 / 16_f64).ceil() as usize - L; // L=x.len()
        let v: usize = 16 * (a.len() as f64 / 16_f64).ceil() as usize - a.len();

        // 5. S = GHASH()
        let const_a_len_u8: [u8; 8] = (a.len() * 8).to_be_bytes(); // const
        let const_c_len_u8: [u8; 8] = (ct.len() * 8).to_be_bytes(); // const
        let a_len: [ByteTarget; 8] =
            array::from_fn(|byte_i| builder.constant(F::from_canonical_u8(const_a_len_u8[byte_i])));
        let c_len: [ByteTarget; 8] =
            array::from_fn(|byte_i| builder.constant(F::from_canonical_u8(const_c_len_u8[byte_i])));
        let ghash_input_vec = [
            a.to_vec(),
            vec![zero_byte; v],
            ct.to_vec(),
            vec![zero_byte; u],
            a_len.to_vec(),
            c_len.to_vec(),
        ]
        .concat();

        let u8_unit_right_shift_lut_idx = u8_unit_right_shift_lut(builder);
        let u8_bitref_lut_idx = u8_bitref_lut(builder);
        let s = ghash_target(
            builder,
            xor_lut,
            u8_unit_right_shift_lut_idx,
            u8_bitref_lut_idx,
            h,
            ghash_input_vec,
        );

        // 6. T=MSB(GCTR()))
        let msb_input = gctr_target(
            builder,
            (xor_lut, gf_2_8_mul_lut, sbox_lut),
            mix_matrix,
            expanded_key,
            &j0,
            &s,
        );
        let t_vec = msb_t_target(TAG_LEN / 8, &msb_input);

        std::iter::zip(tag, t_vec).for_each(|(a, b)| builder.connect(a, b));

        Self {
            key,
            nonce,
            pt,
            ct,
            tag,
        }
    }

    pub fn set_targets(
        &self,
        pw: &mut PartialWitness<F>,
        key: &[u8; NK * NB],
        nonce: &[u8; 12],
        pt: &[u8],
        ct: &[u8],
        tag: &[u8],
    ) -> Result<()> {
        assert!(pt.len() <= L);
        assert!(ct.len() <= L);
        assert!(tag.len() <= TAG_LEN / 8);

        // extend to expected sizes
        let mut pt_arr: [u8; L] = [0u8; L];
        pt_arr.copy_from_slice(pt);
        let mut ct_arr: [u8; L] = [0u8; L];
        ct_arr.copy_from_slice(ct);
        let mut tag_arr: [u8; TAG_LEN / 8] = [0u8; TAG_LEN / 8];
        tag_arr.copy_from_slice(tag);

        std::iter::zip(self.key, key).try_for_each(|(t, v)| pw.set_byte_array_target(t, *v))?;
        std::iter::zip(self.nonce, nonce).try_for_each(|(t, v)| pw.set_byte_array_target(t, *v))?;
        std::iter::zip(self.pt, pt_arr).try_for_each(|(t, v)| pw.set_byte_array_target(t, v))?;

        std::iter::zip(self.ct, ct_arr).try_for_each(|(t, v)| pw.set_byte_array_target(t, v))?;
        if TAG {
            std::iter::zip(self.tag, tag_arr)
                .try_for_each(|(t, v)| pw.set_byte_array_target(t, v))?;
        } else {
            self.tag
                .iter()
                .try_for_each(|t| pw.set_byte_array_target(*t, 0u8))?;
        }
        Ok(())
    }
}

/// L: max size of plaintext to cipher.
fn gctr_target<const NR: usize, const L: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lut_indices: (usize, usize, usize),
    mix_matrix: [[ByteTarget; 4]; 4],
    key: [[ByteTarget; 4]; 4 * (NR + 1)],
    icb: &[ByteTarget; 16],
    x: &[ByteTarget; L],
) -> [ByteTarget; L] {
    let (xor_lut_idx, gf_2_8_mul_lut_idx, sbox_lut_idx) = lut_indices;
    let n = ((L * 8) as f64 / 128_f64).ceil() as usize;

    let mut y: [ByteTarget; L] = *x;
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
            .encrypt_block::<NR>(
                xor_lut_idx,
                gf_2_8_mul_lut_idx,
                sbox_lut_idx,
                mix_matrix,
                StateTarget::from_flat(cb_i),
                key,
            )
            .flatten();

        let (y_i, n_bytes) = if i < n && x_i_raw.len() == 16 {
            (xor_blocks(builder, xor_lut_idx, x_i, ciph_cb_i), 16)
        } else {
            // last chunk, might be smaller than 16 bytes (L%16 bytes)
            let msb_res = msb_t_target(L % 16, ciph_cb_i.as_slice());
            let l = msb_res.len().min(16);
            let mut m: [ByteTarget; 16] = [zero_byte; 16];
            m[..l].copy_from_slice(&msb_res);
            (xor_blocks(builder, xor_lut_idx, x_i, m), l)
        };
        y[i * 16..i * 16 + n_bytes].clone_from_slice(&y_i[..n_bytes]);
    }
    y
}

fn ghash_target(
    builder: &mut CircuitBuilder<F, D>,
    xor_lut_idx: usize,
    u8_unit_right_shift_lut_idx: usize,
    u8_bitref_lut_idx: usize,
    h: [ByteTarget; 16],
    x: Vec<ByteTarget>,
) -> [ByteTarget; 16] {
    assert!(x.len().is_multiple_of(16)); // multiple of 128 bits
    let m = x.len() / 16;

    let zero_byte = builder.zero_byte();
    let mut y = [zero_byte; 16]; // (128 bits)
    for i in 0..m {
        let mut xi = [zero_byte; 16];
        xi.clone_from_slice(&x[i * 16..i * 16 + 16]);
        let y_xi = xor_blocks(builder, xor_lut_idx, y, xi);
        y = gf_2_128_mul_target(
            builder,
            xor_lut_idx,
            u8_unit_right_shift_lut_idx,
            u8_bitref_lut_idx,
            y_xi,
            h,
        );
    }
    y
}
fn gf_2_128_mul_target(
    builder: &mut CircuitBuilder<F, D>,
    xor_lut_idx: usize,
    u8_unit_right_shift_lut_idx: usize,
    u8_bitref_lut_idx: usize,
    x: [ByteTarget; 16],
    y: [ByteTarget; 16],
) -> [ByteTarget; 16] {
    let zero = builder.zero();

    // R: 10000111 (= 225) || 0^120 (in little-endian)
    let r_first = builder.constant(F::from_canonical_u8(225));

    let mut z = [zero; 16];
    let mut v = y;
    for i in 0..128 {
        let byte_index = i / 8;
        let bit_index = 7 - (i % 8);
        let bit_idx_target = builder.constant(F::from_canonical_usize(bit_index));
        let xi = BoolTarget::new_unsafe(u8_bitref(
            builder,
            u8_bitref_lut_idx,
            x[byte_index],
            bit_idx_target,
        ));

        // set z = if xi==1: z^v, else: z
        for b in 0..16 {
            let z_xor_v = byte_xor(builder, xor_lut_idx, z[b], v[b]);
            z[b] = builder.select(xi, z_xor_v, z[b]);
        }

        let lsb = BoolTarget::new_unsafe(u8_bitref(builder, u8_bitref_lut_idx, v[15], zero)); // (little-endian)

        v = right_shift_one_target(builder, u8_unit_right_shift_lut_idx, &v);

        // if lsb==1: v=v^R, else: v
        let v_xor_r = byte_xor(builder, xor_lut_idx, v[0], r_first);
        v[0] = builder.select(lsb, v_xor_r, v[0]);
    }
    z
}
pub fn right_shift_one_target(
    builder: &mut CircuitBuilder<F, D>,
    u8_unit_right_shift_lut_idx: usize,
    v: &[ByteTarget; 16],
) -> [ByteTarget; 16] {
    let mut r: [ByteTarget; 16] = *v;

    let mut carry = builder.zero();
    for i in 0..16 {
        let current = v[i];
        let mut shifted = u8_unit_right_shift(builder, u8_unit_right_shift_lut_idx, current);
        let next_carry =
            builder.mul_const_add(F::from_canonical_u64(2) * F::NEG_ONE, shifted, current);

        shifted = builder.mul_const_add(F::from_canonical_u64(1 << 7), carry, shifted);

        r[i] = shifted;
        carry = next_carry;
    }
    r
}

pub fn inc32_target(
    builder: &mut CircuitBuilder<F, D>,
    block: [ByteTarget; 16],
) -> [ByteTarget; 16] {
    let mut r = block;
    let zero = builder.zero();
    let u8_max = builder.constant(F::from_canonical_u8(u8::MAX));

    let mut carry = builder.one();
    for byte_index in (12..16).rev() {
        let a = block[byte_index];
        let sum = builder.add(a, carry);
        let a_is_u8_max = builder.is_equal(a, u8_max);
        let carry_out = builder.mul(carry, a_is_u8_max.target);
        r[byte_index] = builder.select(a_is_u8_max, zero, sum);
        carry = carry_out;
    }
    r
}

fn xor_blocks(
    builder: &mut CircuitBuilder<F, D>,
    xor_lut_idx: usize,
    b1: [ByteTarget; 16],
    b2: [ByteTarget; 16],
) -> [ByteTarget; 16] {
    array::from_fn(|i| byte_xor(builder, xor_lut_idx, b1[i], b2[i]))
}

pub fn msb_t_target(t_bytes: usize, block: &[ByteTarget]) -> Vec<ByteTarget> {
    // Always dealing with full bytes in circuit.
    let full_bytes = t_bytes;

    let mut out: Vec<ByteTarget> = Vec::new();
    for block_i in block.iter().take(full_bytes) {
        out.push(*block_i);
    }

    out
}

/// Lookup table for unit right-shift of elements of u8.
pub fn u8_unit_right_shift_lut(builder: &mut CircuitBuilder<F, D>) -> usize {
    let u8_unit_right_shift_table: Vec<(u16, u16)> = (0..=u8::MAX as usize)
        .map(|x| (x as u16, (x as u16) >> 1))
        .collect();
    builder.add_lookup_table_from_pairs(Arc::new(u8_unit_right_shift_table))
}
pub fn u8_unit_right_shift(
    builder: &mut CircuitBuilder<F, D>,
    u8_unit_right_shift_lut_idx: usize,
    x: ByteTarget,
) -> ByteTarget {
    builder.add_lookup_from_index(x, u8_unit_right_shift_lut_idx)
}

/// Lookup table for u8 bit referencing.
pub fn u8_bitref_lut(builder: &mut CircuitBuilder<F, D>) -> usize {
    let u8_bitref_table: Vec<(u16, u16)> = (0..=u8::MAX as usize)
        .flat_map(|x| {
            (0..8)
                .map(|i| (((x as u16) << 3) + i as u16, ((x as u16) >> i) & 1))
                .collect::<Vec<_>>()
        })
        .collect();
    builder.add_lookup_table_from_pairs(Arc::new(u8_bitref_table))
}
pub fn u8_bitref(
    builder: &mut CircuitBuilder<F, D>,
    u8_bitref_lut_idx: usize,
    x: ByteTarget,
    i: ByteTarget,
) -> ByteTarget {
    let lookup_idx = builder.mul_const_add(F::from_canonical_u64(8), x, i);
    builder.add_lookup_from_index(lookup_idx, u8_bitref_lut_idx)
}

fn le_bits_from_byte(v: u8) -> [bool; 8] {
    let v_bits = (0..8)
        .scan(v, |st, _| {
            let cur_bit = (*st % 2) != 0;
            *st >>= 1;
            Some(cur_bit)
        })
        .collect::<Vec<_>>();
    array::from_fn(|i| v_bits[i])
}

#[cfg(test)]
mod tests {
    use std::array;

    use anyhow::Result;
    use plonky2::{
        field::goldilocks_field::GoldilocksField as F,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use super::{D, *};
    use crate::{
        circuit_aes::{PartialWitnessByteArray, byte_xor_lut, gf_2_8_mul_lut},
        native_aes::key_expansion,
        native_gcm::{gctr, gf_2_128_mul, ghash, right_shift_one},
    };

    #[test]
    fn test_gctr() -> Result<()> {
        // AES-GCM-128
        test_gctr_opt::<4, 4, 10, 13>()?;
        test_gctr_opt::<4, 4, 10, 17>()?;

        // AES-GCM-256
        test_gctr_opt::<8, 4, 14, 13>()?;

        Ok(())
    }
    fn test_gctr_opt<const NK: usize, const NB: usize, const NR: usize, const L: usize>()
    -> Result<()>
    where
        [(); 4 * (NR + 1)]:,
        [(); NK * NB]:,
    {
        let key: &[u8; NK * NB] = &[42; NK * NB];
        let expanded_key = key_expansion::<NK, NB, NR>(key);
        let nonce: &[u8; 12] = &[111; 12];
        let icb: &[u8; 16] = &[222; 16];
        let pt: &[u8; L] = &[42u8; L];

        let expected = gctr(expanded_key, icb, pt);

        // Circuit declaration
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let key_target: [ByteTarget; NK * NB] = array::from_fn(|_| builder.add_virtual_target());
        let nonce_target: [ByteTarget; 12] = array::from_fn(|_| builder.add_virtual_target());
        let icb_target: [ByteTarget; 16] = array::from_fn(|_| builder.add_virtual_target());
        let pt_target: [ByteTarget; L] = array::from_fn(|_| builder.add_virtual_target());
        let sbox_lut = sbox_lut(&mut builder);
        let xor_lut = byte_xor_lut(&mut builder);
        let gf_2_8_mul_lut = gf_2_8_mul_lut(&mut builder);
        let mix_matrix = state_mix_matrix_bits(&mut builder);

        let key_expanded_target =
            builder.key_expansion::<NK, NB, NR>(xor_lut, sbox_lut, key_target);
        let gctr_out_target = gctr_target::<NR, L>(
            &mut builder,
            (xor_lut, gf_2_8_mul_lut, sbox_lut),
            mix_matrix,
            key_expanded_target,
            &icb_target,
            &pt_target,
        );

        println!(
            "gctr (NK:{}, NB:{}, NR:{}, L:{}) num_gates: {}",
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

    #[test]
    fn test_right_shift_one() -> Result<()> {
        let x: [u8; 16] = [111; 16];

        let mut expected = x;
        right_shift_one(&mut expected);

        // Circuit declaration
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let u8_unit_right_shift_lut_idx = u8_unit_right_shift_lut(&mut builder);

        let x_target: [ByteTarget; 16] = array::from_fn(|_| builder.add_virtual_target());

        let out_target: [ByteTarget; 16] =
            right_shift_one_target(&mut builder, u8_unit_right_shift_lut_idx, &x_target);

        println!("right_shift_one num_gates: {}", builder.num_gates());
        let data = builder.build::<PoseidonGoldilocksConfig>();

        // set values to circuit
        let mut pw = PartialWitness::<F>::new();
        std::iter::zip(x_target, x).try_for_each(|(t, v)| pw.set_byte_array_target(t, v))?;

        std::iter::zip(out_target, expected)
            .try_for_each(|(t, v)| pw.set_byte_array_target(t, v))?;

        let proof = data.prove(pw)?;
        data.verify(proof)?;
        Ok(())
    }

    #[test]
    fn test_gf_mul() -> Result<()> {
        // AES-GCM-128
        test_gf_mul_opt::<4, 4, 10, 16>()?;
        test_gf_mul_opt::<4, 4, 10, 32>()?;

        // AES-GCM-256
        test_gf_mul_opt::<8, 4, 14, 16>()?;

        Ok(())
    }
    fn test_gf_mul_opt<const NK: usize, const NB: usize, const NR: usize, const L: usize>()
    -> Result<()>
    where
        [(); 4 * (NR + 1)]:,
        [(); NK * NB]:,
    {
        let x: [u8; 16] = [111; 16];
        let y: [u8; 16] = [222; 16];

        let expected = gf_2_128_mul(x, y);
        let x_bits: [[bool; 8]; 16] = array::from_fn(|b| super::le_bits_from_byte(x[b]));
        let y_bits: [[bool; 8]; 16] = array::from_fn(|b| super::le_bits_from_byte(y[b]));

        // sanity check
        let expected2 = crate::native_gcm::gf_2_128_mul_circuit_version(x_bits, y_bits);
        let expected_bits: [[bool; 8]; 16] =
            array::from_fn(|b| super::le_bits_from_byte(expected[b]));
        assert_eq!(expected2, expected_bits);

        // Circuit declaration
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let xor_lut_idx = byte_xor_lut(&mut builder);
        let u8_unit_right_shift_lut_idx = u8_unit_right_shift_lut(&mut builder);
        let u8_bitref_lut_idx = u8_bitref_lut(&mut builder);

        let x_target: [ByteTarget; 16] = array::from_fn(|_| builder.add_virtual_target());
        let y_target: [ByteTarget; 16] = array::from_fn(|_| builder.add_virtual_target());

        let out_target = gf_2_128_mul_target(
            &mut builder,
            xor_lut_idx,
            u8_unit_right_shift_lut_idx,
            u8_bitref_lut_idx,
            x_target,
            y_target,
        );

        println!("gf_2_128_mul (L:{}) num_gates: {}", L, builder.num_gates());
        let data = builder.build::<PoseidonGoldilocksConfig>();

        // set values to circuit
        let mut pw = PartialWitness::<F>::new();
        std::iter::zip(x_target, x).try_for_each(|(t, v)| pw.set_byte_array_target(t, v))?;
        std::iter::zip(y_target, y).try_for_each(|(t, v)| pw.set_byte_array_target(t, v))?;

        std::iter::zip(out_target, expected)
            .try_for_each(|(t, v)| pw.set_byte_array_target(t, v))?;

        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_ghash() -> Result<()> {
        // AES-GCM-128
        test_ghash_opt::<4, 4, 10, 16>()?;
        test_ghash_opt::<4, 4, 10, 32>()?;

        // AES-GCM-256
        test_ghash_opt::<8, 4, 14, 16>()?;

        Ok(())
    }
    fn test_ghash_opt<const NK: usize, const NB: usize, const NR: usize, const L: usize>()
    -> Result<()>
    where
        [(); 4 * (NR + 1)]:,
        [(); NK * NB]:,
    {
        let h: [u8; 16] = [222; 16];
        let x: &[u8; L] = &[42u8; L];

        let expected = ghash(h, x);

        // Circuit declaration
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let xor_lut_idx = byte_xor_lut(&mut builder);
        let u8_unit_right_shift_lut_idx = u8_unit_right_shift_lut(&mut builder);
        let u8_bitref_lut_idx = u8_bitref_lut(&mut builder);

        let h_target: [ByteTarget; 16] = array::from_fn(|_| builder.add_virtual_target());
        let x_target: [ByteTarget; L] = array::from_fn(|_| builder.add_virtual_target());

        // let ghash_out_target = ghash_target::<L>(&mut builder, h_target, &x_target);
        let ghash_out_target = ghash_target(
            &mut builder,
            xor_lut_idx,
            u8_unit_right_shift_lut_idx,
            u8_bitref_lut_idx,
            h_target,
            x_target.to_vec(),
        );

        println!("ghash (L:{}) num_gates: {}", L, builder.num_gates());
        let data = builder.build::<PoseidonGoldilocksConfig>();

        // set values to circuit
        let mut pw = PartialWitness::<F>::new();
        std::iter::zip(h_target, h).try_for_each(|(t, v)| pw.set_byte_array_target(t, v))?;
        std::iter::zip(x_target, x).try_for_each(|(t, v)| pw.set_byte_array_target(t, *v))?;

        std::iter::zip(ghash_out_target, expected)
            .try_for_each(|(t, v)| pw.set_byte_array_target(t, v))?;

        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_encrypt() -> Result<()> {
        // AES-GCM-128
        test_encrypt_opt::<4, 4, 10, 13, false>(false)?;
        test_encrypt_opt::<4, 4, 10, 13, true>(false)?; // with tag
        test_encrypt_opt::<4, 4, 10, 17, false>(false)?;

        // AES-GCM-256
        test_encrypt_opt::<8, 4, 14, 13, false>(false)?;
        test_encrypt_opt::<8, 4, 14, 13, true>(false)?; // with tag

        Ok(())
    }
    // run it with: cargo test -- --ignored
    #[ignore]
    #[test]
    fn test_encrypt_report_sizes() -> Result<()> {
        // AES-GCM-128
        test_encrypt_opt::<4, 4, 10, 16, false>(true)?;
        test_encrypt_opt::<4, 4, 10, 17, false>(true)?;
        test_encrypt_opt::<4, 4, 10, 32, false>(true)?;
        test_encrypt_opt::<4, 4, 10, 33, false>(true)?;
        test_encrypt_opt::<4, 4, 10, 64, false>(true)?;
        test_encrypt_opt::<4, 4, 10, 128, false>(true)?;
        test_encrypt_opt::<4, 4, 10, 256, false>(true)?;
        test_encrypt_opt::<4, 4, 10, 512, false>(true)?;
        test_encrypt_opt::<4, 4, 10, 1024, false>(true)?;
        test_encrypt_opt::<4, 4, 10, 2048, false>(true)?;

        // AES-GCM-256
        test_encrypt_opt::<8, 4, 14, 16, false>(true)?;
        test_encrypt_opt::<8, 4, 14, 17, false>(true)?;
        test_encrypt_opt::<8, 4, 14, 32, false>(true)?;
        test_encrypt_opt::<8, 4, 14, 33, false>(true)?;
        test_encrypt_opt::<8, 4, 14, 64, false>(true)?;
        test_encrypt_opt::<8, 4, 14, 128, false>(true)?;
        test_encrypt_opt::<8, 4, 14, 256, false>(true)?;
        test_encrypt_opt::<8, 4, 14, 512, false>(true)?;
        test_encrypt_opt::<8, 4, 14, 1024, false>(true)?;
        test_encrypt_opt::<8, 4, 14, 2048, false>(true)?;

        Ok(())
    }
    fn test_encrypt_opt<
        const NK: usize,
        const NB: usize,
        const NR: usize,
        const L: usize,
        const TAG: bool,
    >(
        only_build: bool,
    ) -> Result<()>
    where
        [(); 4 * (NR + 1)]:,
        [(); NK * NB]:,
    {
        let key: &[u8; NK * NB] = &[42; NK * NB];
        let nonce: &[u8; 12] = &[111; 12];
        let pt: &[u8; L] = &[42u8; L];

        let (ct, tag) = crate::native_gcm::encrypt::<NK, NB, NR>(key, nonce, pt);

        // Circuit declaration
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let aes_targets = AesGcmTarget::<NK, NB, NR, L, TAG>::build(&mut builder);

        println!(
            "encrypt (NK:{}, NB:{}, NR:{}, L:{}, TAG:{}) num_gates: {}",
            NK,
            NB,
            NR,
            L,
            TAG,
            builder.num_gates()
        );
        let data = builder.build::<PoseidonGoldilocksConfig>();

        if only_build {
            return Ok(());
        }

        // set values to circuit
        let mut pw = PartialWitness::<F>::new();
        aes_targets.set_targets(&mut pw, key, nonce, pt, &ct, &tag)?;

        let proof = data.prove(pw)?;
        data.verify(proof)
    }
}
