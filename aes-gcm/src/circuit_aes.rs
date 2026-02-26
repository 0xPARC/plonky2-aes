//! For LICENSE check out https://github.com/0xPARC/plonky2-crypto-gadgets/blob/main/LICENSE
//!
//! Plonky2 circuit implementation of
//! [AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf).

use std::{array, sync::Arc};

use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField as F, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    D,
    constants::{RCON, SBOX},
    native_aes::{State, gf_2_8_mul, rot_word, shift_rows},
};

#[derive(Debug, Copy, Clone)]
pub struct StateTarget(pub [[ByteTarget; 4]; 4]);

impl StateTarget {
    pub(crate) fn flatten(self) -> [ByteTarget; 16] {
        array::from_fn(|i| self.0[i % 4][i / 4])
    }

    pub(crate) fn from_flat(b: [ByteTarget; 16]) -> Self {
        StateTarget(array::from_fn(|i| array::from_fn(|j| b[j * 4 + i])))
    }
}

/// Type alias for byte targets
pub type ByteTarget = Target;

pub trait CircuitBuilderAESState<F: RichField + Extendable<D>, const D: usize> {
    /// Adds state target.
    fn add_virtual_state(&mut self) -> StateTarget;

    /// AES cipher as in spec.
    fn encrypt_block<const NR: usize>(
        &mut self,
        xor_lut_idx: usize,
        gf_2_8_mul_lut_idx: usize,
        sbox_lut_idx: usize,
        mix_matrix: [[ByteTarget; 4]; 4], // constant mix_matrix
        s: StateTarget,
        w: [[ByteTarget; 4]; 4 * (NR + 1)], // expanded key
    ) -> StateTarget {
        let mut s = s;
        s = self.state_add_round_key(xor_lut_idx, &w[0..4], s);
        (1..NR).for_each(|i| {
            s = self.state_sub_bytes(sbox_lut_idx, s);
            s = StateTarget(shift_rows(s.0));
            s = self.state_mix_columns(xor_lut_idx, gf_2_8_mul_lut_idx, mix_matrix, s);
            s = self.state_add_round_key(xor_lut_idx, &w[4 * i..4 * (i + 1)], s);
        });
        s = self.state_sub_bytes(sbox_lut_idx, s);
        s = StateTarget(shift_rows(s.0));
        self.state_add_round_key(xor_lut_idx, &w[4 * NR..4 * (NR + 1)], s)
    }

    /// Applies sub_bytes routine to state.
    fn state_sub_bytes(&mut self, sbox_lut_idx: usize, s: StateTarget) -> StateTarget {
        StateTarget(array::from_fn(|i| {
            self.state_sub_word(sbox_lut_idx, s.0[i])
        }))
    }

    /// SubWord
    fn state_sub_word(&mut self, sbox_lut_idx: usize, word: [ByteTarget; 4]) -> [ByteTarget; 4];

    /// MixColumns
    fn state_mix_columns(
        &mut self,
        xor_lut_idx: usize,
        gf_2_8_mul_lut_idx: usize,
        mix_matrix: [[ByteTarget; 4]; 4],
        s: StateTarget,
    ) -> StateTarget {
        let cols: [_; 4] = array::from_fn(|i| array::from_fn(|j| s.0[j][i]));
        let out_cols: [_; 4] = array::from_fn(|i| {
            self.bytearray_matrix_apply_bits(xor_lut_idx, gf_2_8_mul_lut_idx, mix_matrix, cols[i])
        });
        StateTarget(array::from_fn(|i| array::from_fn(|j| out_cols[j][i])))
    }

    /// AddRoundKey
    fn state_add_round_key(
        &mut self,
        xor_lut_idx: usize,
        round_key: &[[ByteTarget; 4]],
        s: StateTarget,
    ) -> StateTarget {
        StateTarget(array::from_fn(|i| {
            array::from_fn(|j| self.gf_2_8_add(xor_lut_idx, s.0[i][j], round_key[j][i]))
        }))
    }

    /// KeyExpansion
    fn key_expansion<const NK: usize, const NB: usize, const NR: usize>(
        &mut self,
        xor_lut_idx: usize,
        sbox_lut_idx: usize,
        key: [ByteTarget; NK * NB],
    ) -> [[ByteTarget; 4]; 4 * (NR + 1)];

    /// GF(2^8) addition
    fn gf_2_8_add(&mut self, xor_lut_idx: usize, x: Target, y: Target) -> Target;

    /// GF(2^8) multiplication
    fn gf_2_8_mul(&mut self, gf_2_8_mul_lut_idx: usize, x: Target, y: Target) -> Target;

    /// Bytearray inner product.
    fn bytearray_ip_bits<const N: usize>(
        &mut self,
        xor_lut_idx: usize,
        gf_2_8_mul_lut_idx: usize,
        x: [ByteTarget; N],
        y: [ByteTarget; N],
    ) -> ByteTarget;

    /// Bytearray matrix application.
    fn bytearray_matrix_apply_bits<const M: usize, const N: usize>(
        &mut self,
        xor_lut_idx: usize,
        gf_2_8_mul_lut_idx: usize,
        a: [[ByteTarget; N]; M],
        x: [ByteTarget; N],
    ) -> [ByteTarget; M] {
        std::array::from_fn(|i| self.bytearray_ip_bits(xor_lut_idx, gf_2_8_mul_lut_idx, a[i], x))
    }

    /// returns a 0u8 in the shape of a ByteTarget.
    fn zero_byte(&mut self) -> ByteTarget;

    fn empty_state(&mut self) -> StateTarget;
}

impl CircuitBuilderAESState<F, D> for CircuitBuilder<F, D> {
    fn add_virtual_state(&mut self) -> StateTarget {
        StateTarget(array::from_fn(|_| {
            array::from_fn(|_| self.add_virtual_target())
        }))
    }

    fn state_sub_word(&mut self, sbox_lut_idx: usize, word: [ByteTarget; 4]) -> [ByteTarget; 4] {
        array::from_fn(|i| {
            let byte_target = word[i];

            self.add_lookup_from_index(byte_target, sbox_lut_idx)
        })
    }

    fn key_expansion<const NK: usize, const NB: usize, const NR: usize>(
        &mut self,
        xor_lut_idx: usize,
        sbox_lut_idx: usize,
        key: [ByteTarget; NK * NB],
    ) -> [[ByteTarget; 4]; 4 * (NR + 1)] {
        let rcon: [ByteTarget; 11] =
            array::from_fn(|i| self.constant(F::from_canonical_u8(RCON[i])));

        let key: [[_; 4]; NK] = array::from_fn(|i| array::from_fn(|j| key[4 * i + j]));

        let key_additions = (NK..4 * (NR + 1))
            .scan(key.to_vec(), |st, i| {
                let offset = if i % NK == 0 {
                    let term = self.state_sub_word(sbox_lut_idx, rot_word(st[i - 1]));
                    array::from_fn(|j| {
                        if j == 0 {
                            self.gf_2_8_add(xor_lut_idx, term[j], rcon[i / NK])
                        } else {
                            term[j]
                        }
                    })
                } else if (NK > 6) && (i % NK == 4) {
                    self.state_sub_word(sbox_lut_idx, st[i - 1])
                } else {
                    st[i - 1]
                };

                let cur_val =
                    array::from_fn(|j| self.gf_2_8_add(xor_lut_idx, st[i - NK][j], offset[j]));
                st.push(cur_val);
                Some(cur_val)
            })
            .collect::<Vec<_>>();
        std::array::from_fn(|i| {
            if i < NK {
                key[i]
            } else {
                key_additions[i - NK]
            }
        })
    }

    fn gf_2_8_add(&mut self, xor_lut_idx: usize, x: Target, y: Target) -> Target {
        byte_xor(self, xor_lut_idx, x, y)
    }

    fn gf_2_8_mul(&mut self, gf_2_8_mul_lut_idx: usize, x: Target, y: Target) -> Target {
        let lookup_idx = self.mul_const_add(F::from_canonical_u64(1 << 8), x, y);
        self.add_lookup_from_index(lookup_idx, gf_2_8_mul_lut_idx)
    }

    fn bytearray_ip_bits<const N: usize>(
        &mut self,
        xor_lut_idx: usize,
        gf_2_8_mul_lut_idx: usize,
        x: [ByteTarget; N],
        y: [ByteTarget; N],
    ) -> ByteTarget {
        let zero = self.zero();
        std::iter::zip(x, y).fold(zero, |acc, (a, b)| {
            let prod = self.gf_2_8_mul(gf_2_8_mul_lut_idx, a, b);
            self.gf_2_8_add(xor_lut_idx, acc, prod)
        })
    }

    fn zero_byte(&mut self) -> ByteTarget {
        self.zero()
    }

    fn empty_state(&mut self) -> StateTarget {
        let zero_byte: ByteTarget = self.zero_byte();
        StateTarget(array::from_fn(|_| array::from_fn(|_| zero_byte)))
    }
}

pub trait PartialWitnessByteArray {
    fn set_byte_array_target(&mut self, target: ByteTarget, value: u8) -> anyhow::Result<()>;
}

impl<F: Field> PartialWitnessByteArray for PartialWitness<F> {
    fn set_byte_array_target(&mut self, target: ByteTarget, value: u8) -> anyhow::Result<()> {
        self.set_target(target, F::from_canonical_u8(value))
    }
}

pub trait PartialWitnessAESState {
    fn set_target_state(&mut self, target: StateTarget, value: State) -> anyhow::Result<()>;
}

impl<F: Field> PartialWitnessAESState for PartialWitness<F> {
    fn set_target_state(&mut self, target: StateTarget, value: State) -> anyhow::Result<()> {
        std::iter::zip(target.0, value).try_for_each(|(t, v)| {
            std::iter::zip(t, v).try_for_each(|(t, v)| self.set_byte_array_target(t, v))
        })
    }
}

pub fn sbox_lut(builder: &mut CircuitBuilder<F, D>) -> usize {
    builder.add_lookup_table_from_pairs(Arc::new(
        SBOX.into_iter()
            .enumerate()
            .map(|(i, o)| (i as u16, o as u16))
            .collect::<Vec<_>>(),
    ))
}

/// Lookup table for GF(2^8) multiplication, a.k.a. XOR on bytes.
pub fn byte_xor_lut(builder: &mut CircuitBuilder<F, D>) -> usize {
    let xor_table: Vec<(u16, u16)> = (0..=u8::MAX as usize)
        .flat_map(|x| {
            (0..=u8::MAX as usize)
                .map(|y| (((x as u16) << 8) + y as u16, (x as u16) ^ (y as u16)))
                .collect::<Vec<_>>()
        })
        .collect();
    builder.add_lookup_table_from_pairs(Arc::new(xor_table))
}

/// Lookup table for GF(2^8) multiplication.
pub fn gf_2_8_mul_lut(builder: &mut CircuitBuilder<F, D>) -> usize {
    let gf_2_8_mul_table: Vec<(u16, u16)> = (0..=u8::MAX as usize)
        .flat_map(|x| {
            (0..=u8::MAX as usize)
                .map(|y| {
                    (
                        ((x as u16) << 8) + y as u16,
                        gf_2_8_mul(x as u8, y as u8) as u16,
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();
    builder.add_lookup_table_from_pairs(Arc::new(gf_2_8_mul_table))
}

pub fn state_mix_matrix_bits(builder: &mut CircuitBuilder<F, D>) -> [[ByteTarget; 4]; 4] {
    let one = builder.one();
    let two = builder.two();
    let three = builder.constant(F::from_canonical_u64(3));

    [
        [two, three, one, one],
        [one, two, three, one],
        [one, one, two, three],
        [three, one, one, two],
    ]
}

pub fn byte_xor(
    builder: &mut CircuitBuilder<F, D>,
    xor_lut_idx: usize,
    x: ByteTarget,
    y: ByteTarget,
) -> ByteTarget {
    let lookup_idx = builder.mul_const_add(F::from_canonical_u64(1 << 8), x, y);
    builder.add_lookup_from_index(lookup_idx, xor_lut_idx)
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

    use super::{
        ByteTarget, CircuitBuilderAESState, D, PartialWitnessAESState, PartialWitnessByteArray,
        byte_xor_lut, gf_2_8_mul_lut, sbox_lut, state_mix_matrix_bits,
    };
    use crate::native_aes::{State, encrypt_block, key_expansion, mix_columns, sub_bytes};

    #[test]
    fn test_sub_bytes() -> Result<()> {
        // Circuit declaration
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let state_target = builder.add_virtual_state();
        let sbox_lut = sbox_lut(&mut builder);
        let out_state_target = builder.state_sub_bytes(sbox_lut, state_target);

        let data = builder.build::<PoseidonGoldilocksConfig>();

        // set values to circuit
        let mut rng = rand::rng();
        let test_states: [State; 10] = array::from_fn(|_| array::from_fn(|_| rng.random()));

        test_states.into_iter().try_for_each(|s| {
            let expected_result = sub_bytes(s);

            let mut pw = PartialWitness::<F>::new();
            pw.set_target_state(state_target, s)?;
            pw.set_target_state(out_state_target, expected_result)?;

            let proof = data.prove(pw)?;
            data.verify(proof)
        })
    }

    #[test]
    fn test_mix_columns() -> Result<()> {
        // Circuit declaration
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let xor_lut_idx = byte_xor_lut(&mut builder);
        let gf_2_8_mul_lut_idx = gf_2_8_mul_lut(&mut builder);
        let state_target = builder.add_virtual_state();
        let mix_matrix = state_mix_matrix_bits(&mut builder);
        let out_state_target =
            builder.state_mix_columns(xor_lut_idx, gf_2_8_mul_lut_idx, mix_matrix, state_target);

        let data = builder.build::<PoseidonGoldilocksConfig>();

        // set values to circuit
        let mut rng = rand::rng();
        let test_states: [State; 10] = array::from_fn(|_| array::from_fn(|_| rng.random()));

        test_states.into_iter().try_for_each(|s| {
            let expected_result = mix_columns(s);

            let mut pw = PartialWitness::<F>::new();
            pw.set_target_state(state_target, s)?;
            pw.set_target_state(out_state_target, expected_result)?;

            let proof = data.prove(pw)?;
            data.verify(proof)
        })
    }

    #[test]
    fn test_gf_2_8_mul() -> Result<()> {
        // Circuit declaration
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let gf_2_8_mul_lut_idx = gf_2_8_mul_lut(&mut builder);

        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();

        let a_times_b = builder.gf_2_8_mul(gf_2_8_mul_lut_idx, a, b);

        let data = builder.build::<PoseidonGoldilocksConfig>();

        // set values to circuit
        let test_values = [
            (0x57, 0x01, 0x57),
            (0x57, 0x02, 0xae),
            (0x57, 0x04, 0x47),
            (0x57, 0x08, 0x8e),
            (0x57, 0x10, 0x07),
            (0x57, 0x20, 0x0e),
            (0x57, 0x40, 0x1c),
            (0x57, 0x80, 0x38),
            (0x57, 0x13, 0xfe),
        ];
        test_values
            .into_iter()
            .map(|(a, b, c)| {
                (
                    F::from_canonical_u8(a),
                    F::from_canonical_u8(b),
                    F::from_canonical_u8(c),
                )
            })
            .try_for_each(|(a_val, b_val, expected_result)| {
                let mut pw = PartialWitness::<F>::new();
                pw.set_target(a, a_val)?;
                pw.set_target(b, b_val)?;
                pw.set_target(a_times_b, expected_result)?;

                let proof = data.prove(pw)?;
                data.verify(proof)
            })
    }

    #[test]
    fn test_gf_2_8_add() -> Result<()> {
        // Circuit declaration
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let xor_lut_idx = byte_xor_lut(&mut builder);

        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();

        let a_plus_b = builder.gf_2_8_add(xor_lut_idx, a, b);

        let data = builder.build::<PoseidonGoldilocksConfig>();

        // set values to circuit
        let mut rng = rand::rng();
        let test_values: [(u8, u8, u8); 20] = std::array::from_fn(|_| {
            let x = rng.random();
            let y = rng.random();
            (x, y, x ^ y)
        });
        test_values
            .into_iter()
            .map(|(a, b, c)| {
                (
                    F::from_canonical_u8(a),
                    F::from_canonical_u8(b),
                    F::from_canonical_u8(c),
                )
            })
            .try_for_each(|(a_val, b_val, expected_result)| {
                let mut pw = PartialWitness::<F>::new();
                pw.set_target(a, a_val)?;
                pw.set_target(b, b_val)?;
                pw.set_target(a_plus_b, expected_result)?;

                let proof = data.prove(pw)?;
                data.verify(proof)
            })
    }

    #[test]
    fn test_key_expansion() -> Result<()> {
        // AES-128
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        test_key_expansion_op::</*Nk,Nb,Nr*/ 4, 4, 10>(key)?;

        // AES-196
        let key = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];
        test_key_expansion_op::</*Nk,Nb,Nr*/ 6, 4, 12>(key)?;

        // AES-256
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        test_key_expansion_op::</*Nk,Nb,Nr*/ 8, 4, 14>(key)?;

        Ok(())
    }

    /// Analogous tests to `native_aes::tests::test_key_expansion`.
    fn test_key_expansion_op<const NK: usize, const NB: usize, const NR: usize>(
        key: [u8; NK * NB],
    ) -> Result<()>
    where
        [(); 4 * (NR + 1)]:,
        [(); 4 * NK]:,
    {
        // Circuit declaration
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let key_target: [ByteTarget; NK * NB] = array::from_fn(|_| builder.add_virtual_target());
        let xor_lut_idx = byte_xor_lut(&mut builder);
        let sbox_lut_idx = sbox_lut(&mut builder);
        let expanded_key_target =
            builder.key_expansion::<NK, NB, NR>(xor_lut_idx, sbox_lut_idx, key_target);

        println!(
            "key_expansion(NK:{}, NB:{}, NR:{}) num_gates: {}",
            NK,
            NB,
            NR,
            builder.num_gates()
        );
        let data = builder.build::<PoseidonGoldilocksConfig>();

        // set values to circuit
        let w = key_expansion::<NK, NB, NR>(&key);

        let mut pw = PartialWitness::<F>::new();

        std::iter::zip(key_target, key).try_for_each(|(t, v)| pw.set_byte_array_target(t, v))?;

        std::iter::zip(expanded_key_target, w).try_for_each(|(t, v)| {
            std::iter::zip(t, v).try_for_each(|(t, v)| pw.set_byte_array_target(t, v))
        })?;

        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    /// test against native version
    #[test]
    fn test_encrypt_block_test_vector() -> Result<()> {
        // AES-128
        let input_state: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        test_encrypt_block_test_vector_op::<4, 4, 10>(input_state, key)?;

        // AES-196
        let input_state: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let key = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];
        test_encrypt_block_test_vector_op::<6, 4, 12>(input_state, key)?;

        // AES-256
        let input_state: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        test_encrypt_block_test_vector_op::<8, 4, 14>(input_state, key)?;

        Ok(())
    }

    fn test_encrypt_block_test_vector_op<const NK: usize, const NB: usize, const NR: usize>(
        input_state: [u8; 16],
        key: [u8; NK * NB],
    ) -> Result<()>
    where
        [(); 4 * (NR + 1)]:,
        [(); 4 * NK]:,
        // [(); NK * NB]:,
    {
        // Circuit declaration
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let key_target: [ByteTarget; NK * NB] = array::from_fn(|_| builder.add_virtual_target());
        let xor_lut_idx = byte_xor_lut(&mut builder);
        let gf_2_8_mul_lut_idx = gf_2_8_mul_lut(&mut builder);
        let sbox_lut_idx = sbox_lut(&mut builder);
        let mix_matrix = state_mix_matrix_bits(&mut builder);
        let expanded_key_target: [[ByteTarget; 4]; 4 * (NR + 1)] =
            builder.key_expansion::<NK, NB, NR>(xor_lut_idx, sbox_lut_idx, key_target);

        let input_state_target = builder.add_virtual_state();

        let output = builder.encrypt_block(
            xor_lut_idx,
            gf_2_8_mul_lut_idx,
            sbox_lut_idx,
            mix_matrix,
            input_state_target,
            expanded_key_target,
        );

        println!(
            "encrypt_block (NK:{}, NB:{}, NR:{}) num_gates: {}",
            NK,
            NB,
            NR,
            builder.num_gates()
        );
        let data = builder.build::<PoseidonGoldilocksConfig>();

        // set values to circuit
        let mut input_state_matrix: State = [[0; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                input_state_matrix[i][j] = input_state[i + 4 * j];
            }
        }

        let expanded_key: [[u8; 4]; 4 * (NR + 1)] = key_expansion::<NK, NB, NR>(&key);
        let native_ciphertext = encrypt_block::<NR>(&input_state, &expanded_key);

        let mut pw = PartialWitness::<F>::new();

        std::iter::zip(key_target, key).try_for_each(|(t, v)| pw.set_byte_array_target(t, v))?;

        pw.set_target_state(input_state_target, input_state_matrix)?;

        std::iter::zip(expanded_key_target, expanded_key).try_for_each(|(t, v)| {
            std::iter::zip(t, v).try_for_each(|(t, v)| pw.set_byte_array_target(t, v))
        })?;

        std::iter::zip(output.0, native_ciphertext).try_for_each(|(o, e)| {
            std::iter::zip(o, e).try_for_each(|(o, e)| pw.set_byte_array_target(o, e))
        })?;

        let proof = data.prove(pw)?;
        data.verify(proof)
    }
}
