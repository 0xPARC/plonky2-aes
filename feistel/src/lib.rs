#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

pub mod circuit;

use std::array;

use plonky2::field::types::Field;

pub fn feistel_cipher<const STATE_HALF_LEN: usize, const KEY_LEN: usize, F: Field>(
    state: [F; 2 * STATE_HALF_LEN],
    key_schedule: &[[F; KEY_LEN]],
    f: &impl Fn(Vec<F>) -> [F; STATE_HALF_LEN],
) -> [F; 2 * STATE_HALF_LEN] {
    if key_schedule.is_empty() {
        state
    } else {
        let k = key_schedule[0];
        let l = &state[..STATE_HALF_LEN];
        let r = &state[STATE_HALF_LEN..];

        let new_l = r;
        let round_offset = f([r, &k].concat());
        let new_r: [_; STATE_HALF_LEN] = array::from_fn(|i| l[i] + round_offset[i]);

        feistel_cipher(
            array::from_fn(|i| {
                if i < STATE_HALF_LEN {
                    new_l[i]
                } else {
                    new_r[i - STATE_HALF_LEN]
                }
            }),
            &key_schedule[1..],
            f,
        )
    }
}

pub fn feistel_inv_cipher<const STATE_HALF_LEN: usize, const KEY_LEN: usize, F: Field>(
    state: [F; 2 * STATE_HALF_LEN],
    reverse_key_schedule: &[[F; KEY_LEN]],
    f: &impl Fn(Vec<F>) -> [F; STATE_HALF_LEN],
) -> [F; 2 * STATE_HALF_LEN] {
    if reverse_key_schedule.is_empty() {
        state
    } else {
        let k = reverse_key_schedule[0];
        let l = &state[..STATE_HALF_LEN];
        let r = &state[STATE_HALF_LEN..];

        let new_r = l;
        let round_offset = f([l, &k].concat());
        let new_l: [_; STATE_HALF_LEN] = array::from_fn(|i| r[i] - round_offset[i]);

        feistel_inv_cipher(
            array::from_fn(|i| {
                if i < STATE_HALF_LEN {
                    new_l[i]
                } else {
                    new_r[i - STATE_HALF_LEN]
                }
            }),
            &reverse_key_schedule[1..],
            f,
        )
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField as F,
            types::{Field, Field64},
        },
        hash::{
            hashing::hash_n_to_hash_no_pad, keccak::KeccakPermutation,
            poseidon::PoseidonPermutation,
        },
    };
    use rand::{Rng, rngs::OsRng};

    use crate::{feistel_cipher, feistel_inv_cipher};

    pub(crate) fn random_fields<const N: usize>() -> [F; N] {
        std::array::from_fn(|_| F::from_canonical_u64(OsRng.gen_range(0..F::ORDER)))
    }

    #[test]
    fn feistel_keccak_poseidon_roundtrip() {
        const NR: usize = 32;
        const STATE_HALF_LEN: usize = 4;
        const KEY_LEN: usize = 4;

        let f_keccak =
            |fields: Vec<_>| hash_n_to_hash_no_pad::<F, KeccakPermutation<_>>(&fields).elements;
        let f_poseidon =
            |fields: Vec<_>| hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(&fields).elements;

        [f_keccak, f_poseidon].into_iter().for_each(|f| {
            (0..10).for_each(|_| {
                let state: [_; { 2 * STATE_HALF_LEN }] = random_fields();
                let key_schedule: [[_; KEY_LEN]; NR] = std::array::from_fn(|_| random_fields());

                let out_state = feistel_cipher(state, &key_schedule, &f);
                let reverse_key_schedule = key_schedule.into_iter().rev().collect::<Vec<_>>();
                let maybe_original_state = feistel_inv_cipher(out_state, &reverse_key_schedule, &f);

                assert_eq!(state, maybe_original_state);
            })
        })
    }
}
