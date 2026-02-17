use std::array;

use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField as F},
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

pub(crate) const D: usize = 2;

#[derive(Debug, Copy, Clone)]
pub struct FeistelStateTarget<const STATE_LEN: usize>([Target; STATE_LEN]);

pub trait CircuitBuilderFeistel<F: RichField + Extendable<D>, const D: usize> {
    fn add_feistel_state_target<const STATE_LEN: usize>(&mut self)
    -> FeistelStateTarget<STATE_LEN>;

    fn feistel_cipher<const STATE_HALF_LEN: usize, const KEY_LEN: usize>(
        &mut self,
        state: FeistelStateTarget<{ 2 * STATE_HALF_LEN }>,
        key_schedule: &[[Target; KEY_LEN]],
        f: &impl Fn(&mut Self, Vec<Target>) -> [Target; STATE_HALF_LEN],
    ) -> FeistelStateTarget<{ 2 * STATE_HALF_LEN }>;
}

impl CircuitBuilderFeistel<F, D> for CircuitBuilder<F, D> {
    fn add_feistel_state_target<const STATE_LEN: usize>(
        &mut self,
    ) -> FeistelStateTarget<STATE_LEN> {
        FeistelStateTarget(self.add_virtual_target_arr())
    }

    fn feistel_cipher<const STATE_HALF_LEN: usize, const KEY_LEN: usize>(
        &mut self,
        state: FeistelStateTarget<{ 2 * STATE_HALF_LEN }>,
        key_schedule: &[[Target; KEY_LEN]],
        f: &impl Fn(&mut Self, Vec<Target>) -> [Target; STATE_HALF_LEN],
    ) -> FeistelStateTarget<{ 2 * STATE_HALF_LEN }> {
        if key_schedule.is_empty() {
            state
        } else {
            let k = key_schedule[0];
            let l = &state.0[..STATE_HALF_LEN];
            let r = &state.0[STATE_HALF_LEN..];

            let new_l = r;
            let round_offset = f(self, [r, &k].concat());
            let new_r: [_; STATE_HALF_LEN] = array::from_fn(|i| self.add(l[i], round_offset[i]));
            self.feistel_cipher(
                FeistelStateTarget(array::from_fn(|i| {
                    if i < STATE_HALF_LEN {
                        new_l[i]
                    } else {
                        new_r[i - STATE_HALF_LEN]
                    }
                })),
                &key_schedule[1..],
                f,
            )
        }
    }
}

pub trait PartialWitnessFeistel {
    fn set_feistel_state_target<const STATE_SIZE: usize>(
        &mut self,
        target: &FeistelStateTarget<STATE_SIZE>,
        value: &[F; STATE_SIZE],
    ) -> anyhow::Result<()>;
}

impl PartialWitnessFeistel for PartialWitness<F> {
    fn set_feistel_state_target<const STATE_SIZE: usize>(
        &mut self,
        target: &FeistelStateTarget<STATE_SIZE>,
        value: &[F; STATE_SIZE],
    ) -> anyhow::Result<()> {
        self.set_target_arr(&target.0, value)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField as F,
        hash::{
            hashing::hash_n_to_hash_no_pad,
            keccak::KeccakHash,
            poseidon::{PoseidonHash, PoseidonPermutation},
        },
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use super::D;
    use crate::{
        circuit::{CircuitBuilderFeistel, FeistelStateTarget, PartialWitnessFeistel},
        feistel_cipher,
        tests::random_fields,
    };

    #[test]
    fn feistel_poseidon_check() -> anyhow::Result<()> {
        const NR: usize = 32;
        const STATE_HALF_LEN: usize = 4;
        const KEY_LEN: usize = 4;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let state_target: FeistelStateTarget<{ 2 * STATE_HALF_LEN }> =
            builder.add_feistel_state_target();
        let key_schedule_target: [[_; KEY_LEN]; NR] =
            std::array::from_fn(|_| builder.add_virtual_target_arr());

        let f = |builder: &mut CircuitBuilder<F, D>, targets: Vec<_>| {
            builder
                .hash_n_to_hash_no_pad::<PoseidonHash>(targets)
                .elements
        };

        let out_state_target = builder.feistel_cipher(state_target, &key_schedule_target, &f);

        let data = builder.build::<PoseidonGoldilocksConfig>();
        (0..10).try_for_each(|_| {
            let state: [_; { 2 * STATE_HALF_LEN }] = random_fields();
            let key_schedule: [[_; KEY_LEN]; NR] = std::array::from_fn(|_| random_fields());
            let eff = |fields: Vec<_>| {
                hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(&fields).elements
            };
            let out_state = feistel_cipher(state, &key_schedule, &eff);

            let mut pw = PartialWitness::new();
            pw.set_feistel_state_target(&state_target, &state)?;
            std::iter::zip(key_schedule_target, key_schedule)
                .try_for_each(|(t, v)| pw.set_target_arr(&t, &v))?;
            pw.set_feistel_state_target(&out_state_target, &out_state)?;

            let proof = data.prove(pw)?;
            data.verify(proof)
        })
    }
}
