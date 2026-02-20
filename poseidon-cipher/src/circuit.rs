//! For LICENSE check out https://github.com/0xPARC/plonky2-crypto-gadgets/blob/main/LICENSE
//!
//! Implements the Plonky2 circuits for Poseidon encryption as described at
//! https://drive.google.com/file/d/1EVrP3DzoGbmzkRmYnyEDcIQcXVU7GlOd/view .

use std::array;

use anyhow::Result;
use plonky2::{
    field::{
        extension::{quintic::QuinticExtension, FieldExtension},
        goldilocks_field::GoldilocksField as F,
        types::{Field, Field64},
    },
    hash::poseidon::PoseidonHash,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use pod2::backends::plonky2::{
    basetypes::D,
    primitives::ec::{
        curve::{CircuitBuilderElliptic, Point, PointTarget, WitnessWriteCurve},
        field::{CircuitBuilderNNF, OEFTarget},
    },
};

use crate::{Fq, TWO128};

// Fq Target
type FqT = OEFTarget<5, QuinticExtension<F>>;

pub struct PoseidonEncryptTarget<const L: usize>
where
    [(); L + 1]:,
{
    ks: PointTarget,
    m: [FqT; L],
    nonce: [Target; 2],
    ct: [FqT; L + 1],
}

impl<const L: usize> PoseidonEncryptTarget<L>
where
    [(); L + 1]:,
{
    pub fn build(builder: &mut CircuitBuilder<F, D>) -> Self {
        assert!(L.is_multiple_of(3));
        assert!(L < F::ORDER as usize);
        let fqt_zero = const_fqt_zero(builder);

        // add targets
        let ks: PointTarget = builder.add_virtual_point_target();
        let m: [FqT; L] = array::from_fn(|_| builder.add_virtual_nnf_target());
        let nonce: [Target; 2] = builder.add_virtual_target_arr::<2>();
        let mut ct: [FqT; L + 1] = array::from_fn(|_| fqt_zero.clone());

        // build the circuit logic
        let f_zero = builder.constant(F::ZERO);
        let n = FqT::new([nonce[0], nonce[1], f_zero, f_zero, f_zero]);
        let l_two128: Fq = Fq::from_basefield_array([
            F::from_canonical_u64(L as u64),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ]) * TWO128;
        let l_two128_target: FqT = const_fqt_from_fq(builder, l_two128);
        let nl128: FqT = builder.nnf_add(&n, &l_two128_target);
        let fq_zero: FqT = FqT::new([f_zero, f_zero, f_zero, f_zero, f_zero]);
        let mut s: [FqT; 4] = [fq_zero, ks.x.clone(), ks.u.clone(), nl128];

        for i in 0..L / 3 {
            s = hash_state_target(builder, s);

            // absorb
            s[1] = builder.nnf_add(&s[1], &m[i * 3]);
            s[2] = builder.nnf_add(&s[2], &m[i * 3 + 1]);
            s[3] = builder.nnf_add(&s[3], &m[i * 3 + 2]);

            // release
            ct[i * 3] = s[1].clone();
            ct[i * 3 + 1] = s[2].clone();
            ct[i * 3 + 2] = s[3].clone();
        }
        s = hash_state_target(builder, s);
        ct[L] = s[1].clone();

        Self { ks, m, nonce, ct }
    }

    pub fn set_targets(
        &self,
        pw: &mut PartialWitness<F>,
        ks: Point,
        m: &[Fq],
        nonce: [F; 2],
        ct: &[Fq],
    ) -> Result<()> {
        assert_eq!(m.len(), L);
        assert_eq!(m.len() + 1, ct.len());

        pw.set_point_target(&self.ks, &ks)?;
        #[allow(clippy::needless_range_loop)]
        for i in 0..L {
            for j in 0..5 {
                pw.set_target(self.m[i].components[j], m[i].0[j])?;
            }
        }
        pw.set_target_arr(&self.nonce, &nonce)?;
        #[allow(clippy::needless_range_loop)]
        for i in 0..L + 1 {
            for j in 0..5 {
                pw.set_target(self.ct[i].components[j], ct[i].0[j])?;
            }
        }

        Ok(())
    }
}

fn hash_state_target(builder: &mut CircuitBuilder<F, D>, s: [FqT; 4]) -> [FqT; 4] {
    let elems: [Target; 4 * 5] = array::from_fn(|i| s[i / 5].components[i % 5]);
    let h = builder
        .hash_n_to_hash_no_pad::<PoseidonHash>(elems.to_vec())
        .elements;
    let mut h5: [Target; 5] = [builder.zero(); 5];
    h5[..4].copy_from_slice(&h);
    let fqt_zero = const_fqt_zero(builder);
    [
        FqT::new(h5),
        fqt_zero.clone(),
        fqt_zero.clone(),
        fqt_zero.clone(),
    ]
}

fn const_fqt_from_fq(builder: &mut CircuitBuilder<F, D>, fq: Fq) -> FqT {
    let t: [Target; 5] = array::from_fn(|i| builder.constant(fq.0[i]));
    FqT::new(t)
}
fn const_fqt_from_f(builder: &mut CircuitBuilder<F, D>, f: F) -> FqT {
    let v = builder.constant(f);
    let zero = builder.constant(F::ZERO);
    FqT::new([v, zero, zero, zero, zero])
}
fn const_fqt_zero(builder: &mut CircuitBuilder<F, D>) -> FqT {
    let zero = builder.constant(F::ZERO);
    FqT::new([zero, zero, zero, zero, zero])
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField as F, types::Sample},
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use super::*;

    #[test]
    fn test_encrypt() -> Result<()> {
        let mut rng = rand::thread_rng();
        const L: usize = 129; // (multiple of 3)

        let (_k, K) = crate::new_key();
        let ks = crate::expanded_key(K);
        let nonce: [F; 2] = [F::rand(), F::rand()];
        let msg: Vec<Fq> = (0..L).map(|_| Fq::sample(&mut rng)).collect();
        let l = msg.len();

        let ct = crate::encrypt(ks, &msg, nonce);

        let m = crate::decrypt(ks, &ct, nonce, l);
        assert_eq!(m, msg);

        // circuit declaration
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let cipher_targets = PoseidonEncryptTarget::<L>::build(&mut builder);

        println!(
            "PoseidonEncrypt circuit (L:{}) num_gates: {}",
            L,
            builder.num_gates()
        );
        let data = builder.build::<PoseidonGoldilocksConfig>();

        // set values to circuit
        let mut pw = PartialWitness::<F>::new();
        cipher_targets.set_targets(&mut pw, ks, &msg, nonce, &ct)?;

        let proof = data.prove(pw)?;
        data.verify(proof)
    }
}
