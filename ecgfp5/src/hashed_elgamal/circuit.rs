use std::array;

use plonky2::{
    field::extension::Extendable,
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use pod2::backends::plonky2::{
    basetypes::{D, F},
    primitives::ec::{
        bits::BigUInt320Target,
        curve::{CircuitBuilderElliptic, Point, PointTarget},
    },
};

use crate::circuit::PublicKeyTarget;

pub trait CircuitBuilderHashedElGamal<F: RichField + Extendable<D>, const D: usize> {
    /// Encrypts an EcGFp5 point according to the 'hashed ElGamal '
    /// scheme described in `super::hashed_elgamal_encrypt`.
    fn hashed_elgamal_encrypt(
        &mut self,
        pk: &PublicKeyTarget,
        nonce: &BigUInt320Target,
        msg: [Target; 5],
    ) -> (PointTarget, [Target; 5]);
}

impl CircuitBuilderHashedElGamal<F, D> for CircuitBuilder<F, D> {
    fn hashed_elgamal_encrypt(
        &mut self,
        pk: &PublicKeyTarget,
        nonce: &BigUInt320Target,
        msg: [Target; 5],
    ) -> (PointTarget, [Target; 5]) {
        let generator = self.constant_point(Point::generator());
        let nonce_times_gen = self.multiply_point(&nonce.bits, &generator);
        let nonce_times_pk = self.multiply_point(&nonce.bits, pk);
        let h = self.hash_n_to_m_no_pad::<PoseidonHash>(
            [nonce_times_pk.x.components, nonce_times_pk.u.components].concat(),
            5,
        );
        (nonce_times_gen, array::from_fn(|i| self.add(msg[i], h[i])))
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::RandBigInt;
    use plonky2::{
        field::types::{Field, Field64},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use pod2::backends::plonky2::{
        basetypes::{D, F},
        primitives::ec::{
            bits::CircuitBuilderBits,
            curve::{CircuitBuilderElliptic, GROUP_ORDER, WitnessWriteCurve},
        },
    };
    use rand::{Rng, rngs::OsRng};

    use crate::{
        ECGFP5SecretKey,
        hashed_elgamal::{circuit::CircuitBuilderHashedElGamal, hashed_elgamal_encrypt},
    };

    #[test]
    fn hashed_elgamal_encryption() -> anyhow::Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let pk_target = builder.add_virtual_point_target();
        let nonce_target = builder.add_virtual_biguint320_target();
        let msg_target = builder.add_virtual_target_arr();

        let ct_target = builder.hashed_elgamal_encrypt(&pk_target, &nonce_target, msg_target);

        let data = builder.build::<PoseidonGoldilocksConfig>();

        (0..10).try_for_each(|_| {
            let sk = ECGFP5SecretKey::rand();
            let pk = sk.public_key();

            let msg = std::array::from_fn(|_| F::from_canonical_u64(OsRng.gen_range(0..F::ORDER)));
            let nonce = OsRng.gen_biguint_below(&GROUP_ORDER);

            let encrypted_msg = hashed_elgamal_encrypt(pk, &nonce, msg);

            let mut pw = PartialWitness::new();
            pw.set_point_target(&pk_target, &pk)?;
            pw.set_target_arr(&msg_target, &msg)?;
            pw.set_biguint320_target(&nonce_target, &nonce)?;
            pw.set_point_target(&ct_target.0, &encrypted_msg.0)?;
            pw.set_target_arr(&ct_target.1, &encrypted_msg.1)?;

            let proof = data.prove(pw)?;
            data.verify(proof)
        })
    }
}
