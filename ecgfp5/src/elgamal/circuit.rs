use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
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

pub trait CircuitBuilderElGamal<F: RichField + Extendable<D>, const D: usize> {
    /// Encrypts an EcGFp5 point according to the ElGamal scheme.
    fn elgamal_encrypt(
        &mut self,
        pk: &PublicKeyTarget,
        nonce: &BigUInt320Target,
        msg: &PointTarget,
    ) -> (PointTarget, PointTarget);
}

impl CircuitBuilderElGamal<F, D> for CircuitBuilder<F, D> {
    fn elgamal_encrypt(
        &mut self,
        pk: &PublicKeyTarget,
        nonce: &BigUInt320Target,
        msg: &PointTarget,
    ) -> (PointTarget, PointTarget) {
        let generator = self.constant_point(Point::generator());
        let nonce_times_gen = self.multiply_point(&nonce.bits, &generator);
        let nonce_times_pk = self.multiply_point(&nonce.bits, pk);
        (nonce_times_gen, self.add_point(msg, &nonce_times_pk))
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::RandBigInt;
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use pod2::backends::plonky2::{
        basetypes::{D, F},
        primitives::ec::{
            bits::CircuitBuilderBits,
            curve::{CircuitBuilderElliptic, GROUP_ORDER, Point, WitnessWriteCurve},
        },
    };
    use rand::rngs::OsRng;

    use crate::{
        ECGFP5SecretKey,
        elgamal::{circuit::CircuitBuilderElGamal, elgamal_encrypt},
    };

    #[test]
    fn elgamal_encryption() -> anyhow::Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let pk_target = builder.add_virtual_point_target();
        let nonce_target = builder.add_virtual_biguint320_target();
        let msg_target = builder.add_virtual_point_target();

        let ct_target = builder.elgamal_encrypt(&pk_target, &nonce_target, &msg_target);

        let data = builder.build::<PoseidonGoldilocksConfig>();

        (0..10).try_for_each(|_| {
            let sk = ECGFP5SecretKey::rand();
            let pk = sk.public_key();

            let msg = Point::new_rand_from_subgroup();
            let nonce = OsRng.gen_biguint_below(&GROUP_ORDER);

            let encrypted_msg = elgamal_encrypt(pk, &nonce, msg);

            let mut pw = PartialWitness::new();
            pw.set_point_target(&pk_target, &pk)?;
            pw.set_point_target(&msg_target, &msg)?;
            pw.set_biguint320_target(&nonce_target, &nonce)?;
            pw.set_point_target(&ct_target.0, &encrypted_msg.0)?;
            pw.set_point_target(&ct_target.1, &encrypted_msg.1)?;

            let proof = data.prove(pw)?;
            data.verify(proof)
        })
    }
}
