use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::witness::PartialWitness,
    plonk::circuit_builder::CircuitBuilder,
};
use pod2::backends::plonky2::{
    basetypes::{D, F},
    primitives::ec::{
        bits::{BigUInt320Target, CircuitBuilderBits},
        curve::{CircuitBuilderElliptic, Point, PointTarget, WitnessWriteCurve},
    },
};

use crate::ECGFP5SecretKey;

/// EcGFp5 secret key target type
pub struct ECGFP5SecretKeyTarget(pub BigUInt320Target);

/// EcGFp5 public key (point) type alias
pub type PublicKeyTarget = PointTarget;

pub trait CircuitBuilderECGFP5PublicKey<F: RichField + Extendable<D>, const D: usize> {
    /// Adds secret key target
    fn add_secret_key(&mut self) -> ECGFP5SecretKeyTarget;

    /// Derives public key from secret key
    fn public_key(&mut self, sk: &ECGFP5SecretKeyTarget) -> PublicKeyTarget;
}

impl CircuitBuilderECGFP5PublicKey<F, D> for CircuitBuilder<F, D> {
    fn add_secret_key(&mut self) -> ECGFP5SecretKeyTarget {
        ECGFP5SecretKeyTarget(self.add_virtual_biguint320_target())
    }

    fn public_key(&mut self, sk: &ECGFP5SecretKeyTarget) -> PublicKeyTarget {
        let generator = self.constant_point(Point::generator());
        self.multiply_point(&sk.0.bits, &generator)
    }
}

pub trait PartialWitnessECGFP5PublicKey {
    /// Sets EcGFp5 secret key witnesses
    fn set_secret_key_target(
        &mut self,
        target: &ECGFP5SecretKeyTarget,
        value: &ECGFP5SecretKey,
    ) -> anyhow::Result<()>;
}

impl PartialWitnessECGFP5PublicKey for PartialWitness<F> {
    fn set_secret_key_target(
        &mut self,
        target: &ECGFP5SecretKeyTarget,
        value: &ECGFP5SecretKey,
    ) -> anyhow::Result<()> {
        self.set_biguint320_target(&target.0, &value.0)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use pod2::backends::plonky2::{
        basetypes::{D, F},
        primitives::ec::curve::WitnessWriteCurve,
    };

    use crate::{
        ECGFP5SecretKey,
        circuit::{CircuitBuilderECGFP5PublicKey, PartialWitnessECGFP5PublicKey},
    };

    #[test]
    fn public_key_calculation() -> anyhow::Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let sk_target = builder.add_secret_key();
        let pk_target = builder.public_key(&sk_target);

        let data = builder.build::<PoseidonGoldilocksConfig>();
        (0..10).try_for_each(|_| {
            let sk = ECGFP5SecretKey::rand();
            let pk = sk.public_key();

            let mut pw = PartialWitness::new();
            pw.set_secret_key_target(&sk_target, &sk)?;
            pw.set_point_target(&pk_target, &pk)?;

            let proof = data.prove(pw)?;
            data.verify(proof)
        })
    }
}
