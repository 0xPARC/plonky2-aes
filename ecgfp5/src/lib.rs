use std::array;

use num::BigUint;
use num_bigint::RandBigInt;
use plonky2::field::{
    extension::quintic::QuinticExtension,
    goldilocks_field::GoldilocksField as F,
    types::{Field, Field64},
};
use pod2::backends::plonky2::primitives::ec::curve::{GROUP_ORDER, Point};
use rand::{Rng, rngs::OsRng};

pub mod circuit;
pub mod elgamal;
pub mod hashed_elgamal;

// Message encoding constants
pub const BITS_PER_LIMB: usize = 32;
pub const TOTAL_BITS: usize = 5 * BITS_PER_LIMB;

/// EcGFp5 secret key type
pub struct ECGFP5SecretKey(pub BigUint);

impl ECGFP5SecretKey {
    /// EcGFp5 secret key constructor
    pub fn new(s: BigUint) -> Self {
        assert!(&s < &GROUP_ORDER);
        Self(s)
    }

    /// Random EcGFp5 secret key generator
    pub fn rand() -> Self {
        Self(OsRng.gen_biguint_below(&GROUP_ORDER))
    }

    /// Derives public key from secret key
    pub fn public_key(&self) -> Point {
        &self.0 * Point::generator()
    }
}

/// Convert `TOTAL_BITS`-bit biguint to an EcGFp5 point by padding
/// with random bits. This is an adaptation of the probabilistic
/// algorithm described in §3 of Koblitz's *Elliptic Curve
/// Cryptosystems* (1987).
pub fn encode_binary(x: &BigUint) -> Point {
    let num_bits = x.bits() as usize;
    assert!(num_bits <= TOTAL_BITS);

    let bs_bits = [x.to_radix_le(2), vec![0; TOTAL_BITS - num_bits]].concat();
    let bs_fields: Vec<F> = bs_bits
        .chunks(BITS_PER_LIMB)
        .map(|bits| {
            F::from_noncanonical_biguint(
                BigUint::from_radix_le(bits, 2).expect("Should be a valid bit decomposition"),
            )
        })
        .collect();

    std::iter::repeat_with(|| {
        let ec_fields: [_; 5] = array::from_fn(|i| {
            let random_element: u64 = OsRng.gen_range(0..F::ORDER - bs_fields[i].0);
            F::from_canonical_u64(
                bs_fields[i].0 + ((random_element >> BITS_PER_LIMB) << BITS_PER_LIMB),
            )
        });
        QuinticExtension(ec_fields)
    })
    .find_map(|w| Point::decompress_into_subgroup(&w).ok())
    .expect("Should be a match!")
}

/// Convert an EcGFp5 point to a `TOTAL_BITS`-bit biguint. This is the
/// inverse to `encode_binary`.
pub fn decode_binary(p: Point) -> BigUint {
    let msg_bits: Vec<_> = p
        .compress_from_subgroup()
        .unwrap()
        .0
        .into_iter()
        .flat_map(|f| {
            BigUint::from(f.0)
                .to_radix_le(2)
                .into_iter()
                .take(BITS_PER_LIMB)
                .collect::<Vec<_>>()
        })
        .collect();
    BigUint::from_bytes_le(
        &BigUint::from_radix_le(&msg_bits, 2)
            .expect("Should be a valid bit slice.")
            .to_radix_le(256),
    )
}
#[cfg(test)]
mod tests {
    use num::BigUint;
    use num_bigint::RandBigInt;
    use rand::rngs::OsRng;

    use crate::{TOTAL_BITS, decode_binary, encode_binary};

    #[test]
    fn msg_encoding_roundtrip() {
        (0..100).for_each(|_| {
            let test_val = OsRng.gen_biguint_below(&BigUint::from(2u32).pow(TOTAL_BITS as u32));
            let pt = encode_binary(&test_val);
            let maybe_test_val = decode_binary(pt);
            assert_eq!(test_val, maybe_test_val);
        })
    }
}
