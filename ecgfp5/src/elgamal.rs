use std::array;

use num::bigint::BigUint;
use num_bigint::RandBigInt;
use plonky2::field::{
    extension::quintic::QuinticExtension,
    goldilocks_field::GoldilocksField as F,
    types::{Field, Field64},
};
use pod2::backends::plonky2::primitives::ec::curve::{GROUP_ORDER, Point};
use rand::{Rng, rngs::OsRng};

pub mod circuit;

// Message encoding constants
pub const BITS_PER_LIMB: usize = 32;
pub const TOTAL_BITS: usize = 5 * BITS_PER_LIMB;

pub struct ECGFP5SecretKey(pub BigUint);

impl ECGFP5SecretKey {
    pub fn new(s: BigUint) -> Self {
        assert!(&s < &GROUP_ORDER);
        Self(s)
    }

    pub fn rand() -> Self {
        Self(OsRng.gen_biguint_below(&GROUP_ORDER))
    }

    pub fn public_key(&self) -> Point {
        &self.0 * Point::generator()
    }
}

pub fn elgamal_encrypt(pk: Point, nonce: &BigUint, msg: Point) -> (Point, Point) {
    assert!(nonce < &GROUP_ORDER);
    let nonce_times_gen = nonce * Point::generator();
    let nonce_times_pk = nonce * pk;
    (nonce_times_gen, msg + nonce_times_pk)
}

pub fn elgamal_decrypt(sk: ECGFP5SecretKey, ct: (Point, Point)) -> Point {
    let nonce_times_pk = &sk.0 * ct.0;
    ct.1 + nonce_times_pk.inverse()
}

/// Convert `TOTAL_BITS`-bit biguint to a point by padding with random bits.
pub fn biguint_to_point(x: &BigUint) -> Point {
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

pub fn point_to_biguint(p: Point) -> BigUint {
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
    use pod2::backends::plonky2::primitives::ec::curve::{GROUP_ORDER, Point};
    use rand::rngs::OsRng;

    use crate::elgamal::{
        ECGFP5SecretKey, TOTAL_BITS, biguint_to_point, elgamal_decrypt, elgamal_encrypt,
        point_to_biguint,
    };

    #[test]
    fn msg_encoding_roundtrip() {
        (0..100).for_each(|_| {
            let test_val = OsRng.gen_biguint_below(&BigUint::from(2u32).pow(TOTAL_BITS as u32));
            let pt = biguint_to_point(&test_val);
            let maybe_test_val = point_to_biguint(pt);
            assert_eq!(test_val, maybe_test_val);
        })
    }

    #[test]
    fn round_trip_encryption() {
        (0..100).for_each(|_| {
            let sk = ECGFP5SecretKey::rand();
            let pk = sk.public_key();

            let msg = Point::new_rand_from_subgroup();
            let nonce = OsRng.gen_biguint_below(&GROUP_ORDER);

            let encrypted_msg = elgamal_encrypt(pk, &nonce, msg);
            let decrypted_msg = elgamal_decrypt(sk, encrypted_msg);

            assert_eq!(msg, decrypted_msg);
        })
    }
}
