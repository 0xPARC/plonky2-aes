use std::array;

use num::bigint::BigUint;
use plonky2::{
    field::goldilocks_field::GoldilocksField as F,
    hash::{hashing::hash_n_to_m_no_pad, poseidon::PoseidonPermutation},
};
use pod2::backends::plonky2::primitives::ec::curve::{GROUP_ORDER, Point};

use crate::ECGFP5SecretKey;

pub mod circuit;

/// A variant of 'hashed ElGamal' with addition in place of
/// XORing. Assumes a message of 5 field elements and uses the
/// Poseidon hash function outputting 5 field elements.
pub fn hashed_elgamal_encrypt(pk: Point, nonce: &BigUint, msg: [F; 5]) -> (Point, [F; 5]) {
    assert!(nonce < &GROUP_ORDER);
    let nonce_times_gen = nonce * Point::generator();
    let nonce_times_pk = nonce * pk;
    let h = hash_n_to_m_no_pad::<F, PoseidonPermutation<_>>(&nonce_times_pk.as_fields(), 5);
    (nonce_times_gen, array::from_fn(|i| msg[i] + h[i]))
}

/// Inverse to `hashed_elgamal_encrypt`.
pub fn hashed_elgamal_decrypt(sk: ECGFP5SecretKey, ct: (Point, [F; 5])) -> [F; 5] {
    let nonce_times_pk = &sk.0 * ct.0;
    let h = hash_n_to_m_no_pad::<F, PoseidonPermutation<_>>(&nonce_times_pk.as_fields(), 5);
    array::from_fn(|i| ct.1[i] - h[i])
}

#[cfg(test)]
mod tests {
    use num_bigint::RandBigInt;
    use plonky2::field::{
        goldilocks_field::GoldilocksField as F,
        types::{Field, Field64},
    };
    use pod2::backends::plonky2::primitives::ec::curve::GROUP_ORDER;
    use rand::{Rng, rngs::OsRng};

    use crate::{
        ECGFP5SecretKey,
        hashed_elgamal::{hashed_elgamal_decrypt, hashed_elgamal_encrypt},
    };

    #[test]
    fn round_trip_encryption() {
        (0..100).for_each(|_| {
            let sk = ECGFP5SecretKey::rand();
            let pk = sk.public_key();

            let msg = std::array::from_fn(|_| F::from_canonical_u64(OsRng.gen_range(0..F::ORDER)));
            let nonce = OsRng.gen_biguint_below(&GROUP_ORDER);

            let encrypted_msg = hashed_elgamal_encrypt(pk, &nonce, msg);
            let decrypted_msg = hashed_elgamal_decrypt(sk, encrypted_msg);

            assert_eq!(msg, decrypted_msg);
        })
    }
}
