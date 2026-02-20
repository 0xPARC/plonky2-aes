use num::bigint::BigUint;
use pod2::backends::plonky2::primitives::ec::curve::{GROUP_ORDER, Point};

use crate::ECGFP5SecretKey;

pub mod circuit;

/// ElGamal encryption on EcGFp5
pub fn elgamal_encrypt(pk: Point, nonce: &BigUint, msg: Point) -> (Point, Point) {
    assert!(nonce < &GROUP_ORDER);
    let nonce_times_gen = nonce * Point::generator();
    let nonce_times_pk = nonce * pk;
    (nonce_times_gen, msg + nonce_times_pk)
}

/// ElGamal decryption on EcGFp5
pub fn elgamal_decrypt(sk: ECGFP5SecretKey, ct: (Point, Point)) -> Point {
    let nonce_times_pk = &sk.0 * ct.0;
    ct.1 + nonce_times_pk.inverse()
}

#[cfg(test)]
mod tests {
    use num_bigint::RandBigInt;
    use pod2::backends::plonky2::primitives::ec::curve::{GROUP_ORDER, Point};
    use rand::rngs::OsRng;

    use crate::elgamal::{ECGFP5SecretKey, elgamal_decrypt, elgamal_encrypt};

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
