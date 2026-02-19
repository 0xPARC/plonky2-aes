//! For LICENSE check out https://github.com/0xPARC/plonky2-crypto-gadgets/blob/main/LICENSE

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![allow(dead_code)] // TMP
#![allow(non_snake_case)]

use std::array;

use num::bigint::BigUint;
use num_bigint::RandBigInt;
use plonky2::{
    field::{
        extension::{FieldExtension, quintic::QuinticExtension},
        goldilocks_field::GoldilocksField as F,
        types::Field,
    },
    hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
};
use pod2::backends::plonky2::primitives::ec::curve::{GROUP_ORDER, Point};
use rand::rngs::OsRng;

pub mod circuit;

// ECField
type Fq = QuinticExtension<F>;

pub fn new_key() -> (BigUint, Point) {
    let k: BigUint = OsRng.gen_biguint_below(&GROUP_ORDER);
    let K = &k * Point::generator();
    (k, K)
}
pub fn expanded_key(K: Point) -> Point {
    let r: BigUint = OsRng.gen_biguint_below(&GROUP_ORDER);
    &r * K
}

pub(crate) fn two_128() -> Fq {
    // WIP TODO
    let two32 = Fq::from(F::from_canonical_u64(2_u64.pow(32)));
    // dbg!(2_u64.pow(32));
    // dbg!(F::from_canonical_u64(2_u64.pow(32)));
    // dbg!(&two32);
    let two64: Fq = two32 * two32;
    // dbg!(&two64);
    let two128: Fq = two64 * two64;
    // dbg!(&two128);
    two128
}

pub fn encrypt(ks: Point, msg: &[Fq], nonce: F) -> Vec<Fq> {
    // pad m
    let mut m = msg.to_vec();
    m.resize(m.len().next_multiple_of(3), Fq::ZERO);

    let l = Fq::from(F::from_canonical_u64(msg.len() as u64));
    let n = Fq::from(nonce);
    let nl128: Fq = n + l * two_128();
    let mut s: [Fq; 4] = [Fq::ZERO, ks.x, ks.u, nl128];

    let mut ct: Vec<Fq> = vec![Fq::ZERO; m.len() + 1];
    for i in 0..m.len() / 3 {
        s = hash_state(s);

        // absorb
        s[1] += m[i * 3];
        s[2] += m[i * 3 + 1];
        s[3] += m[i * 3 + 2];

        // release
        ct[i * 3] = s[1];
        ct[i * 3 + 1] = s[2];
        ct[i * 3 + 2] = s[3];
    }
    s = hash_state(s);
    ct[m.len()] = s[1];
    ct
}

pub fn decrypt(ks: Point, ct: &[Fq], nonce: F, l: usize) -> Vec<Fq> {
    let l_fq = Fq::from(F::from_canonical_u64(l as u64));
    let n = Fq::from(nonce);
    let nl128: Fq = n + l_fq * two_128();
    let mut s: [Fq; 4] = [Fq::ZERO, ks.x, ks.u, nl128];

    let mut m: Vec<Fq> = vec![Fq::ZERO; ct.len() - 1];
    for i in 0..ct.len() / 3 {
        s = hash_state(s);

        // release
        m[3 * i] = s[1] + ct[3 * i];
        m[3 * i + 1] = s[2] + ct[3 * i + 1];
        m[3 * i + 2] = s[3] + ct[3 * i + 2];

        // modify state
        s[1] = ct[3 * i];
        s[2] = ct[3 * i + 1];
        s[3] = ct[3 * i + 2];
    }

    if l > 3 {
        if l % 3 == 2 {
            assert_eq!(m[m.len() - 1], Fq::ZERO);
        } else if l % 3 == 1 {
            assert_eq!(m[m.len() - 1], Fq::ZERO);
            assert_eq!(m[m.len() - 2], Fq::ZERO);
        }
    }
    s = hash_state(s);
    assert_eq!(ct[ct.len() - 1], s[1]);
    m[0..l].to_vec()
}

fn hash_state(s: [Fq; 4]) -> [Fq; 4] {
    let elems: [F; 4 * 5] = array::from_fn(|i| s[i / 5].0[i % 5]);
    let h = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(&elems).elements;
    let mut h5: [F; 5] = [F::ZERO; 5];
    h5[..4].copy_from_slice(&h);
    [Fq::from_basefield_array(h5), Fq::ZERO, Fq::ZERO, Fq::ZERO]
}

#[cfg(test)]
mod tests {
    use plonky2::field::types::Sample;

    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        test_encrypt_decrypt_op(9);
        test_encrypt_decrypt_op(10);
        test_encrypt_decrypt_op(11);
        test_encrypt_decrypt_op(12);
        test_encrypt_decrypt_op(128);
        test_encrypt_decrypt_op(129);
        test_encrypt_decrypt_op(1024);
        test_encrypt_decrypt_op(1023);
        test_encrypt_decrypt_op(1025);
    }
    fn test_encrypt_decrypt_op(msg_len: usize) {
        let mut rng = rand::thread_rng();

        let (_k, K) = new_key();
        let ks = expanded_key(K);
        let nonce = F::rand();
        let msg: Vec<Fq> = (0..msg_len).map(|_| Fq::sample(&mut rng)).collect();
        let l = msg.len();

        let ct = encrypt(ks, &msg, nonce);

        let m = decrypt(ks, &ct, nonce, l);
        assert_eq!(m, msg);
    }
}
