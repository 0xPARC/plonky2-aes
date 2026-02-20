//! For LICENSE check out https://github.com/0xPARC/plonky2-crypto-gadgets/blob/main/LICENSE
//!
//! Implements Poseidon encryption as described at
//! https://drive.google.com/file/d/1EVrP3DzoGbmzkRmYnyEDcIQcXVU7GlOd/view .

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![allow(dead_code)] // TMP
#![allow(non_snake_case)]

use std::array;

use num::bigint::BigUint;
use num_bigint::RandBigInt;
use plonky2::{
    field::{
        extension::{quintic::QuinticExtension, FieldExtension},
        goldilocks_field::GoldilocksField as F,
        types::{Field, Field64},
    },
    hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
};
use pod2::backends::plonky2::primitives::ec::curve::{Point, GROUP_ORDER};
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

pub(crate) const TWO128: Fq =
    QuinticExtension::<F>([F(F::ORDER - 1), F(F::ORDER - 1), F::ZERO, F::ZERO, F::ZERO]);

// /// 2^128
// pub(crate) fn two_128() -> Fq {
//     // WIP TODO
//     let two32 = Fq::from(F::from_canonical_u64(2_u64.pow(32)));
//     let two64: Fq = two32 * two32;
//     let two128: Fq = two64 * two64;
//     // note: two64 gets two32-1
//     // dbg!(2_u64.pow(32));
//     // dbg!(F::from_canonical_u64(2_u64.pow(32)));
//     // dbg!(&two32);
//     // dbg!(&two64);
//     // dbg!(&two128);
//     two128
// }

pub fn f_vec_to_fq_vec(f: &[F]) -> Vec<Fq> {
    f.chunks(5)
        .map(|c| {
            let mut e: [F; 5] = [F::ZERO; 5];
            e[0..c.len()].copy_from_slice(c);
            Fq::from_basefield_array(e)
        })
        .collect()
}

pub fn encrypt_f(ks: Point, msg_f: &[F], nonce: [F; 2]) -> Vec<F> {
    let l_f = msg_f.len();
    dbg!(msg_f.len());
    dbg!(&msg_f);
    let msg: Vec<Fq> = f_vec_to_fq_vec(msg_f);
    dbg!(msg.len());
    dbg!(&msg);
    let ct = encrypt(ks, &msg, nonce);
    ct.into_iter().flat_map(|ct_i| ct_i.0).collect()
}
pub fn encrypt(ks: Point, msg: &[Fq], nonce: [F; 2]) -> Vec<Fq> {
    let mut m = msg.to_vec(); // pad m
    m.resize(m.len().next_multiple_of(3), Fq::ZERO);
    assert!(m.len() < F::ORDER as usize);

    let l = Fq::from(F::from_canonical_u64(msg.len() as u64));
    let nonce_5: [F; 5] = [nonce[0], nonce[1], F::ZERO, F::ZERO, F::ZERO];
    let n = Fq::from_basefield_array(nonce_5);
    let nl128: Fq = n + l * TWO128;
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

pub fn decrypt_f(ks: Point, ct_f: &[F], nonce: [F; 2], l: usize) -> Vec<F> {
    let ct: Vec<Fq> = f_vec_to_fq_vec(ct_f);
    let m = decrypt(ks, &ct, nonce, l);
    m.to_vec().into_iter().flat_map(|e| e.0).collect()
}
pub fn decrypt(ks: Point, ct: &[Fq], nonce: [F; 2], l: usize) -> Vec<Fq> {
    let l_fq = Fq::from(F::from_canonical_u64(l as u64));
    let nonce_5: [F; 5] = [nonce[0], nonce[1], F::ZERO, F::ZERO, F::ZERO];
    let n = Fq::from_basefield_array(nonce_5);
    let nl128: Fq = n + l_fq * TWO128;
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
    // Note: here we're using plonky2's normal poseidon, not duplex-sponge
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
        let nonce: [F; 2] = [F::rand(), F::rand()];
        // let msg: Vec<Fq> = (0..msg_len).map(|_| Fq::sample(&mut rng)).collect();
        let msg: Vec<F> = (0..msg_len).map(|_| F::sample(&mut rng)).collect();
        let l = msg.len().div_ceil(5);
        dbg!(msg.len(), l);

        let ct = encrypt_f(ks, &msg, nonce);

        let m = decrypt_f(ks, &ct, nonce, l);
        assert_eq!(m, msg);
    }
}
