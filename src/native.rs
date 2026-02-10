//! For LICENSE check out https://github.com/0xPARC/plonky2-aes/blob/main/LICENSE
//!
//! Rust native implementation of
//! [AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) having
//! in mind the approach that will be done in-circuit; this means that it is not
//! written in the most rust idiomatic way, but simulating the behavior that we
//! will do later inside the circuit.

use std::array;

use crate::constants::{RCON, SBOX};

pub(crate) type State = [[u8; 4]; 4];

fn flatten_state(s: State) -> [u8; 16] {
    let mut r = [0u8; 16];
    for i in 0..4 {
        for j in 0..4 {
            // TODO
            r[i * 4 + j] = s[i][j];
        }
    }
    r
}

/// encrypts an AES block (16 bytes). NR determines the number of rounds,
/// where AES-128: NR=10, AES-196: NR=12, AES-256: NR=14.
pub(crate) fn encrypt_block<const NR: usize>(
    input: &[u8; 16],
    w: &[[u8; 4]; 4 * (NR + 1)],
) -> State {
    assert_eq!(4 * (NR + 1), w.len());

    let mut s: State = [[0; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            // TODO
            s[i][j] = input[i + 4 * j];
        }
    }

    s = add_round_key(s, &w[0..4]);

    for round in 1..NR {
        s = sub_bytes(s);
        s = shift_rows(s);
        s = mix_columns(s);
        s = add_round_key(s, &w[4 * round..4 * round + 4]);
    }

    s = sub_bytes(s);
    s = shift_rows(s);
    s = add_round_key(s, &w[4 * NR..4 * NR + 4]);

    s
}

pub(crate) fn sub_bytes(s: State) -> State {
    let mut r = [[0u8; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            r[i][j] = SBOX[s[i][j] as usize];
        }
    }
    r
}

pub(crate) fn shift_rows<T: Copy>(s: [[T; 4]; 4]) -> [[T; 4]; 4] {
    array::from_fn(|i| array::from_fn(|j| s[i][(i + j) % 4]))
}

pub(crate) fn mix_columns(s: State) -> State {
    let mut r = [[0u8; 4]; 4];
    for c in 0..4 {
        r[0][c] = gf_2_8_mul(0x02, s[0][c]) ^ gf_2_8_mul(0x03, s[1][c]) ^ s[2][c] ^ s[3][c];
        r[1][c] = s[0][c] ^ gf_2_8_mul(0x02, s[1][c]) ^ gf_2_8_mul(0x03, s[2][c]) ^ s[3][c];
        r[2][c] = s[0][c] ^ s[1][c] ^ gf_2_8_mul(0x02, s[2][c]) ^ gf_2_8_mul(0x03, s[3][c]);
        r[3][c] = gf_2_8_mul(0x03, s[0][c]) ^ s[1][c] ^ s[2][c] ^ gf_2_8_mul(0x02, s[3][c]);
    }
    r
}

/// multiplication in GF(2^8), section 4.2
fn gf_2_8_mul(a_raw: u8, b_raw: u8) -> u8 {
    let mut r = 0u8;
    let mut a = a_raw;
    let mut b = b_raw;
    for _ in 0..8 {
        if b & 1 == 1 {
            r ^= a
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit == 0x80 {
            a ^= 0x1b; // ^0x1b = reduce mod m(x) = x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    r
}

fn add_round_key(s: State, key: &[[u8; 4]]) -> State {
    assert_eq!(key.len(), 4); // ensures that key: [[u8;4]; 4]
    let mut r: [[u8; 4]; 4] = [[0; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            r[i][j] = s[i][j] ^ key[j][i];
        }
    }
    r
}

pub(crate) fn key_expansion<const NK: usize, const NB: usize, const NR: usize>(
    key: &[u8; NK * NB],
) -> [[u8; 4]; 4 * (NR + 1)]
where
    [(); 4 * (NR + 1)]:,
    [(); 4 * 4 * (NR + 1)]:,
{
    let mut w = [[0u8; 4]; 4 * (NR + 1)]; // expanded key

    for i in 0..NK {
        w[i].clone_from_slice(&key[i * 4..i * 4 + 4]);
    }

    for i in NK..4 * (NR + 1) {
        let mut temp = w[i - 1];
        if i % NK == 0 {
            let rcon: [u8; 4] = [RCON[i / NK], 0, 0, 0];
            temp = xor_words(sub_word(rot_word(temp)), rcon);
        } else if NK > 6 && i % NK == 4 {
            temp = sub_word(temp);
        }
        w[i] = xor_words(w[i - NK], temp);
    }
    w
}

pub(crate) fn rot_word<T: Copy>(w: [T; 4]) -> [T; 4] {
    array::from_fn(|i| w[(i + 1) % 4])
}
fn sub_word(w: [u8; 4]) -> [u8; 4] {
    let mut r = [0u8; 4];
    for i in 0..4 {
        r[i] = SBOX[w[i] as usize];
    }
    r
}
fn xor_words(w1: [u8; 4], w2: [u8; 4]) -> [u8; 4] {
    let mut r = [0u8; 4];
    for i in 0..4 {
        r[i] = w1[i] ^ w2[i];
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// test against test vectors from Appendix A
    #[test]
    fn test_key_expansion() {
        // AES-128
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let expected: [u32; 4] = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];
        let w = key_expansion::</*Nk,Nb,Nr*/ 4, 4, 10>(&key);
        for i in 0..4 {
            assert_eq!(expected[i], u32::from_be_bytes(w[i]));
        }

        // AES-196
        let key = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];
        let expected: [u32; 6] = [
            0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b,
        ];
        let w = key_expansion::</*Nk,Nb,Nr*/ 6, 4, 12>(&key);
        for i in 0..6 {
            assert_eq!(expected[i], u32::from_be_bytes(w[i]));
        }

        // AES-256
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let expected: [u32; 8] = [
            0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3,
            0x0914dff4,
        ];
        let w = key_expansion::</*Nk,Nb,Nr*/ 8, 4, 14>(&key);
        for i in 0..8 {
            assert_eq!(expected[i], u32::from_be_bytes(w[i]));
        }
    }

    /// test against paper test vector (appendix B)
    #[test]
    fn test_encrypt_block_test_vector() {
        let input: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let expanded_key = key_expansion::<4, 4, 10>(&key);

        let c = encrypt_block::<10>(&input, &expanded_key);

        let expected: [u8; 16] = [
            0x39, 0x02, 0xdc, 0x19, 0x25, 0xdc, 0x11, 0x6a, 0x84, 0x09, 0x85, 0x0b, 0x1d, 0xfb,
            0x97, 0x32,
        ];

        assert_eq!(flatten_state(c), expected);
    }

    /// test with loop of random-values against a rust well-tested library
    #[test]
    fn test_encrypt_block_external_lib() {
        // TODO random-values loop against a rust well-tested library
    }
}
