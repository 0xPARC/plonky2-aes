//! For LICENSE check out https://github.com/0xPARC/plonky2-aes/blob/main/LICENSE
//!
//! Rust native implementation of [AES-GCM (Galois Counter
//! Mode)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
//! having in mind the approach that will be done in-circuit; this means that it
//! is not written in the most rust idiomatic way, nor memory-efficient, but
//! simulating the behavior that we will do later inside the circuit.
//!

use crate::native_aes::{encrypt_block, flatten_state, key_expansion, State};

// supported tag length
const TAG_LEN: usize = 128;

/// Section 7.1 from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
pub fn encrypt<const NK: usize, const NB: usize, const NR: usize>(
    key: &[u8; NK * NB],
    nonce: &[u8; 12],
    pt: &[u8], // plaintext
) -> (Vec<u8>, Vec<u8>)
where
    [(); 4 * (NR + 1)]:,
{
    let a: &[u8] = &[]; // additional authenticated data // TODO maybe as input
    let expanded_key: [[u8; 4]; 4 * (NR + 1)] = key_expansion::<NK, NB, NR>(&key);

    // 1. CIPH_K
    let h = encrypt_block::<NR>(&[0u8; 16], &expanded_key);
    let h = flatten_state(h);

    // 2. J_0
    let j0: [u8; 16] = if nonce.len() * 8 == 96 {
        // J_0 = IV || 0^31 || 1
        let mut out = [0u8; 16];
        out[..12].copy_from_slice(&nonce.as_slice());
        out[12..16].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        out
    } else {
        panic!("unsuported at initial version; nonce.len()=12 (96 bits)");
    };

    // 3. C=GCTR()
    let c = gctr(&inc32(j0), &pt);

    // 4. u, v
    // let u = (16 - ceil(c.len() % 16)) % 16 // TODO WIP
    let u: usize = 16 * (c.len() as f64 / 16_f64).ceil() as usize - c.len();
    let v: usize = 16 * (a.len() as f64 / 16_f64).ceil() as usize - a.len();

    // 5. S = GHASH()
    let a_len: [u8; 8] = (a.len() * 8).to_be_bytes();
    let c_len: [u8; 8] = (c.len() * 8).to_be_bytes();
    let ghash_input = &[
        a.to_vec(),
        vec![0u8; v],
        c.clone(),
        vec![0u8; u],
        a_len.to_vec(),
        c_len.to_vec(),
    ]
    .concat();
    let s = ghash(h, ghash_input);

    // 6. T=MSB(GCTR()))
    let t = msb_t(TAG_LEN, &gctr(&j0, &s));

    (c, t)
}

/// Section 6.5, Algorithm 3
fn gctr(icb: &[u8; 16], x: &[u8]) -> Vec<u8> {
    todo!()
}

/// Section 6.4, Algorithm 2
fn ghash(h: [u8; 16], x: &[u8]) -> [u8; 16] {
    assert!(x.len() % 16 == 0); // multiple of 128 bits
    let m = x.len() / 16;

    let mut y = [0u8; 16]; // (128 bits)
    for i in 0..m {
        let mut xi = [0u8; 16];
        xi.clone_from_slice(&x[i * 16..i * 16 + 16]);
        let y_xi = xor_blocks(y, xi);
        y = gf_2_128_mul(y_xi, h);
    }
    y
}
fn xor_blocks(b1: [u8; 16], b2: [u8; 16]) -> [u8; 16] {
    let mut r = [0u8; 16];
    for i in 0..16 {
        r[i] = b1[i] ^ b2[i];
    }
    r
}

/// multiplication of blocks (in GF(2^128)), Algorithm 1, Section 6.3
pub fn gf_2_128_mul(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    // R = 11100001 || 0^120
    const R: [u8; 16] = [
        0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    let mut z = [0u8; 16];
    let mut v = y;
    for i in 0..128 {
        // xi: i-th bit of x
        let byte_index = i / 8;
        let bit_index = 7 - (i % 8);
        let xi = (x[byte_index] >> bit_index) & 1;

        if xi == 1 {
            z = xor_blocks(z, v);
        }
        let lsb = v[15] & 1;
        right_shift_one(&mut v);
        if lsb == 1 {
            v = xor_blocks(v, R);
        }
    }
    z
}
fn right_shift_one(block: &mut [u8; 16]) {
    let mut carry = 0u8;

    for byte in block.iter_mut() {
        let new_carry = *byte & 1;
        *byte = (*byte >> 1) | (carry << 7);
        carry = new_carry;
    }
}

/// increment the right-most 32 bits of the given block (128 bits). Section 2.
pub fn inc32(b: [u8; 16]) -> [u8; 16] {
    let mut r = b.clone();
    // counter = last 32bits
    let counter = u32::from_be_bytes([r[12], r[13], r[14], r[15]]);
    let incremented = counter.wrapping_add(1);
    let bytes = incremented.to_be_bytes();
    r[12..16].copy_from_slice(&bytes);
    r
}

/// returns the t left-most (most-significant in BE) bits of the block
pub fn msb_t(t: usize, block: &[u8]) -> Vec<u8> {
    assert!(t <= 128, "MSB_t err: max 128 bits");

    let mut out = Vec::with_capacity((t + 7) / 8); // ceiling bytes
    let mut bits_left = t;
    for byte in block.iter() {
        if bits_left == 0 {
            break;
        }
        if bits_left >= 8 {
            out.push(*byte);
            bits_left -= 8;
        } else {
            // take the top `bits_left` bits of the byte
            let mask = 0xFFu8 << (8 - bits_left);
            out.push(byte & mask);
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use aes_gcm::{
        aead::{Aead, AeadCore, Key, KeyInit, OsRng},
        Aes128Gcm, Nonce,
    };

    /// test checking against NIST test vector
    #[test]
    fn test_aes_gcm_encrypt_nist_vector() {
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
        let key: [u8; 16] = [
            0xFE, 0xFF, 0xE9, 0x92, 0x86, 0x65, 0x73, 0x1C, 0x6D, 0x6A, 0x8F, 0x94, 0x67, 0x30,
            0x83, 0x08,
        ];
        let nonce: [u8; 12] = [
            0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88,
        ];
        let plaintext = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let aad: &[u8] = &[];
        let expected_ciphertext: &[u8] = &[
            0x32, 0x47, 0x18, 0x4B, 0x3C, 0x4F, 0x69, 0xA4, 0x4D, 0xBC, 0xD2, 0x28, 0x87, 0xBB,
            0xB4, 0x18,
        ];

        todo!();
    }

    /// test checking against external aes-gcm lib
    #[test]
    fn test_with_external_lib() -> anyhow::Result<()> {
        let key: &[u8; 16] = &[42; 16];
        let nonce: &[u8; 12] = &[111; 12];
        let pt = b"plaintext test message";

        let key: &Key<Aes128Gcm> = key.into();
        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(nonce);

        let ciphertext = cipher.encrypt(&nonce, pt.as_ref()).unwrap();

        let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(&plaintext, pt);
        Ok(())
    }
}
