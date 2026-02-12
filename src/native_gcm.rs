//! For LICENSE check out https://github.com/0xPARC/plonky2-aes/blob/main/LICENSE
//!
//! Rust native implementation of [AES-GCM (Galois Counter
//! Mode)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
//! having in mind the approach that will be done in-circuit; this means that it
//! is not written in the most rust idiomatic way, nor memory-efficient, but
//! simulating the behavior that we will do later inside the circuit.
//!

use crate::native_aes::{encrypt_block, flatten_state, key_expansion};

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
    let expanded_key: [[u8; 4]; 4 * (NR + 1)] = key_expansion::<NK, NB, NR>(key);

    // 1. CIPH_K
    let h = encrypt_block::<NR>(&[0u8; 16], &expanded_key);
    let h = flatten_state(h);

    // 2. J_0
    let j0: [u8; 16] = if nonce.len() * 8 == 96 {
        // J_0 = IV || 0^31 || 1
        let mut out = [0u8; 16];
        out[..12].copy_from_slice(nonce.as_slice());
        out[12..16].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        out
    } else {
        panic!("unsuported at initial version; nonce.len()=12 (96 bits)");
    };

    // 3. C=GCTR()
    let c = gctr(expanded_key, &inc32(j0), pt);

    // 4. u, v
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
    let t = msb_t(TAG_LEN, &gctr(expanded_key, &j0, &s));

    (c, t)
}

/// GCM-Ctr, Section 6.5, Algorithm 3
fn gctr<const NR: usize>(key: [[u8; 4]; 4 * (NR + 1)], icb: &[u8; 16], x: &[u8]) -> Vec<u8> {
    if x.is_empty() {
        return x.to_vec();
    }

    let n = ((x.len() * 8) as f64 / 128_f64).ceil() as usize;

    let mut y: Vec<Vec<u8>> = vec![];
    let mut cb_i = *icb;
    for (i, x_i_raw) in x.chunks(16).enumerate() {
        if i > 0 {
            cb_i = inc32(cb_i);
        }

        let l = x_i_raw.len().min(16);
        let mut x_i = [0u8; 16];
        x_i[..l].copy_from_slice(x_i_raw);

        let ciph_cb_i = flatten_state(encrypt_block::<NR>(&cb_i, &key));

        let (y_i, n_bytes) = if i < n && x_i_raw.len() == 16 {
            (xor_blocks(x_i, ciph_cb_i), 16)
        } else {
            // last chunk, might be smaller than 16 bytes
            let msb_res = msb_t(x_i_raw.len(), ciph_cb_i.as_slice());
            let l = msb_res.len().min(16);
            let mut m = [0u8; 16];
            m[..l].copy_from_slice(&msb_res);
            (xor_blocks(x_i, m), l)
        };
        y.push(y_i[..n_bytes].to_vec());
    }
    y.concat()
}

/// Section 6.4, Algorithm 2
fn ghash(h: [u8; 16], x: &[u8]) -> [u8; 16] {
    assert!(x.len().is_multiple_of(16)); // multiple of 128 bits
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
    let mut r = b;
    // counter = last 32bits
    let counter = u32::from_be_bytes([r[12], r[13], r[14], r[15]]);
    let incremented = counter.wrapping_add(1);
    let bytes = incremented.to_be_bytes();
    r[12..16].copy_from_slice(&bytes);
    r
}

/// returns the t left-most (most-significant in BE) bits of the block
pub fn msb_t(t_bytes: usize, block: &[u8]) -> Vec<u8> {
    let t = t_bytes * 8;

    let mut out = Vec::with_capacity(t.div_ceil(8));
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
        aead::{Aead, KeyInit},
        Aes128Gcm, Aes256Gcm, Nonce,
    };
    use rand::Rng;

    fn hex_to_array<const N: usize>(h: &str) -> [u8; N] {
        let bytes = hex::decode(h).unwrap();
        assert_eq!(bytes.len(), N);
        let mut r: [u8; N] = [0u8; N];
        r.copy_from_slice(&bytes);
        r
    }

    #[test]
    fn test_aes_gcm_encrypt_nist_vector() {
        // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES

        // test vector from line 7
        let key: [u8; 16] = hex_to_array("cf063a34d4a9a76c2c86787d3f96db71");
        let iv: [u8; 12] = hex_to_array("113b9785971864c83b01c787");
        let pt = [];
        let expected_c: &[u8] = &[];
        let expected_tag: [u8; 16] = hex_to_array("72ac8493e3a5228b5d130a69d2510e42");
        let (c, tag) = encrypt::<4, 4, 10>(&key, &iv, &pt);
        assert_eq!(c, expected_c);
        assert_eq!(tag, expected_tag);

        // test vector from line 4417
        let key: [u8; 16] = hex_to_array("e98b72a9881a84ca6b76e0f43e68647a");
        let iv: [u8; 12] = hex_to_array("8b23299fde174053f3d652ba");
        let pt: [u8; 16] = hex_to_array("28286a321293253c3e0aa2704a278032");
        let expected_c: [u8; 16] = hex_to_array("5a3c1cf1985dbb8bed818036fdd5ab42");
        let expected_tag: [u8; 16] = hex_to_array("23c7ab0f952b7091cd324835043b5eb5");
        let (c, tag) = encrypt::<4, 4, 10>(&key, &iv, &pt);
        assert_eq!(c, expected_c);
        assert_eq!(tag, expected_tag);

        // test vector from line 8834
        let key: [u8; 16] = hex_to_array("387218b246c1a8257748b56980e50c94");
        let iv: [u8; 12] = hex_to_array("dd7e014198672be39f95b69d");
        let expected_c: [u8; 13] = hex_to_array("cdba9e73eaf3d38eceb2b04a8d");
        let expected_tag: [u8; 16] = hex_to_array("ecf90f4a47c9c626d6fb2c765d201556");
        let pt: [u8; 13] = hex_to_array("48f5b426baca03064554cc2b30");
        let (c, tag) = encrypt::<4, 4, 10>(&key, &iv, &pt);
        assert_eq!(c, expected_c);
        assert_eq!(tag, expected_tag);

        // test vector from line 13237
        let key: [u8; 16] = hex_to_array("bfd414a6212958a607a0f5d3ab48471d");
        let iv: [u8; 12] = hex_to_array("86d8ea0ab8e40dcc481cd0e2");
        let expected_c: [u8; 32] =
            hex_to_array("62171db33193292d930bf6647347652c1ef33316d7feca99d54f1db4fcf513f8");
        let expected_tag: [u8; 16] = hex_to_array("c28280aa5c6c7a8bd366f28c1cfd1f6e");
        let pt: [u8; 32] =
            hex_to_array("a6b76a066e63392c9443e60272ceaeb9d25c991b0f2e55e2804e168c05ea591a");
        let (c, tag) = encrypt::<4, 4, 10>(&key, &iv, &pt);
        assert_eq!(c, expected_c);
        assert_eq!(tag, expected_tag);
    }

    /// test checking against external aes-gcm lib
    #[test]
    fn test_with_external_lib() -> anyhow::Result<()> {
        test_with_external_lib_op::<4, 4, 10, Aes128Gcm>()?;
        test_with_external_lib_op::<8, 4, 14, Aes256Gcm>()
    }
    fn test_with_external_lib_op<const NK: usize, const NB: usize, const NR: usize, C>(
    ) -> anyhow::Result<()>
    where
        [(); NK * NB]:,
        [(); 4 * (NR + 1)]:,
        C: KeyInit + Aead,
    {
        let key: &[u8; NK * NB] = &[42; NK * NB];
        let nonce: &[u8; 12] = &[111; 12];
        let pt: Vec<Vec<u8>> = vec![
            vec![42u8; 0],
            vec![42u8; 16],
            vec![42u8; 32],
            vec![42u8; 1],
            vec![42u8; 17],
            b"test plaintext".to_vec(),
            b"test plaintext for AES-GCM".to_vec(),
            rand_bytes(131),
            rand_bytes(1027),
            rand_bytes(4242),
        ];

        let nonce_ext = Nonce::from_slice(nonce);
        let cipher = C::new_from_slice(key.as_slice()).unwrap();

        for pt_i in pt.iter() {
            let ciphertext = cipher.encrypt(nonce_ext, pt_i.as_ref()).unwrap();

            let plaintext = cipher.decrypt(nonce_ext, ciphertext.as_ref()).unwrap();
            assert_eq!(plaintext, *pt_i);

            let (c, t) = encrypt::<NK, NB, NR>(key, nonce, pt_i);
            assert_eq!(c.len() + t.len(), ciphertext.len());
            assert_eq!([c, t].concat(), ciphertext);
        }
        Ok(())
    }
    fn rand_bytes(n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        rand::rng().fill_bytes(&mut v);
        v
    }
}
