# plonky2-crypto-gadgets

> Warning: this code is unaudited.

- [aes-gcm](/aes-gcm): Plonky2 circuits for AES & AES-GCM encryption system as described at
	- AES: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
	- AES-GCM (Galois Counter Mode): https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- [ecgfp5](/ecgfp5): Plonky2 circuits for ElGamal and (a finite field analogue of) hashed ElGamal cryptosystems as described at
    - ElGamal: §1.4.3 of Menezes - *Elliptic Curve Public Key Cryptosystems* (1993)
    - hashed ElGamal: Abdalla, Bellare & Rogaway - *The oracle Diffie-Hellman assumptions and an analysis of DHIES* (2001)
- [feistel](/feistel): a Plonky2 library for a finite field analogue of the Feistel cipher as described [here](https://en.wikipedia.org/wiki/Feistel_cipher).
