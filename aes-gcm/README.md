# plonky2-aes

- [aes-gcm](/aes-gcm): Plonky2 circuits for AES & AES-GCM encryption system as described at
	- AES: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
	- AES-GCM (Galois Counter Mode): https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf


> Warning: this code is unaudited.

Full example of usage at [examples](https://github.com/0xPARC/plonky2-aes/blob/main/examples) directory.
```rust
// circuit declaration
let config = CircuitConfig::standard_recursion_zk_config();
let mut builder = CircuitBuilder::<F, D>::new(config);
let aes_targets = AesGcm128Target::<L>::new_virtual(&mut builder);
aes_targets.build_circuit(&mut builder);
let data = builder.build::<PoseidonGoldilocksConfig>();

// set values to circuit
let mut pw = PartialWitness::<F>::new();
aes_targets.set_targets(&mut pw, key, nonce, pt, ct, tag)?;

let proof = data.prove(pw)?;
data.verify(proof)
```
