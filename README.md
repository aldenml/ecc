# ecc

[![c](https://github.com/aldenml/ecc/actions/workflows/c.yml/badge.svg?branch=master)](https://github.com/aldenml/ecc/actions/workflows/c.yml)
[![js](https://github.com/aldenml/ecc/actions/workflows/js.yml/badge.svg?branch=master)](https://github.com/aldenml/ecc/actions/workflows/js.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/5fac0b504c25497ca621938007bc1cf6)](https://app.codacy.com/gh/aldenml/ecc/dashboard)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/5fac0b504c25497ca621938007bc1cf6)](https://www.codacy.com/gh/aldenml/ecc/dashboard)

Library to work with elliptic-curve cryptography based on [libsodium](https://github.com/jedisct1/libsodium)
and [blst](https://github.com/supranational/blst).

| Bindings |   |   |
|--------------------|---|---|
| Java               | [jvm](jvm) | [![maven](https://img.shields.io/maven-central/v/org.ssohub/ecc.svg?label=maven)](https://search.maven.org/search?q=g:%22org.ssohub%22%20AND%20a:%22ecc%22) |
| Javascript         | [js/ecc](js/ecc) | [![npm](https://img.shields.io/npm/v/@aldenml/ecc)](https://www.npmjs.com/package/@aldenml/ecc) |

### OPRF Oblivious pseudo-random functions using ristretto255

This is an implementation of [draft-irtf-cfrg-voprf-08](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08)
ciphersuite **OPRF(ristretto255, SHA-512)** using `libsodium`.

There are two variants in this protocol: a *base* mode and *verifiable* mode. In the
base mode, a client and server interact to compute `output = F(skS, input, info)`,
where `input` is the client's private input, `skS` is the server's private key, `info`
is the public input, and `output` is the computation output. The client learns `output`
and the server learns nothing. In the verifiable mode, the client also receives proof
that the server used `skS` in computing the function.

The flow is shown below (from the irtf draft):
```
  Client(input, info)                               Server(skS, info)
  ----------------------------------------------------------------------
  blind, blindedElement = Blind(input)

                             blindedElement
                               ---------->

                 evaluatedElement = Evaluate(skS, blindedElement, info)

                             evaluatedElement
                               <----------

  output = Finalize(input, blind, evaluatedElement, blindedElement, info)
```

In the verifiable mode of the protocol, the server additionally
computes a proof in Evaluate. The client verifies this proof using
the server's expected public key before completing the protocol and
producing the protocol output.

### BLS12-381 Pairing

In the context of pairing friendly elliptic curves, a pairing is a map `e: G1xG2 -> GT` such
that for each a, b, P and Q
```
e(a * P, b * Q) = e(P, Q)^(a * b)
```
You can use this to obtain such pairings:
```c
// c code, for a very similar java code, look at the unit tests
byte_t a[ecc_bls12_381_SCALARSIZE];
byte_t b[ecc_bls12_381_SCALARSIZE];
ecc_bls12_381_scalar_random(a);
ecc_bls12_381_scalar_random(b);

byte_t aP[ecc_bls12_381_G1SIZE];
byte_t bQ[ecc_bls12_381_G2SIZE];

ecc_bls12_381_g1_scalarmult_base(aP, a); // a * P
ecc_bls12_381_g2_scalarmult_base(bQ, b); // b * Q

byte_t pairing[ecc_bls12_381_FP12SIZE];
ecc_bls12_381_pairing(pairing, aP, bQ); // e(a * P, b * Q)
```

Read more at:<br/>
https://hackmd.io/@benjaminion/bls12-381 <br/>
https://en.wikipedia.org/wiki/Pairing-based_cryptography

### Proxy Re-Encryption (PRE)

With a pairing-friendly elliptic curve and a well-defined pairing operation,
you can implement a proxy re-encryption scheme. This library provides an
implementation using BLS12-381.

Example of how to use it:
```java
// This is a java code, but for a similar plain C code, look at unit tests

// client A setup public/private keys and signing keys
KeyPair keysA = pre_schema1_KeyGen();
SigningKeyPair signingA = pre_schema1_SigningKeyGen();

// client B setup public/private keys (signing keys are not used here)
KeyPair keysB = pre_schema1_KeyGen();

// proxy server setup signing keys
SigningKeyPair signingProxy = pre_schema1_SigningKeyGen();

// client A select a plaintext message, this message
// in itself is random, but can be used as a seed
// for symmetric encryption keys
byte[] message = pre_schema1_MessageGen();

// client A encrypts the message to itself, making it
// possible to send this ciphertext to the proxy.
byte[] ciphertextLevel1 = pre_schema1_Encrypt(message, keysA.pk, signingA);

// client A sends ciphertextLevel1 to the proxy server and
// eventually client A allows client B to see the encrypted
// message, in this case the proxy needs to re-encrypt
// ciphertextLevel1 (without ever knowing the plaintext).
// In order to do that, the client A needs to create a re-encryption
// key that the proxy can use to perform such operation.

// client A creates a re-encryption key that the proxy can use
// to re-encrypt the ciphertext (ciphertextLevel1) in order for
// client B be able to recover the original message
byte[] reEncKey = pre_schema1_ReKeyGen(keysA.sk, keysB.pk, signingA);

// the proxy re-encrypt the ciphertext ciphertextLevel1 with such
// a key that allows client B to recover the original message
byte[] ciphertextLevel2 = pre_schema1_ReEncrypt(
    ciphertextLevel1,
    reEncKey,
    signingA.spk, keysB.pk,
    signingProxy
);

// client B is able to decrypt ciphertextLevel2 and the result
// is the original plaintext message
byte[] messageDecrypted = pre_schema1_DecryptLevel2(
    ciphertextLevel2,
    keysB.sk, signingProxy.spk
);

// now both client A and client B share the same plaintext message
// messageDecrypted is equal to message
```

Read more at:<br/>
"A Fully Secure Unidirectional and Multi-user Proxy Re-encryption Scheme" by H. Wang and Z. Cao, 2009 <br/>
"A Multi-User CCA-Secure Proxy Re-Encryption Scheme" by Y. Cai and X. Liu, 2014 <br/>
"Cryptographically Enforced Orthogonal Access Control at Scale" by B. Wall and P. Walsh, 2018 <br/>
https://en.wikipedia.org/wiki/Proxy_re-encryption
