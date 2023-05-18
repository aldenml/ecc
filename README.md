# elliptic-curve cryptography

[![macOS](https://github.com/aldenml/ecc/actions/workflows/macos.yml/badge.svg?branch=master)](https://github.com/aldenml/ecc/actions/workflows/macos.yml)
[![Linux](https://github.com/aldenml/ecc/actions/workflows/linux.yml/badge.svg?branch=master)](https://github.com/aldenml/ecc/actions/workflows/linux.yml)
[![Windows](https://github.com/aldenml/ecc/actions/workflows/windows.yml/badge.svg?branch=master)](https://github.com/aldenml/ecc/actions/workflows/windows.yml)
[![javascript](https://github.com/aldenml/ecc/actions/workflows/javascript.yml/badge.svg?branch=master)](https://github.com/aldenml/ecc/actions/workflows/javascript.yml)
[![iOS](https://github.com/aldenml/ecc/actions/workflows/ios.yml/badge.svg?branch=master)](https://github.com/aldenml/ecc/actions/workflows/ios.yml)
[![Android](https://github.com/aldenml/ecc/actions/workflows/android.yml/badge.svg?branch=master)](https://github.com/aldenml/ecc/actions/workflows/android.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/b805b9122f2e46d097eab8cefb0df48e)](https://app.codacy.com/gh/aldenml/ecc/dashboard)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/b805b9122f2e46d097eab8cefb0df48e)](https://www.codacy.com/gh/aldenml/ecc/dashboard)
[![javadoc](https://javadoc.io/badge2/org.ssohub/ecc/javadoc.svg)](https://javadoc.io/doc/org.ssohub/ecc)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=aldenml_ecc&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=aldenml_ecc)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=aldenml_ecc&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=aldenml_ecc)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=aldenml_ecc&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=aldenml_ecc)
[![Sonatype Lift](https://lift.sonatype.com/api/badge/github.com/aldenml/ecc)](https://github.com/aldenml/ecc)

Library to work with elliptic-curve cryptography based on [libsodium](https://github.com/jedisct1/libsodium)
and [blst](https://github.com/supranational/blst).

| Bindings   |                               |                                                                                                                                      |
|------------|-------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| Java       | [jvm/ecc](bindings/jvm)       | [![maven](https://img.shields.io/maven-central/v/org.ssohub/ecc.svg?label=maven)](https://central.sonatype.com/namespace/org.ssohub) |
| Javascript | [js/ecc](bindings/js)         | [![npm](https://img.shields.io/npm/v/@aldenml/ecc)](https://www.npmjs.com/package/@aldenml/ecc)                                      |
| Python     | [python/ecc](bindings/python) | [![PyPI version](https://badge.fury.io/py/libecc.svg)](https://badge.fury.io/py/libecc)                                              |

### Features

- [OPRF](#oprf-oblivious-pseudo-random-functions)
- [OPAQUE](#opaque-the-opaque-asymmetric-pake-protocol)
- [Two-Round Threshold Schnorr Signatures with FROST](#two-round-threshold-schnorr-signatures-with-frost)
- [Ethereum BLS Signature](#ethereum-bls-signature)
- [BLS12-381 Pairing](#bls12-381-pairing)
- [Proxy Re-Encryption (PRE)](#proxy-re-encryption-pre)
- [Cryptographic primitives and utilities](#cryptographic-primitives-and-utilities)

### OPRF Oblivious pseudo-random functions

This is an implementation of [draft-irtf-cfrg-voprf-21](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21)
ciphersuite **OPRF(ristretto255, SHA-512)** using `libsodium`.

An Oblivious Pseudorandom Function (OPRF) is a two-party protocol between client
and server for computing the output of a Pseudorandom Function (PRF). The server
provides the PRF secret key, and the client provides the PRF input. At the end
of the protocol, the client learns the PRF output without learning anything
about the PRF secret key, and the server learns neither the PRF input nor
output.

There are two variations of the basic protocol:

- VOPRF: is OPRF with the notion of verifiability. Clients can verify that the
server used a specific private key during the execution of the protocol.
- POPRF: is a partially-oblivious VOPRF that allows clients and servers to
provide public input to the PRF computation.

The OPRF flow is shown below (from the IRTF draft):
```
    Client(input)                                        Server(skS)
  -------------------------------------------------------------------
  blind, blindedElement = Blind(input)

                             blindedElement
                               ---------->

                evaluatedElement = BlindEvaluate(skS, blindedElement)

                             evaluatedElement
                               <----------

  output = Finalize(input, blind, evaluatedElement)
```

For the advanced modes VOPRF and POPRF refer to the published draft.

### OPAQUE The OPAQUE Asymmetric PAKE Protocol

This is an implementation of [draft-irtf-cfrg-opaque-10](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-10)
using `libsodium`.

OPAQUE consists of two stages: registration and authenticated key
exchange. In the first stage, a client registers its password with
the server and stores its encrypted credentials in the server, but
the server never knows what the password is.

The registration flow is shown below (from the IRTF draft):

```
       creds                                   parameters
         |                                         |
         v                                         v
       Client                                    Server
       ------------------------------------------------
                   registration request
                ------------------------->
                   registration response
                <-------------------------
                         record
                ------------------------->
      ------------------------------------------------
         |                                         |
         v                                         v
     export_key                                 record
```

In the second stage, the client outputs two values, an "export_key" (matching
that from registration) and a "session_key". The server outputs a single value
"session_key" that matches that of the client.

The authenticated key exchange flow is shown below (from the IRTF draft):
```
       creds                             (parameters, record)
         |                                         |
         v                                         v
       Client                                    Server
       ------------------------------------------------
                      AKE message 1
                ------------------------->
                      AKE message 2
                <-------------------------
                      AKE message 3
                ------------------------->
      ------------------------------------------------
         |                                         |
         v                                         v
   (export_key, session_key)                  session_key
```

The public API for implementing the protocol is:

- Client
```
opaque_ristretto255_sha512_CreateRegistrationRequest
opaque_ristretto255_sha512_FinalizeRequest
opaque_ristretto255_sha512_3DH_ClientInit
opaque_ristretto255_sha512_3DH_ClientFinish
```

- Server
```
opaque_ristretto255_sha512_CreateRegistrationResponse
opaque_ristretto255_sha512_3DH_ServerInit
opaque_ristretto255_sha512_3DH_ServerFinish
```

### Two-Round Threshold Schnorr Signatures with FROST

This is an implementation of [draft-irtf-cfrg-frost-13](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-frost-13)
using `libsodium`.

The draft presents a two-round signing variant of FROST, a Flexible Round-Optimized Schnorr Threshold signature
scheme. FROST signatures can be issued after a threshold number of entities cooperate to issue a signature,
allowing for improved distribution of trust and redundancy with respect to a secret key.

Unlike signatures in a single-party setting, threshold signatures require cooperation among a threshold number
of signers each holding a share of a common private key. The security of threshold schemes in general assume
that an adversary can corrupt strictly fewer than a threshold number of participants.

This implementation follows the trusted dealer key generation documented in the Appendix B of the draft
using Shamir and Verifiable Secret Sharing.

### Ethereum BLS Signature

Ethereum uses BLS signatures as specified in the IETF
draft [draft-irtf-cfrg-bls-signature-04](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04)
ciphersuite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.

This library provides the following API:

```
ecc_sign_eth_bls_KeyGen
ecc_sign_eth_bls_SkToPk
ecc_sign_eth_bls_KeyValidate
ecc_sign_eth_bls_Sign
ecc_sign_eth_bls_Verify
ecc_sign_eth_bls_Aggregate
ecc_sign_eth_bls_FastAggregateVerify
ecc_sign_eth_bls_AggregateVerify
```

BLS is a digital signature scheme with aggregation properties that can be applied to signatures
and public keys. For this reason, in the context of blockchains, BLS signatures are used for
authenticating transactions, votes during consensus protocols, and to reduce bandwidth
and storage requirements.

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
you can implement a proxy re-encryption scheme.

This library provides an implementation using BLS12-381.

Example of how to use it:
```java
// This is a java code sample, but for a similar plain C code sample look at the unit tests

// client A setup public/private keys and signing keys
KeyPair keysA = pre_schema1_KeyGen();
SigningKeyPair signingA = pre_schema1_SigningKeyGen();

// client B setup public/private keys (signing keys are not used here)
KeyPair keysB = pre_schema1_KeyGen();

// proxy server setup signing keys
SigningKeyPair signingProxy = pre_schema1_SigningKeyGen();

// client A selects a plaintext message, this message
// in itself is random but can be used as a seed
// for symmetric encryption keys
byte[] message = pre_schema1_MessageGen();

// client A encrypts the message to itself, making it
// possible to send this ciphertext to the proxy.
byte[] ciphertextLevel1 = pre_schema1_Encrypt(message, keysA.pk, signingA);

// client A sends ciphertextLevel1 to the proxy server and
// eventually client A allows client B to see the encrypted
// message, in this case the proxy needs to re-encrypt
// ciphertextLevel1 (without ever knowing the plaintext).
// In order to do that, client A needs to create a re-encryption
// key that the proxy can use to perform such operation.

// client A creates a re-encryption key the proxy can use
// to re-encrypt the ciphertext (ciphertextLevel1) in order for
// client B be able to recover the original message
byte[] reEncKey = pre_schema1_ReKeyGen(keysA.sk, keysB.pk, signingA);

// the proxy re-encrypts the ciphertext ciphertextLevel1 with such
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

### Cryptographic primitives and utilities

```
ecc_hash_sha256
ecc_hash_sha512

ecc_kdf_scrypt
ecc_kdf_argon2id

ecc_aead_chacha20poly1305_encrypt
ecc_aead_chacha20poly1305_decrypt
```

### Bindings and building

To generate the static files for bindings:
```shell
python3 bindings/gen_code.py
```
To build c shared and static libraries and jvm bindings:
```shell
./build-c.sh
```
To build javascript bindings:
```shell
./build-js.sh
```
