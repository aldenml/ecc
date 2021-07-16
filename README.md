# ecc

[![c](https://github.com/aldenml/ecc/actions/workflows/c.yml/badge.svg?branch=master)](https://github.com/aldenml/ecc/actions/workflows/c.yml)
[![js](https://github.com/aldenml/ecc/actions/workflows/js.yml/badge.svg?branch=master)](https://github.com/aldenml/ecc/actions/workflows/js.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/5fac0b504c25497ca621938007bc1cf6)](https://app.codacy.com/gh/aldenml/ecc/dashboard)

Set of libraries to work with elliptic-curve cryptography based on [libsodium](https://github.com/jedisct1/libsodium)
and [blst](https://github.com/supranational/blst).

| Library |   |   |
|---|---|---|
| Java binding | [jvm](jvm) | [![maven](https://img.shields.io/maven-central/v/org.ssohub/ecc.svg?label=maven)](https://search.maven.org/search?q=g:%22org.ssohub%22%20AND%20a:%22ecc%22) |
| Javascript binding | [js/ecc](js/ecc) | [![npm](https://img.shields.io/npm/v/@aldenml/ecc)](https://www.npmjs.com/package/@aldenml/ecc) |
| OPAQUE Asymmetric PAKE Protocol | [js/opaque](js/opaque) | [![npm](https://img.shields.io/npm/v/@aldenml/opaque)](https://www.npmjs.com/package/@aldenml/opaque) |
| OPRF Oblivious pseudo-random | [js/oprf](js/oprf) | [![npm](https://img.shields.io/npm/v/@aldenml/oprf)](https://www.npmjs.com/package/@aldenml/oprf) |

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
