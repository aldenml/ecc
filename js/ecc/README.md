# ecc

[![npm](https://img.shields.io/npm/v/@aldenml/ecc)](https://www.npmjs.com/package/@aldenml/ecc)

This is the javascript version of the [ecc](https://github.com/aldenml/ecc) library.

It is a WebAssembly compilation with a thin layer on
top to expose the cryptographic primitives. It also provides
the same protocol implementations as the more specialized
(and a lot smaller) libraries.

| Library |   |
|---|---|
| OPAQUE Asymmetric PAKE Protocol | [![npm](https://img.shields.io/npm/v/@aldenml/opaque)](https://www.npmjs.com/package/@aldenml/opaque) |
| OPRF Oblivious pseudo-random | [![npm](https://img.shields.io/npm/v/@aldenml/oprf)](https://www.npmjs.com/package/@aldenml/oprf) |

### BLS12-381 Pairing

In the context of pairing friendly elliptic curves, a pairing is a map e: G1xG2 -> GT such
that for each a, b, P and Q
```
e(a * P, b * Q) = e(P, Q)^(a * b)
```
You can use this to obtain such pairings:
```js
const libecc = await libecc_module();

const a = new Uint8Array(32);
const b = new Uint8Array(32);
libecc.ecc_bls12_381_scalar_random(a);
libecc.ecc_bls12_381_scalar_random(b);

const aP = new Uint8Array(96);
const bQ = new Uint8Array(192);

libecc.ecc_bls12_381_g1_scalarmult_base(aP, a); // a * P
libecc.ecc_bls12_381_g2_scalarmult_base(bQ, b); // b * Q

const pairing = new Uint8Array(576);
libecc.ecc_bls12_381_pairing(pairing, aP, bQ); // e(a * P, b * Q)
```

Read more at:<br/>
https://hackmd.io/@benjaminion/bls12-381 <br/>
https://en.wikipedia.org/wiki/Pairing-based_cryptography
