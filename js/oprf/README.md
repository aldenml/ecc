# OPRF

[![npmjs](https://img.shields.io/npm/v/@aldenml/oprf?label=npmjs)](https://www.npmjs.com/package/@aldenml/oprf)

Oblivious pseudo-random function using ristretto255.

This is an implementation of [draft-irtf-cfrg-voprf-06](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06)
using [libsodium](https://doc.libsodium.org).

It contains the following primitives (plus all the supporting functions):

- `oprf_ristretto255_sha512_Blind` - client sends a masked secret input to the server.
- `oprf_ristretto255_sha512_Evaluate` - server takes the masked secret and evaluates an "element" and sends it to the client.
- `oprf_ristretto255_sha512_Finalize` - client takes the evaluated "element" and calculates the random output.

## Installation

For node.js, use:
```
npm install @aldenml/oprf
```
For the browser, use the included `dist/oprf.min.js` or `dist/oprf.dev.js`.

## Usage

Navigate to https://github.com/aldenml/ecc/tree/master/examples/oprf to see
how to use this in both the client and the server. Run:
```
npm install
npm run app
```
and open the browser at the url http://localhost:8000.

Create an issue with any question or clarification you need at https://github.com/aldenml/ecc/issues.
