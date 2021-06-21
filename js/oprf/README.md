# OPRF

Oblivious pseudo-random function using ristretto255.

This is an implementation of [draft-irtf-cfrg-voprf-06](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06)
using [libsodium](https://doc.libsodium.org).

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
npm run app
```
and open the browser at the url http://localhost:8000.

Create an issue with any question or clarification you need at https://github.com/aldenml/ecc/issues.
