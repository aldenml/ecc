# OPAQUE

[![npm](https://img.shields.io/npm/v/@aldenml/opaque)](https://www.npmjs.com/package/@aldenml/opaque)

The OPAQUE Asymmetric PAKE Protocol.

This is an implementation of [draft-irtf-cfrg-opaque-05](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.4)
using [libsodium](https://doc.libsodium.org) with a focus on reduced size.

OPAQUE consists of two stages: registration and authenticated key
exchange. In the first stage, a client registers its password with
the server and stores its encrypted credentials on the server, but
the server never knows what the password it.

The registration flow is shown below (from the irtf draft):
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

The authenticated key exchange flow is shown below (from the irtf draft):
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

## Installation

For node.js, use:
```
npm install @aldenml/opaque
```
For the browser, use the included `dist/opaque.min.js` or `dist/opaque.dev.js`.

## Usage

See unit test at https://github.com/aldenml/ecc/blob/master/js/opaque/opaque.test.js

Create an issue with any question or clarification you need at https://github.com/aldenml/ecc/issues.
