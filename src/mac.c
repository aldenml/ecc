/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "mac.h"
#include <sodium.h>

void ecc_mac_hmac_sha256_keygen(BYTE *k) {
    crypto_auth_hmacsha256_keygen(k);
}

int ecc_mac_hmac_sha256(BYTE *out, const BYTE *in, int inlen, const BYTE *k) {
    return crypto_auth_hmacsha256(out, in, inlen, k);
}

int ecc_mac_hmac_sha256_verify(const BYTE *h, const BYTE *in, int inlen, const BYTE *k) {
    return crypto_auth_hmacsha256_verify(h, in, inlen, k);
}

void ecc_mac_hmac_sha512_keygen(BYTE *k) {
    crypto_auth_hmacsha512_keygen(k);
}

int ecc_mac_hmac_sha512(BYTE *out, const BYTE *in, int inlen, const BYTE *k) {
    return crypto_auth_hmacsha512(out, in, inlen, k);
}

int ecc_mac_hmac_sha512_verify(const BYTE *h, const BYTE *in, int inlen, const BYTE *k) {
    return crypto_auth_hmacsha512256_verify(h, in, inlen, k);
}

void ecc_mac_hmac_sha512256_keygen(BYTE *k) {
    crypto_auth_hmacsha512256_keygen(k);
}

int ecc_mac_hmac_sha512256(BYTE *out, const BYTE *in, int inlen, const BYTE *k) {
    return crypto_auth_hmacsha512256(out, in, inlen, k);
}

int ecc_mac_hmac_sha512256_verify(const BYTE *h, const BYTE *in, int inlen, const BYTE *k) {
    return crypto_auth_hmacsha512256_verify(h, in, inlen, k);
}
