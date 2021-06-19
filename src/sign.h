/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_SIGN_H
#define ECC_SIGN_H

#include "export.h"

ECC_EXPORT
int ecc_sign_ed25519(BYTE *sm, int *smlen_p, const BYTE *m, int mlen, const BYTE *sk);

ECC_EXPORT
int ecc_sign_ed25519_open(BYTE *m, int *mlen_p, const BYTE *sm, int smlen, const BYTE *pk);

ECC_EXPORT
int ecc_sign_ed25519_detached(BYTE *sig, int *siglen_p, const BYTE *m, int mlen, const BYTE *sk);

ECC_EXPORT
int ecc_sign_ed25519_verify_detached(const BYTE *sig, const BYTE *m, int mlen, const BYTE *pk);

ECC_EXPORT
int ecc_sign_ed25519_keypair(BYTE *pk, BYTE *sk);

ECC_EXPORT
int ecc_sign_ed25519_seed_keypair(BYTE *pk, BYTE *sk, const BYTE *seed);

ECC_EXPORT
int ecc_sign_ed25519_pk_to_curve25519(BYTE *curve25519_pk, const BYTE *ed25519_pk);

ECC_EXPORT
int ecc_sign_ed25519_sk_to_curve25519(BYTE *curve25519_sk, const BYTE *ed25519_sk);

ECC_EXPORT
int ecc_sign_ed25519_sk_to_seed(BYTE *seed, const BYTE *sk);

ECC_EXPORT
int ecc_sign_ed25519_sk_to_pk(BYTE *pk, const BYTE *sk);

#endif // ECC_SIGN_H
