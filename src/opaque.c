/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "opaque.h"
#include "util.h"
#include "h2c.h"
#include "ristretto255.h"

void ecc_opaque_ristretto255_sha512_HashToScalar(byte_t *out, const byte_t *msg, const int msg_len) {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.2
    // contextString = I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
    // modeBase = 0x00
    // suite id = 0x0001
    byte_t contextString[3];
    ecc_I2OSP(&contextString[0], 0x00, 1);
    ecc_I2OSP(&contextString[1], 0x0001, 2);

    // domain separation tag (DST)
    byte_t DST[19] = "OPAQUE-HashToScalar";
    ecc_concat2(DST, DST, 21, contextString, 3);

    byte_t expand_message[64];
    ecc_h2c_expand_message_xmd_sha512(expand_message, msg, msg_len, DST, 24, 64);

    ecc_ristretto255_scalar_reduce(out, expand_message);

    // stack memory cleanup
    ecc_memzero(expand_message, sizeof expand_message);
}

void ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
    byte_t *private_key, byte_t *public_key,
    const byte_t *seed, const int seed_len
) {
    // Steps:
    // 1. private_key = HashToScalar(seed, dst="OPAQUE-HashToScalar")
    // 2. public_key = ScalarBaseMult(private_key)
    // 3. Output (private_key, public_key)

    ecc_opaque_ristretto255_sha512_HashToScalar(private_key, seed, seed_len);
    ecc_ristretto255_scalarmult_base(public_key, private_key);
}
