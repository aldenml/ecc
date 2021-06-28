/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "oprf.h"
#include "util.h"
#include "h2c.h"
#include "ristretto255.h"

void ecc_oprf_ristretto255_sha512_HashToGroup(byte_t *out, const byte_t *in, const int in_len) {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.2
    // contextString = I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
    // modeBase = 0x00
    // suite id = 0x0001
    byte_t contextString[3];
    ecc_I2OSP(&contextString[0], 0x00, 1);
    ecc_I2OSP(&contextString[1], 0x0001, 2);

    // domain separation tag (DST)
    byte_t DST[23] = "VOPRF06-HashToGroup-";
    ecc_concat2(DST, DST, 20, contextString, 3);

    byte_t expand_message[64];
    ecc_h2c_expand_message_xmd_sha512(expand_message, in, in_len, DST, 23, 64);

    ecc_ristretto255_from_hash(out, expand_message);

    // stack memory cleanup
    ecc_memzero(expand_message, sizeof expand_message);
}

void ecc_oprf_ristretto255_sha512_HashToScalar(byte_t *out, const byte_t *msg, const int msg_len) {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.2
    // contextString = I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
    // modeBase = 0x00
    // suite id = 0x0001
    byte_t contextString[3];
    ecc_I2OSP(&contextString[0], 0x00, 1);
    ecc_I2OSP(&contextString[1], 0x0001, 2);

    // domain separation tag (DST)
    byte_t DST[24] = "VOPRF06-HashToScalar-";
    ecc_concat2(DST, DST, 21, contextString, 3);

    byte_t expand_message[64];
    ecc_h2c_expand_message_xmd_sha512(expand_message, msg, msg_len, DST, 24, 64);

    ecc_ristretto255_scalar_reduce(out, expand_message);

    // stack memory cleanup
    ecc_memzero(expand_message, sizeof expand_message);
}

void ecc_oprf_ristretto255_sha512_BlindWithScalar(
    byte_t *out,
    const byte_t *in, int const in_len,
    const byte_t *s
) {
    byte_t P[32];
    ecc_oprf_ristretto255_sha512_HashToGroup(P, in, in_len);
    ecc_ristretto255_scalarmult(out, s, P);

    // stack memory cleanup
    ecc_memzero(P, sizeof P);
}
