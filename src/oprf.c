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

void ecc_oprf_ristretto255_sha512_HashToGroupWithDST(
    byte_t *out,
    const byte_t *input, int input_len,
    const byte_t *dst, int dst_len
) {
    byte_t expand_message[64];
    ecc_h2c_expand_message_xmd_sha512(expand_message, input, input_len, dst, dst_len, 64);

    ecc_ristretto255_from_hash(out, expand_message);

    // stack memory cleanup
    ecc_memzero(expand_message, sizeof expand_message);
}

void ecc_oprf_ristretto255_sha512_HashToGroup(
    byte_t *out,
    const byte_t *input, const int input_len,
    const int mode
) {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.2
    // contextString = I2OSP(mode, 1) || I2OSP(suite.ID, 2)
    // suite id = 0x0001
    byte_t contextString[3];
    ecc_I2OSP(&contextString[0], mode, 1);
    ecc_I2OSP(&contextString[1], 0x0001, 2);

    // domain separation tag (DST)
    byte_t DST[23] = "VOPRF06-HashToGroup-";
    ecc_concat2(DST, DST, 20, contextString, 3);

    ecc_oprf_ristretto255_sha512_HashToGroupWithDST(out, input, input_len, DST, 23);
}

void ecc_oprf_ristretto255_sha512_HashToScalarWithDST(
    byte_t *out,
    const byte_t *input, int input_len,
    const byte_t *dst, int dst_len
) {
    byte_t expand_message[64];
    ecc_h2c_expand_message_xmd_sha512(expand_message, input, input_len, dst, dst_len, 64);

    ecc_ristretto255_scalar_reduce(out, expand_message);

    // stack memory cleanup
    ecc_memzero(expand_message, sizeof expand_message);
}

void ecc_oprf_ristretto255_sha512_HashToScalar(
    byte_t *out,
    const byte_t *input, const int input_len,
    const int mode
) {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.2
    // contextString = I2OSP(mode, 1) || I2OSP(suite.ID, 2)
    // suite id = 0x0001
    byte_t contextString[3];
    ecc_I2OSP(&contextString[0], mode, 1);
    ecc_I2OSP(&contextString[1], 0x0001, 2);

    // domain separation tag (DST)
    byte_t DST[24] = "VOPRF06-HashToScalar-";
    ecc_concat2(DST, DST, 21, contextString, 3);

    ecc_oprf_ristretto255_sha512_HashToScalarWithDST(out, input, input_len, DST, 24);
}

void ecc_oprf_ristretto255_sha512_BlindWithScalar(
    byte_t *out,
    const byte_t *input, const int input_len,
    const byte_t *blind
) {
    byte_t P[32];
    ecc_oprf_ristretto255_sha512_HashToGroup(P, input, input_len, 0x00);
    ecc_ristretto255_scalarmult(out, blind, P);

    // stack memory cleanup
    ecc_memzero(P, sizeof P);
}

void ecc_oprf_ristretto255_sha512_Blind(
    byte_t *out, byte_t *blind,
    const byte_t *input, int input_len
) {
    ecc_ristretto255_scalar_random(blind);
    ecc_oprf_ristretto255_sha512_BlindWithScalar(out, input, input_len, blind);
}
