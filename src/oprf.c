/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "oprf.h"
#include <assert.h>
#include <sodium.h>
#include "util.h"
#include "hash.h"
#include "h2c.h"
#include "ristretto255.h"

static_assert(ecc_oprf_ristretto255_sha512_ELEMENTSIZE_CONST == ecc_ristretto255_SIZE_CONST, "");
static_assert(ecc_oprf_ristretto255_sha512_SCALARSIZE_CONST == ecc_ristretto255_SCALARSIZE_CONST, "");
static_assert(ecc_oprf_ristretto255_sha512_Nh_CONST == ecc_hash_sha512_SIZE, "");

void ecc_oprf_ristretto255_sha512_Evaluate(
    byte_t *evaluatedElement, // 32 bytes
    const byte_t *skS,
    const byte_t *blindedElement
) {
    // R = GG.DeserializeElement(blindedElement)
    // Z = skS * R
    // evaluatedElement = GG.SerializeElement(Z)
    ecc_ristretto255_scalarmult(evaluatedElement, skS, blindedElement);
}

void ecc_oprf_ristretto255_sha512_BlindWithScalar(
    byte_t *blindedElement, // 32
    const byte_t *input, const int input_len,
    const byte_t *blind // 32
) {
    // using modeBase=0x00
    byte_t P[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_HashToGroup(P, input, input_len, 0x00);
    ecc_ristretto255_scalarmult(blindedElement, blind, P);

    // stack memory cleanup
    ecc_memzero(P, sizeof P);
}

void ecc_oprf_ristretto255_sha512_Blind(
    byte_t *blindedElement, // 32
    byte_t *blind, // 32
    const byte_t *input, const int input_len
) {
    ecc_ristretto255_scalar_random(blind);
    ecc_oprf_ristretto255_sha512_BlindWithScalar(
        blindedElement,
        input, input_len,
        blind
    );
}

void ecc_oprf_ristretto255_sha512_Unblind(
    byte_t *unblindedElement, // 32 bytes
    const byte_t *blind,
    const byte_t *evaluatedElement
) {
    // Z = GG.DeserializeElement(evaluatedElement)
    // N = (blind^(-1)) * Z
    // unblindedElement = GG.SerializeElement(N)
    byte_t blindInverted[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_ristretto255_scalar_invert(blindInverted, blind); // blind^(-1)
    ecc_ristretto255_scalarmult(unblindedElement, blindInverted, evaluatedElement);

    // stack memory cleanup
    ecc_memzero(blindInverted, sizeof blindInverted);
}

void ecc_oprf_ristretto255_sha512_Finalize(
    byte_t *output, // 64 bytes
    const byte_t *input, const int input_len,
    const byte_t *blind,
    const byte_t *evaluatedElement,
    const int mode
) {
    // unblindedElement = Unblind(blind, evaluatedElement)
    //
    // finalizeDST = "Finalize-" || self.contextString
    // hashInput = I2OSP(len(input), 2) || input ||
    //             I2OSP(len(unblindedElement), 2) || unblindedElement ||
    //             I2OSP(len(finalizeDST), 2) || finalizeDST
    // return Hash(hashInput)

    byte_t unblindedElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_Unblind(unblindedElement, blind, evaluatedElement);

    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);

    // I2OSP(len(input), 2)
    byte_t tmp[2];
    ecc_I2OSP(tmp, input_len, 2);
    crypto_hash_sha512_update(&st, tmp, 2);
    // input
    crypto_hash_sha512_update(&st, input, input_len);
    // I2OSP(len(unblindedElement), 2)
    ecc_I2OSP(tmp, 32, 2);
    crypto_hash_sha512_update(&st, tmp, 2);
    // unblindedElement
    crypto_hash_sha512_update(&st, unblindedElement, 32);

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-3.2
    // contextString = I2OSP(mode, 1) || I2OSP(suite.ID, 2)
    // suite id = 0x0001
    byte_t contextString[3];
    ecc_I2OSP(&contextString[0], mode, 1);
    ecc_I2OSP(&contextString[1], 0x0001, 2);
    // domain separation tag (DST)
    byte_t finalizeDST[20] = "Finalize-VOPRF07-";
    ecc_concat2(finalizeDST, finalizeDST, 17, contextString, 3);

    // I2OSP(len(finalizeDST), 2)
    ecc_I2OSP(tmp, sizeof finalizeDST, 2);
    crypto_hash_sha512_update(&st, tmp, 2);
    // finalizeDST
    crypto_hash_sha512_update(&st, finalizeDST, sizeof finalizeDST);

    // return Hash(hashInput)
    crypto_hash_sha512_final(&st, output);

    // stack memory cleanup
    ecc_memzero(unblindedElement, sizeof unblindedElement);
    ecc_memzero((byte_t *) &st, sizeof st);
}

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
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-3.2
    // contextString = I2OSP(mode, 1) || I2OSP(suite.ID, 2)
    // suite id = 0x0001
    byte_t contextString[3];
    ecc_I2OSP(&contextString[0], mode, 1);
    ecc_I2OSP(&contextString[1], 0x0001, 2);

    // domain separation tag (DST)
    byte_t DST[23] = "HashToGroup-VOPRF07-";
    ecc_concat2(DST, DST, 20, contextString, 3);

    ecc_oprf_ristretto255_sha512_HashToGroupWithDST(out, input, input_len, DST, sizeof DST);
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
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-3.2
    // contextString = I2OSP(mode, 1) || I2OSP(suite.ID, 2)
    // suite id = 0x0001
    byte_t contextString[3];
    ecc_I2OSP(&contextString[0], mode, 1);
    ecc_I2OSP(&contextString[1], 0x0001, 2);

    // domain separation tag (DST)
    byte_t DST[24] = "HashToScalar-VOPRF07-";
    ecc_concat2(DST, DST, 21, contextString, 3);

    ecc_oprf_ristretto255_sha512_HashToScalarWithDST(out, input, input_len, DST, sizeof DST);
}
