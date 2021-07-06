/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "oprf.h"
#include <sodium.h>
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
    byte_t *blinded_element, // 32
    const byte_t *input, const int input_len,
    const byte_t *blind // 32
) {
    // using modeBase=0x00
    byte_t P[32];
    ecc_oprf_ristretto255_sha512_HashToGroup(P, input, input_len, 0x00);
    ecc_ristretto255_scalarmult(blinded_element, blind, P);

    // stack memory cleanup
    ecc_memzero(P, sizeof P);
}

void ecc_oprf_ristretto255_sha512_Blind(
    byte_t *blinded_element, // 32
    byte_t *blind, // 32
    const byte_t *input, const int input_len
) {
    ecc_ristretto255_scalar_random(blind);
    ecc_oprf_ristretto255_sha512_BlindWithScalar(
        blinded_element,
        input, input_len,
        blind
    );
}

void ecc_oprf_ristretto255_sha512_Unblind(
    byte_t *unblinded_element, // 32 bytes
    const byte_t *blind,
    const byte_t *evaluated_element
) {
    // Z = GG.DeserializeElement(evaluatedElement)
    // N = (blind^(-1)) * Z
    // unblindedElement = GG.SerializeElement(N)
    byte_t inverted_blind[32];
    ecc_ristretto255_scalar_invert(inverted_blind, blind);
    ecc_ristretto255_scalarmult(unblinded_element, inverted_blind, evaluated_element);

    // stack memory cleanup
    ecc_memzero(inverted_blind, sizeof inverted_blind);
}

void ecc_oprf_ristretto255_sha512_Finalize(
    byte_t *output, // 64 bytes
    const byte_t *input, const int input_len,
    const byte_t *blind,
    const byte_t *evaluated_element,
    const int mode
) {
    // unblindedElement = Unblind(blind, evaluatedElement)
    //
    // finalizeDST = "VOPRF06-Finalize-" || self.contextString
    // hashInput = I2OSP(len(input), 2) || input ||
    //             I2OSP(len(unblindedElement), 2) || unblindedElement ||
    //             I2OSP(len(finalizeDST), 2) || finalizeDST
    // return Hash(hashInput)

    byte_t unblinded_element[32];
    ecc_oprf_ristretto255_sha512_Unblind(unblinded_element, blind, evaluated_element);

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
    crypto_hash_sha512_update(&st, unblinded_element, 32);

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.2
    // contextString = I2OSP(mode, 1) || I2OSP(suite.ID, 2)
    // suite id = 0x0001
    byte_t context_string[3];
    ecc_I2OSP(&context_string[0], mode, 1);
    ecc_I2OSP(&context_string[1], 0x0001, 2);
    // domain separation tag (DST)
    byte_t finalizeDST[20] = "VOPRF06-Finalize-";
    ecc_concat2(finalizeDST, finalizeDST, 17, context_string, 3);

    // I2OSP(len(finalizeDST), 2)
    ecc_I2OSP(tmp, sizeof finalizeDST, 2);
    crypto_hash_sha512_update(&st, tmp, 2);
    // finalizeDST
    crypto_hash_sha512_update(&st, finalizeDST, sizeof finalizeDST);

    // return Hash(hashInput)
    crypto_hash_sha512_final(&st, output);

    // stack memory cleanup
    ecc_memzero(unblinded_element, sizeof unblinded_element);
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_oprf_ristretto255_sha512_Evaluate(
    byte_t *evaluated_element, // 32 bytes
    const byte_t *skS, const byte_t *blinded_element
) {
    // R = GG.DeserializeElement(blindedElement)
    // Z = skS * R
    // evaluatedElement = GG.SerializeElement(Z)
    ecc_ristretto255_scalarmult(evaluated_element, skS, blinded_element);
}
