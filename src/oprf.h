/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_OPRF_H
#define ECC_OPRF_H

#include "export.h"

/**
 * Same as calling `ecc_oprf_ristretto255_sha512_HashToGroup` with an
 * specified DST string.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-2.1
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-5.1
 *
 * @param out element of the group
 * @param input input string to map
 * @param input_len length of `input`
 * @param dst domain separation tag (DST)
 * @param dst_len length of `dst`
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_HashToGroupWithDST(
    byte_t *out,
    const byte_t *input, int input_len,
    const byte_t *dst, int dst_len
);

/**
 * Deterministically maps an array of bytes "x" to an element of "GG" in
 * the ristretto255 curve.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-2.1
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-5.1
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-2.2.5
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3
 *
 * @param out element of the group
 * @param input input string to map
 * @param input_len length of `input`
 * @param mode mode to build the internal DST string (modeBase=0x00, modeVerifiable=0x01)
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_HashToGroup(
    byte_t *out,
    const byte_t *input, int input_len,
    int mode
);

ECC_EXPORT
void ecc_oprf_ristretto255_sha512_HashToScalarWithDST(
    byte_t *out,
    const byte_t *input, int input_len,
    const byte_t *dst, int dst_len
);

ECC_EXPORT
void ecc_oprf_ristretto255_sha512_HashToScalar(
    byte_t *out,
    const byte_t *input, int input_len,
    int mode
);

/**
 * Same as calling `ecc_oprf_ristretto255_sha512_Blind` with an
 * specified scalar blind.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.3.1
 *
 * @param blindedElement (output) blinded element
 * @param input message to blind
 * @param input_len length of `input`
 * @param blind scalar to use in the blind operation
 */
ECC_OPRF_EXPORT
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_BlindWithScalar(
    byte_t *blindedElement, // 32
    const byte_t *input, int input_len,
    const byte_t *blind // 32
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.3.1
 *
 * @param blindedElement (output) blinded element
 * @param blind (output) scalar used in the blind operation
 * @param input message to blind
 * @param input_len length of `input`
 */
ECC_OPRF_EXPORT
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_Blind(
    byte_t *blindedElement, // 32
    byte_t *blind, // 32
    const byte_t *input, int input_len
);

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.3.2
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_Unblind(
    byte_t *unblinded_element,
    const byte_t *blind,
    const byte_t *evaluated_element
);

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.3.3
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_Finalize(
    byte_t *output,
    const byte_t *input, int input_len,
    const byte_t *blind,
    const byte_t *evaluated_element,
    int mode
);

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.1.1
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_Evaluate(
    byte_t *evaluated_element,
    const byte_t *skS, const byte_t *blinded_element
);

#endif // ECC_OPRF_H
