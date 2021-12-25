/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_OPRF_H
#define ECC_OPRF_H

#include "export.h"

// const
/**
 * Size of a serialized group element, since this is the ristretto255
 * curve the size is 32 bytes.
 */
#define ecc_oprf_ristretto255_sha512_ELEMENTSIZE 32

// const
/**
 * Size of a serialized scalar, since this is the ristretto255
 * curve the size is 32 bytes.
 */
#define ecc_oprf_ristretto255_sha512_SCALARSIZE 32

// const
/**
 * Size of the protocol output in the `Finalize` operations, since
 * this is ristretto255 with SHA-512, the size is 64 bytes.
 */
#define ecc_oprf_ristretto255_sha512_Nh 64

/**
 * Evaluates serialized representations of blinded group elements from the
 * client as inputs.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-3.3.1.1
 *
 * @param[out] evaluatedElement evaluated element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param skS private key, size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param blindedElement blinded element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_Evaluate(
    byte_t *evaluatedElement,
    const byte_t *skS,
    const byte_t *blindedElement
);

/**
 * Same as calling `ecc_oprf_ristretto255_sha512_Blind` with an
 * specified scalar blind.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-3.3.3.1
 *
 * @param[out] blindedElement blinded element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param input message to blind, size:input_len
 * @param input_len length of `input`
 * @param blind scalar to use in the blind operation, size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_BlindWithScalar(
    byte_t *blindedElement, // 32
    const byte_t *input, int input_len,
    const byte_t *blind // 32
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-3.3.3.1
 *
 * @param[out] blindedElement blinded element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param[out] blind scalar used in the blind operation, size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param input message to blind, size:input_len
 * @param input_len length of `input`
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_Blind(
    byte_t *blindedElement, // 32
    byte_t *blind, // 32
    const byte_t *input, int input_len
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-3.3.3.1
 *
 * @param unblindedElement size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param blind size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param evaluatedElement size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_Unblind(
    byte_t *unblindedElement,
    const byte_t *blind,
    const byte_t *evaluatedElement
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-3.3.3.2
 *
 * @param[out] output size:64
 * @param input the input message, size:input_len
 * @param input_len the length of `input`
 * @param blind size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param evaluatedElement size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param mode mode to build the internal DST string (modeBase=0x00, modeVerifiable=0x01)
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_Finalize(
    byte_t *output,
    const byte_t *input, int input_len,
    const byte_t *blind,
    const byte_t *evaluatedElement,
    int mode
);

/**
 * Same as calling `ecc_oprf_ristretto255_sha512_HashToGroup` with an
 * specified DST string.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-2.1
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-4.1
 *
 * @param[out] out element of the group, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param input input string to map, size:input_len
 * @param input_len length of `input`
 * @param dst domain separation tag (DST), size:dst_len
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
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-2.1
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-4.1
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-2.2.5
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-3
 *
 * @param[out] out element of the group, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param input input string to map, size:input_len
 * @param input_len length of `input`
 * @param mode mode to build the internal DST string (modeBase=0x00, modeVerifiable=0x01)
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_HashToGroup(
    byte_t *out,
    const byte_t *input, int input_len,
    int mode
);

/**
 *
 * @param[out] out size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param input size:input_len
 * @param input_len
 * @param dst size:dst_len
 * @param dst_len
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_HashToScalarWithDST(
    byte_t *out,
    const byte_t *input, int input_len,
    const byte_t *dst, int dst_len
);

/**
 *
 * @param[out] out size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param input size:input_len
 * @param input_len
 * @param mode
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_HashToScalar(
    byte_t *out,
    const byte_t *input, int input_len,
    int mode
);

#endif // ECC_OPRF_H
