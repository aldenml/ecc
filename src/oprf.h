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
 * Size of a proof. Proof is a sequence of two scalars.
 */
#define ecc_oprf_ristretto255_sha512_PROOFSIZE 64

// const
/**
 * Size of the protocol output in the `Finalize` operations, since
 * this is ristretto255 with SHA-512, the size is 64 bytes.
 */
#define ecc_oprf_ristretto255_sha512_Nh 64

// const
/**
 * A client and server interact to compute output = F(skS, input, info).
 */
#define ecc_oprf_ristretto255_sha512_MODE_BASE 0

// const
/**
 * A client and server interact to compute output = F(skS, input, info) and
 * the client also receives proof that the server used skS in computing
 * the function.
 */
#define ecc_oprf_ristretto255_sha512_MODE_VERIFIABLE 1

/**
 * Evaluates serialized representations of blinded group elements from the
 * client as inputs.
 *
 * This operation could fail if internally, there is an attempt to invert
 * the `0` scalar.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.1.1
 *
 * @param[out] evaluatedElement evaluated element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param skS private key, size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param blindedElement blinded element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param info opaque byte string no larger than 200 bytes, size:infoLen
 * @param infoLen the size of `info`
 * @return 0 on success, or -1 if an error
 */
ECC_EXPORT
int ecc_oprf_ristretto255_sha512_Evaluate(
    byte_t *evaluatedElement,
    const byte_t *skS,
    const byte_t *blindedElement,
    const byte_t *info,
    int infoLen
);

/**
 * Evaluates serialized representations of blinded group elements from the
 * client as inputs and produces a proof that `skS` was used in computing
 * the result.
 *
 * This operation could fail if internally, there is an attempt to invert
 * the `0` scalar.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.2.1
 *
 * @param[out] evaluatedElement evaluated element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param[out] proof size:ecc_oprf_ristretto255_sha512_PROOFSIZE
 * @param skS private key, size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param blindedElement blinded element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param info opaque byte string no larger than 200 bytes, size:infoLen
 * @param infoLen the size of `info`
 * @param r size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @return 0 on success, or -1 if an error
 */
ECC_EXPORT
int ecc_oprf_ristretto255_sha512_VerifiableEvaluateWithScalar(
    byte_t *evaluatedElement,
    byte_t *proof,
    const byte_t *skS,
    const byte_t *blindedElement,
    const byte_t *info, int infoLen,
    const byte_t *r
);

/**
 * Evaluates serialized representations of blinded group elements from the
 * client as inputs and produces a proof that `skS` was used in computing
 * the result.
 *
 * This operation could fail if internally, there is an attempt to invert
 * the `0` scalar.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.2.1
 *
 * @param[out] evaluatedElement evaluated element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param[out] proof size:ecc_oprf_ristretto255_sha512_PROOFSIZE
 * @param skS private key, size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param blindedElement blinded element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param info opaque byte string no larger than 200 bytes, size:infoLen
 * @param infoLen the size of `info`
 * @return 0 on success, or -1 if an error
 */
ECC_EXPORT
int ecc_oprf_ristretto255_sha512_VerifiableEvaluate(
    byte_t *evaluatedElement,
    byte_t *proof,
    const byte_t *skS,
    const byte_t *blindedElement,
    const byte_t *info, int infoLen
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.2.2
 *
 * @param[out] proof size:ecc_oprf_ristretto255_sha512_PROOFSIZE
 * @param k size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param A size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param B size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param C size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param D size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param r size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_GenerateProofWithScalar(
    byte_t *proof,
    const byte_t *k,
    const byte_t *A,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D,
    const byte_t *r
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.2.2
 *
 * @param[out] proof size:ecc_oprf_ristretto255_sha512_PROOFSIZE
 * @param k size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param A size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param B size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param C size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param D size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_GenerateProof(
    byte_t *proof,
    const byte_t *k,
    const byte_t *A,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.2.3
 *
 * @param[out] M size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param[out] Z size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param B size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param Cs size:m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param Ds size:m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param m
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_ComputeComposites(
    byte_t *M,
    byte_t *Z,
    const byte_t *B,
    const byte_t *Cs,
    const byte_t *Ds,
    int m
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.2.3
 *
 * @param[out] M size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param[out] Z size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param k size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param B size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param Cs size:m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param Ds size:m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param m
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_ComputeCompositesFast(
    byte_t *M,
    byte_t *Z,
    const byte_t *k,
    const byte_t *B,
    const byte_t *Cs,
    const byte_t *Ds,
    int m
);

/**
 * Same as calling `ecc_oprf_ristretto255_sha512_Blind` with an
 * specified scalar blind.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.3.1
 *
 * @param[out] blindedElement blinded element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param input message to blind, size:inputLen
 * @param inputLen length of `input`
 * @param blind scalar to use in the blind operation, size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param mode
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_BlindWithScalar(
    byte_t *blindedElement, // 32
    const byte_t *input, int inputLen,
    const byte_t *blind,
    int mode
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.3.1
 *
 * @param[out] blindedElement blinded element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param[out] blind scalar used in the blind operation, size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param input message to blind, size:inputLen
 * @param inputLen length of `input`
 * @param mode
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_Blind(
    byte_t *blindedElement, // 32
    byte_t *blind, // 32
    const byte_t *input, int inputLen,
    int mode
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.3.1
 *
 * @param[out] unblindedElement size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
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
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.3.2
 *
 * @param[out] output size:ecc_oprf_ristretto255_sha512_Nh
 * @param input the input message, size:inputLen
 * @param inputLen the length of `input`
 * @param blind size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param evaluatedElement size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param info size:infoLen
 * @param infoLen
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_Finalize(
    byte_t *output,
    const byte_t *input, int inputLen,
    const byte_t *blind,
    const byte_t *evaluatedElement,
    const byte_t *info, int infoLen
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.4.1
 *
 * @param A size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param B size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param C size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param D size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param proof size:ecc_oprf_ristretto255_sha512_PROOFSIZE
 * @return on success verification returns 1, else 0.
 */
ECC_EXPORT
int ecc_oprf_ristretto255_sha512_VerifyProof(
    const byte_t *A,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D,
    const byte_t *proof
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.4.2
 *
 * @param[out] unblindedElement size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param blind size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param evaluatedElement size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param blindedElement size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param pkS size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param proof size:ecc_oprf_ristretto255_sha512_PROOFSIZE
 * @param info size:infoLen
 * @param infoLen
 * @return on success verification returns 0, else -1.
 */
ECC_EXPORT
int ecc_oprf_ristretto255_sha512_VerifiableUnblind(
    byte_t *unblindedElement,
    const byte_t *blind,
    const byte_t *evaluatedElement,
    const byte_t *blindedElement,
    const byte_t *pkS,
    const byte_t *proof,
    const byte_t *info, int infoLen
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.4.3
 *
 * @param[out] output size:ecc_oprf_ristretto255_sha512_Nh
 * @param input size:inputLen
 * @param inputLen
 * @param blind size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param evaluatedElement size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param blindedElement size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param pkS size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param proof size:ecc_oprf_ristretto255_sha512_PROOFSIZE
 * @param info size:infoLen
 * @param infoLen
 * @return on success verification returns 0, else -1.
 */
ECC_EXPORT
int ecc_oprf_ristretto255_sha512_VerifiableFinalize(
    byte_t *output,
    const byte_t *input, int inputLen,
    const byte_t *blind,
    const byte_t *evaluatedElement,
    const byte_t *blindedElement,
    const byte_t *pkS,
    const byte_t *proof,
    const byte_t *info, int infoLen
);

/**
 * Same as calling `ecc_oprf_ristretto255_sha512_HashToGroup` with an
 * specified DST string.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-2.1
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-4.1
 *
 * @param[out] out element of the group, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param input input string to map, size:inputLen
 * @param inputLen length of `input`
 * @param dst domain separation tag (DST), size:dstLen
 * @param dstLen length of `dst`
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_HashToGroupWithDST(
    byte_t *out,
    const byte_t *input, int inputLen,
    const byte_t *dst, int dstLen
);

/**
 * Deterministically maps an array of bytes "x" to an element of "GG" in
 * the ristretto255 curve.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-2.1
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-4.1
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-13#section-2.2.5
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3
 *
 * @param[out] out element of the group, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
 * @param input input string to map, size:inputLen
 * @param inputLen length of `input`
 * @param mode mode to build the internal DST string (modeBase=0x00, modeVerifiable=0x01)
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_HashToGroup(
    byte_t *out,
    const byte_t *input, int inputLen,
    int mode
);

/**
 *
 * @param[out] out size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param input size:inputLen
 * @param inputLen
 * @param dst size:dstLen
 * @param dstLen
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_HashToScalarWithDST(
    byte_t *out,
    const byte_t *input, int inputLen,
    const byte_t *dst, int dstLen
);

/**
 *
 * @param[out] out size:ecc_oprf_ristretto255_sha512_SCALARSIZE
 * @param input size:inputLen
 * @param inputLen
 * @param mode
 */
ECC_EXPORT
void ecc_oprf_ristretto255_sha512_HashToScalar(
    byte_t *out,
    const byte_t *input, int inputLen,
    int mode
);

#endif // ECC_OPRF_H
