/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_VOPRF_H
#define ECC_VOPRF_H

#include "export.h"

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21
// https://github.com/cfrg/draft-irtf-cfrg-voprf

// const
/**
 * Size of a serialized group element, since this is the ristretto255
 * curve the size is 32 bytes.
 */
#define ecc_voprf_ristretto255_sha512_ELEMENTSIZE 32

// const
/**
 * Size of a serialized scalar, since this is the ristretto255
 * curve the size is 32 bytes.
 */
#define ecc_voprf_ristretto255_sha512_SCALARSIZE 32

// const
/**
 * Size of a proof. Proof is a tuple of two scalars.
 */
#define ecc_voprf_ristretto255_sha512_PROOFSIZE 64

// const
/**
 * Size of the protocol output in the `Finalize` operations, since
 * this is ristretto255 with SHA-512, the size is 64 bytes.
 */
#define ecc_voprf_ristretto255_sha512_Nh 64

// const
/**
 * A client and server interact to compute output = F(skS, input, info).
 */
#define ecc_voprf_ristretto255_sha512_MODE_OPRF 0

// const
/**
 * A client and server interact to compute output = F(skS, input, info) and
 * the client also receives proof that the server used skS in computing
 * the function.
 */
#define ecc_voprf_ristretto255_sha512_MODE_VOPRF 1

// const
/**
 * A client and server interact to compute output = F(skS, input, info).
 * Allows clients and servers to provide public input to the PRF computation.
 */
#define ecc_voprf_ristretto255_sha512_MODE_POPRF 2

// const
/**
 *
 */
#define ecc_voprf_ristretto255_sha512_MAXINFOSIZE 2000

/**
 * Generates a proof using the specified scalar. Given elements A and B, two
 * non-empty lists of elements C and D of length m, and a scalar k; this
 * function produces a proof that k*A == B and k*C[i] == D[i] for each i in
 * [0, ..., m - 1]. The output is a value of type Proof, which is a tuple of two
 * scalar values.
 *
 * @param[out] proof size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @param k size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param A size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param B size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param C size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param D size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param m the size of the `C` and `D` arrays
 * @param mode the protocol mode VOPRF or POPRF
 * @param r size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 */
ECC_EXPORT
void ecc_voprf_ristretto255_sha512_GenerateProofWithScalar(
    byte_t *proof,
    const byte_t *k,
    const byte_t *A,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D,
    int m,
    int mode,
    const byte_t *r
);

/**
 * Generates a proof. Given elements A and B, two
 * non-empty lists of elements C and D of length m, and a scalar k; this
 * function produces a proof that k*A == B and k*C[i] == D[i] for each i in
 * [0, ..., m - 1]. The output is a value of type Proof, which is a tuple of two
 * scalar values.
 *
 * @param[out] proof size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @param k size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param A size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param B size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param C size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param D size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param m the size of the `C` and `D` arrays
 * @param mode the protocol mode VOPRF or POPRF
 */
ECC_EXPORT
void ecc_voprf_ristretto255_sha512_GenerateProof(
    byte_t *proof,
    const byte_t *k,
    const byte_t *A,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D,
    int m,
    int mode
);

/**
 * Helper function used in GenerateProof. It is an optimization of the
 * ComputeComposites function for servers since they have knowledge of the
 * private key.
 *
 * @param[out] M size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param[out] Z size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param k size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param B size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param C size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param D size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param m the size of the `C` and `D` arrays
 * @param mode the protocol mode VOPRF or POPRF
 */
ECC_EXPORT
void ecc_voprf_ristretto255_sha512_ComputeCompositesFast(
    byte_t *M,
    byte_t *Z,
    const byte_t *k,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D,
    int m,
    int mode
);

/**
 * This function takes elements A and B, two non-empty lists of elements C and D
 * of length m, and a Proof value output from GenerateProof. It outputs a single
 * boolean value indicating whether or not the proof is valid for the given DLEQ
 * inputs. Note this function can verify proofs on lists of inputs whenever the
 * proof was generated as a batched DLEQ proof with the same inputs.
 *
 * @param A size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param B size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param C size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param D size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param m the size of the `C` and `D` arrays
 * @param mode the protocol mode VOPRF or POPRF
 * @param proof size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @return on success verification returns 1, else 0.
 */
ECC_EXPORT
int ecc_voprf_ristretto255_sha512_VerifyProof(
    const byte_t *A,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D,
    int m,
    int mode,
    const byte_t *proof
);

/**
 * Helper function used in `VerifyProof`.
 *
 * @param[out] M size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param[out] Z size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param B size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param C size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param D size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param m the size of the `C` and `D` arrays
 * @param mode the protocol mode VOPRF or POPRF
 */
ECC_EXPORT
void ecc_voprf_ristretto255_sha512_ComputeComposites(
    byte_t *M,
    byte_t *Z,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D,
    int m,
    int mode
);

/**
 * In the offline setup phase, the server key pair (skS, pkS) is generated using
 * this function, which produces a randomly generate private and public key pair.
 *
 * @param[out] skS size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param[out] pkS size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 */
ECC_EXPORT
void ecc_voprf_ristretto255_sha512_GenerateKeyPair(
    byte_t *skS,
    byte_t *pkS
);

/**
 * Deterministically generate a key. It accepts a randomly generated seed of
 * length Ns bytes and an optional (possibly empty) public info string.
 *
 * @param[out] skS size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param[out] pkS size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param seed size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param info size:infoLen
 * @param infoLen the size of `info`, it should be <= ecc_voprf_ristretto255_sha512_MAXINFOSIZE
 * @param mode the protocol mode VOPRF or POPRF
 * @return 0 on success, or -1 if an error
 */
ECC_EXPORT
int ecc_voprf_ristretto255_sha512_DeriveKeyPair(
    byte_t *skS,
    byte_t *pkS,
    const byte_t *seed,
    const byte_t *info, int infoLen,
    int mode
);

/**
 * Same as calling `ecc_voprf_ristretto255_sha512_Blind` with an
 * specified scalar blind.
 *
 * @param[out] blindedElement blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param input message to blind, size:inputLen
 * @param inputLen length of `input`
 * @param blind scalar to use in the blind operation, size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param mode oprf mode
 * @return 0 on success, or -1 if an error
 */
ECC_EXPORT
int ecc_voprf_ristretto255_sha512_BlindWithScalar(
    byte_t *blindedElement, // 32
    const byte_t *input, int inputLen,
    const byte_t *blind,
    int mode
);

/**
 * The OPRF protocol begins with the client blinding its input. Note that this
 * function can fail for certain inputs that map to the group identity element.
 *
 * @param[out] blind scalar used in the blind operation, size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param[out] blindedElement blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param input message to blind, size:inputLen
 * @param inputLen length of `input`
 * @param mode oprf mode
 * @return 0 on success, or -1 if an error
 */
ECC_EXPORT
int ecc_voprf_ristretto255_sha512_Blind(
    byte_t *blind,
    byte_t *blindedElement,
    const byte_t *input, int inputLen,
    int mode
);

/**
 * Clients store blind locally, and send blindedElement to the server for
 * evaluation. Upon receipt, servers process blindedElement using this function.
 *
 * @param[out] evaluatedElement blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param skS scalar used in the blind operation, size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param blindedElement blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 */
ECC_EXPORT
void ecc_voprf_ristretto255_sha512_BlindEvaluate(
    byte_t *evaluatedElement,
    const byte_t *skS,
    const byte_t *blindedElement
);

/**
 * Servers send the output evaluatedElement to clients for processing. Recall
 * that servers may process multiple client inputs by applying the BlindEvaluate
 * function to each blindedElement received, and returning an array with the
 * corresponding evaluatedElement values. Upon receipt of evaluatedElement,
 * clients process it to complete the OPRF evaluation with this function.
 *
 * @param[out] output size:ecc_voprf_ristretto255_sha512_Nh
 * @param input the input message, size:inputLen
 * @param inputLen the length of `input`
 * @param blind size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param evaluatedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 */
ECC_EXPORT
void ecc_voprf_ristretto255_sha512_Finalize(
    byte_t *output,
    const byte_t *input, int inputLen,
    const byte_t *blind,
    const byte_t *evaluatedElement
);

/**
 * An entity which knows both the secret key and the input can compute the PRF
 * result using this function.
 *
 * @param[out] output size:ecc_voprf_ristretto255_sha512_Nh
 * @param skS size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param input the input message, size:inputLen
 * @param inputLen the length of `input`
 * @param mode oprf mode
 * @return 0 on success, or -1 if an error
 */
ECC_EXPORT
int ecc_voprf_ristretto255_sha512_Evaluate(
    byte_t *output,
    const byte_t *skS,
    const byte_t *input, int inputLen,
    int mode
);

/**
 * Same as calling ecc_voprf_ristretto255_sha512_VerifiableBlindEvaluate but
 * using a specified scalar `r`.
 *
 * @param[out] evaluatedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param[out] proof size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @param skS size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param pkS size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param blindedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param r size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 */
ECC_EXPORT
void ecc_voprf_ristretto255_sha512_VerifiableBlindEvaluateWithScalar(
    byte_t *evaluatedElement,
    byte_t *proof,
    const byte_t *skS,
    const byte_t *pkS,
    const byte_t *blindedElement,
    const byte_t *r
);

/**
 * The VOPRF protocol begins with the client blinding its input. Clients store
 * the output blind locally and send blindedElement to the server for
 * evaluation. Upon receipt, servers process blindedElement to compute an
 * evaluated element and DLEQ proof using this function.
 *
 * @param[out] evaluatedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param[out] proof size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @param skS size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param pkS size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param blindedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 */
ECC_EXPORT
void ecc_voprf_ristretto255_sha512_VerifiableBlindEvaluate(
    byte_t *evaluatedElement,
    byte_t *proof,
    const byte_t *skS,
    const byte_t *pkS,
    const byte_t *blindedElement
);

/**
 * The server sends both evaluatedElement and proof back to the client. Upon
 * receipt, the client processes both values to complete the VOPRF computation
 * using this function below.
 *
 * @param[out] output size:ecc_voprf_ristretto255_sha512_Nh
 * @param input the input message, size:inputLen
 * @param inputLen the length of `input`
 * @param blind size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param evaluatedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param blindedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param pkS size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param proof size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @return 0 on success, or -1 if an error
 */
ECC_EXPORT
int ecc_voprf_ristretto255_sha512_VerifiableFinalize(
    byte_t *output,
    const byte_t *input, int inputLen,
    const byte_t *blind,
    const byte_t *evaluatedElement,
    const byte_t *blindedElement,
    const byte_t *pkS,
    const byte_t *proof
);

/**
 * Same as calling ecc_voprf_ristretto255_sha512_PartiallyBlind with an
 * specified blind scalar.
 *
 * @param[out] blindedElement blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param[out] tweakedKey blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param input message to blind, size:inputLen
 * @param inputLen length of `input`
 * @param info message to blind, size:infoLen
 * @param infoLen length of `info`, it should be <= ecc_voprf_ristretto255_sha512_MAXINFOSIZE
 * @param pkS size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param blind size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @return 0 on success, or -1 if an error
 */
ECC_EXPORT
int ecc_voprf_ristretto255_sha512_PartiallyBlindWithScalar(
    byte_t *blindedElement,
    byte_t *tweakedKey,
    const byte_t *input, int inputLen,
    const byte_t *info, int infoLen,
    const byte_t *pkS,
    const byte_t *blind
);

/**
 * The POPRF protocol begins with the client blinding its input, using the
 * following modified Blind function. In this step, the client also binds a
 * public info value, which produces an additional tweakedKey to be used later
 * in the protocol. Note that this function can fail for certain private inputs
 * that map to the group identity element, as well as certain public inputs
 * that, if not detected at this point, will cause server evaluation to fail.
 *
 * @param[out] blind scalar used in the blind operation, size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param[out] blindedElement blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param[out] tweakedKey blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param input message to blind, size:inputLen
 * @param inputLen length of `input`
 * @param info message to blind, size:infoLen
 * @param infoLen length of `info`, it should be <= ecc_voprf_ristretto255_sha512_MAXINFOSIZE
 * @param pkS size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @return 0 on success, or -1 if an error
 */
ECC_EXPORT
int ecc_voprf_ristretto255_sha512_PartiallyBlind(
    byte_t *blind,
    byte_t *blindedElement,
    byte_t *tweakedKey,
    const byte_t *input, int inputLen,
    const byte_t *info, int infoLen,
    const byte_t *pkS
);

/**
 * Same as calling ecc_voprf_ristretto255_sha512_PartiallyBlindEvaluate with an
 * specified scalar r.
 *
 * @param[out] evaluatedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param[out] proof size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @param skS size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param blindedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param info message to blind, size:infoLen
 * @param infoLen length of `info`, it should be <= ecc_voprf_ristretto255_sha512_MAXINFOSIZE
 * @param r size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @return 0 on success, or -1 if an error
 */
ECC_EXPORT
int ecc_voprf_ristretto255_sha512_PartiallyBlindEvaluateWithScalar(
    byte_t *evaluatedElement,
    byte_t *proof,
    const byte_t *skS,
    const byte_t *blindedElement,
    const byte_t *info, int infoLen,
    const byte_t *r
);

/**
 * Clients store the outputs blind and tweakedKey locally and send
 * blindedElement to the server for evaluation. Upon receipt, servers process
 * blindedElement to compute an evaluated element and DLEQ proof using the
 * this function.
 *
 * @param[out] evaluatedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param[out] proof size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @param skS size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param blindedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param info message to blind, size:infoLen
 * @param infoLen length of `info`, it should be <= ecc_voprf_ristretto255_sha512_MAXINFOSIZE
 * @return 0 on success, or -1 if an error
 */
ECC_EXPORT
int ecc_voprf_ristretto255_sha512_PartiallyBlindEvaluate(
    byte_t *evaluatedElement,
    byte_t *proof,
    const byte_t *skS,
    const byte_t *blindedElement,
    const byte_t *info, int infoLen
);

/**
 * The server sends both evaluatedElement and proof back to the client. Upon
 * receipt, the client processes both values to complete the POPRF computation
 * using this function.
 *
 * @param[out] output size:ecc_voprf_ristretto255_sha512_Nh
 * @param input the input message, size:inputLen
 * @param inputLen the length of `input`
 * @param blind size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param evaluatedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param blindedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param proof size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @param info message to blind, size:infoLen
 * @param infoLen length of `info`, it should be <= ecc_voprf_ristretto255_sha512_MAXINFOSIZE
 * @param tweakedKey blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @return 0 on success, or -1 if an error
 */
ECC_EXPORT
int ecc_voprf_ristretto255_sha512_PartiallyFinalize(
    byte_t *output,
    const byte_t *input, int inputLen,
    const byte_t *blind,
    const byte_t *evaluatedElement,
    const byte_t *blindedElement,
    const byte_t *proof,
    const byte_t *info, int infoLen,
    const byte_t *tweakedKey
);

/**
 * An entity which knows both the secret key and the input can compute the PRF
 * result using this function.
 *
 * @param[out] output size:ecc_voprf_ristretto255_sha512_Nh
 * @param skS size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param input the input message, size:inputLen
 * @param inputLen the length of `input`
 * @param info message to blind, size:infoLen
 * @param infoLen length of `info`, it should be <= ecc_voprf_ristretto255_sha512_MAXINFOSIZE
 * @return 0 on success, or -1 if an error
 */
ECC_EXPORT
int ecc_voprf_ristretto255_sha512_PartiallyEvaluate(
    byte_t *output,
    const byte_t *skS,
    const byte_t *input, int inputLen,
    const byte_t *info, int infoLen
);

/**
 * Same as calling `ecc_voprf_ristretto255_sha512_HashToGroup` with an
 * specified DST string.
 *
 * @param[out] out element of the group, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param input input string to map, size:inputLen
 * @param inputLen length of `input`
 * @param dst domain separation tag (DST), size:dstLen
 * @param dstLen length of `dst`
 */
ECC_EXPORT
void ecc_voprf_ristretto255_sha512_HashToGroupWithDST(
    byte_t *out,
    const byte_t *input, int inputLen,
    const byte_t *dst, int dstLen
);

/**
 * Deterministically maps an array of bytes "x" to an element of "G" in
 * the ristretto255 curve.
 *
 * @param[out] out element of the group, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param input input string to map, size:inputLen
 * @param inputLen length of `input`
 * @param mode mode to build the internal DST string (OPRF, VOPRF, POPRF)
 */
ECC_EXPORT
void ecc_voprf_ristretto255_sha512_HashToGroup(
    byte_t *out,
    const byte_t *input, int inputLen,
    int mode
);

/**
 * Same as calling ecc_voprf_ristretto255_sha512_HashToScalar with a specified
 * DST.
 *
 * @param[out] out size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param input size:inputLen
 * @param inputLen the length of `input`
 * @param dst size:dstLen
 * @param dstLen the length of `dst`
 */
ECC_EXPORT
void ecc_voprf_ristretto255_sha512_HashToScalarWithDST(
    byte_t *out,
    const byte_t *input, int inputLen,
    const byte_t *dst, int dstLen
);

/**
 * Deterministically maps an array of bytes x to an element in GF(p) in
 * the ristretto255 curve.
 *
 * @param[out] out size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param input size:inputLen
 * @param inputLen the length of `input`
 * @param mode oprf mode
 */
ECC_EXPORT
void ecc_voprf_ristretto255_sha512_HashToScalar(
    byte_t *out,
    const byte_t *input, int inputLen,
    int mode
);

#endif // ECC_VOPRF_H
