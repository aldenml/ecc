/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "oprf.h"
#include <string.h>
#include <assert.h>
#include "util.h"
#include "hash.h"
#include "h2c.h"
#include "ristretto255.h"

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcpp"
#endif

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcpp"
#endif

#include <sodium.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#define ELEMENTSIZE ecc_oprf_ristretto255_sha512_ELEMENTSIZE
#define SCALARSIZE ecc_oprf_ristretto255_sha512_SCALARSIZE
#define MODE_BASE ecc_oprf_ristretto255_sha512_MODE_BASE
#define MODE_VERIFIABLE ecc_oprf_ristretto255_sha512_MODE_VERIFIABLE

typedef struct {
    byte_t c[SCALARSIZE];
    byte_t s[SCALARSIZE];
} Proof_t;

static_assert(ecc_oprf_ristretto255_sha512_ELEMENTSIZE == ecc_ristretto255_ELEMENTSIZE, "");
static_assert(ecc_oprf_ristretto255_sha512_SCALARSIZE == ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_oprf_ristretto255_sha512_PROOFSIZE == 2 * ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_oprf_ristretto255_sha512_Nh == ecc_hash_sha512_HASHSIZE, "");

static_assert(sizeof(Proof_t) == ecc_oprf_ristretto255_sha512_PROOFSIZE, "");

int createContextString(
    byte_t *contextString,
    const int mode,
    byte_t *prefix,
    const int prefixLen
);

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.2
int createContextString(
    byte_t *contextString,
    const int mode,
    byte_t *prefix,
    const int prefixLen
) {
    // contextString = "${RFC_ID}-" || I2OSP(mode, 1) || I2OSP(suite_id, 2)

    byte_t rfcId[7] = "VOPRF08"; // TODO: change to "RFCXXXX", where XXXX is the final number
    byte_t dash[1] = "-";

    byte_t *p = contextString;

    if (prefix != NULL) {
        ecc_concat2(p, prefix, prefixLen, dash, 1);
        p += prefixLen + 1;
    }

    ecc_concat2(p, rfcId, sizeof rfcId, dash, 1);
    p += sizeof rfcId + 1;
    ecc_I2OSP(p, mode, 1);
    p += 1;
    ecc_I2OSP(p, 0x0001, 2); // 0x0001 for OPRF(ristretto255, SHA-512)
    p += 2;

    return (int)(p - contextString);
}

int ecc_oprf_ristretto255_sha512_Evaluate(
    byte_t *evaluatedElement, // 32 bytes
    const byte_t *skS,
    const byte_t *blindedElement,
    const byte_t *info,
    const int infoLen
) {
    // R = GG.DeserializeElement(blindedElement)
    // context = "Context-" || contextString ||
    //           I2OSP(len(info), 2) || info
    // m = GG.HashToScalar(context)
    // t = skS + m
    // if t == 0:
    //     raise InverseError
    // Z = t^(-1) * R
    // evaluatedElement = GG.SerializeElement(Z)

    // context = "Context-" || contextString ||
    //           I2OSP(len(info), 2) || info
    byte_t context[256];
    byte_t contextPrefix[7] = "Context";
    int contextLen = createContextString(
        context, MODE_BASE,
        contextPrefix, sizeof contextPrefix
    );
    ecc_I2OSP(&context[contextLen], infoLen, 2);
    ecc_concat2(&context[contextLen + 2], info, infoLen, NULL, 0);
    contextLen += 2 + infoLen;

    // m = GG.HashToScalar(context)
    byte_t m[SCALARSIZE];
    ecc_oprf_ristretto255_sha512_HashToScalar(m, context, contextLen, MODE_BASE);

    // t = skS + m
    // if t == 0:
    //     raise InverseError
    byte_t t[SCALARSIZE];
    memcpy(t, skS, SCALARSIZE);
    sodium_add(t, m, SCALARSIZE);
    if (ecc_is_zero(t, sizeof t)) {
        // stack memory cleanup
        ecc_memzero(context, sizeof context);
        ecc_memzero(m, sizeof m);
        ecc_memzero(t, sizeof t);
        return -1;
    }

    // Z = t^(-1) * R
    byte_t tInverted[SCALARSIZE];
    ecc_ristretto255_scalar_invert(tInverted, t); // t^(-1)
    ecc_ristretto255_scalarmult(evaluatedElement, tInverted, blindedElement);

    // stack memory cleanup
    ecc_memzero(context, sizeof context);
    ecc_memzero(m, sizeof m);
    ecc_memzero(t, sizeof t);
    ecc_memzero(tInverted, sizeof tInverted);

    return 0;
}

int ecc_oprf_ristretto255_sha512_VerifiableEvaluateWithScalar(
    byte_t *evaluatedElement,
    byte_t *proof,
    const byte_t *skS,
    const byte_t *blindedElement,
    const byte_t *info, const int infoLen,
    const byte_t *r
) {
    // R = GG.DeserializeElement(blindedElement)
    // context = "Context-" || contextString ||
    //           I2OSP(len(info), 2) || info
    // m = GG.HashToScalar(context)
    // t = skS + m
    // if t == 0:
    //     raise InverseError
    // Z = t^(-1) * R
    //
    // U = ScalarBaseMult(t)
    // proof = GenerateProof(t, G, U, Z, R)
    // evaluatedElement = GG.SerializeElement(Z)

    // context = "Context-" || contextString ||
    //           I2OSP(len(info), 2) || info
    byte_t context[256];
    byte_t contextPrefix[7] = "Context";
    int contextLen = createContextString(
        context, MODE_VERIFIABLE,
        contextPrefix, sizeof contextPrefix
    );
    ecc_I2OSP(&context[contextLen], infoLen, 2);
    ecc_concat2(&context[contextLen + 2], info, infoLen, NULL, 0);
    contextLen += 2 + infoLen;

    // m = GG.HashToScalar(context)
    byte_t m[SCALARSIZE];
    ecc_oprf_ristretto255_sha512_HashToScalar(m, context, contextLen, MODE_VERIFIABLE);

    // t = skS + m
    // if t == 0:
    //     raise InverseError
    byte_t t[SCALARSIZE];
    memcpy(t, skS, SCALARSIZE);
    sodium_add(t, m, SCALARSIZE);
    if (ecc_is_zero(t, SCALARSIZE)) {
        // stack memory cleanup
        ecc_memzero(context, sizeof context);
        ecc_memzero(m, sizeof m);
        ecc_memzero(t, sizeof t);
        return -1;
    }

    // Z = t^(-1) * R
    byte_t tInverted[SCALARSIZE];
    ecc_ristretto255_scalar_invert(tInverted, t); // t^(-1)
    ecc_ristretto255_scalarmult(evaluatedElement, tInverted, blindedElement);

    // U = ScalarBaseMult(t)
    byte_t U[ELEMENTSIZE];
    ecc_ristretto255_scalarmult_base(U, t);

    // G is the group generator
    byte_t G[ELEMENTSIZE];
    ecc_ristretto255_generator(G);

    // proof = GenerateProof(t, G, U, Z, R)
    ecc_oprf_ristretto255_sha512_GenerateProofWithScalar(
        proof,
        t,
        G,
        U,
        evaluatedElement,
        blindedElement,
        r
    );

    // stack memory cleanup
    ecc_memzero(context, sizeof context);
    ecc_memzero(m, sizeof m);
    ecc_memzero(t, sizeof t);
    ecc_memzero(tInverted, sizeof tInverted);
    ecc_memzero(U, sizeof U);

    return 0;
}

int ecc_oprf_ristretto255_sha512_VerifiableEvaluate(
    byte_t *evaluatedElement,
    byte_t *proof,
    const byte_t *skS,
    const byte_t *blindedElement,
    const byte_t *info, int infoLen
) {
    byte_t r[SCALARSIZE];
    ecc_ristretto255_scalar_random(r);

    const int ret = ecc_oprf_ristretto255_sha512_VerifiableEvaluateWithScalar(
        evaluatedElement,
        proof,
        skS,
        blindedElement,
        info, infoLen,
        r
    );

    // stack memory cleanup
    ecc_memzero(r, sizeof r);

    return ret;
}

void ecc_oprf_ristretto255_sha512_GenerateProofWithScalar(
    byte_t *proofPtr,
    const byte_t *k,
    const byte_t *A,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D,
    const byte_t *r
) {
    // Cs = [C]
    // Ds = [D]
    // (M, Z) = ComputeCompositesFast(k, B, Cs, Ds)
    //
    // r = GG.RandomScalar()
    // t2 = r * A
    // t3 = r * M
    //
    // Bm = GG.SerializeElement(B)
    // a0 = GG.SerializeElement(M)
    // a1 = GG.SerializeElement(Z)
    // a2 = GG.SerializeElement(t2)
    // a3 = GG.SerializeElement(t3)
    //
    // challengeDST = "Challenge-" || contextString
    // h2Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(a0), 2) || a0 ||
    //           I2OSP(len(a1), 2) || a1 ||
    //           I2OSP(len(a2), 2) || a2 ||
    //           I2OSP(len(a3), 2) || a3 ||
    //           I2OSP(len(challengeDST), 2) || challengeDST
    //
    // c = GG.HashToScalar(h2Input)
    // s = (r - c * k) mod p
    //
    // proof = GG.SerializeScalar(c) || GG.SerializeScalar(s)

    Proof_t *proof = (Proof_t *) proofPtr;

    // Cs = [C]
    // Ds = [D]
    // (M, Z) = ComputeCompositesFast(k, B, Cs, Ds)
    byte_t M[ELEMENTSIZE];
    byte_t Z[ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_ComputeCompositesFast(
        M,
        Z,
        k,
        B,
        C,
        D,
        1
    );

    // r = GG.RandomScalar()
    // t2 = r * A
    byte_t t2[ELEMENTSIZE];
    ecc_ristretto255_scalarmult(t2, r, A);
    // t3 = r * M
    byte_t t3[ELEMENTSIZE];
    ecc_ristretto255_scalarmult(t3, r, M);

    // Bm = GG.SerializeElement(B)
    // a0 = GG.SerializeElement(M)
    // a1 = GG.SerializeElement(Z)
    // a2 = GG.SerializeElement(t2)
    // a3 = GG.SerializeElement(t3)
    const byte_t *Bm = B;
    const byte_t *a0 = M;
    const byte_t *a1 = Z;
    const byte_t *a2 = t2;
    const byte_t *a3 = t3;

    // challengeDST = "Challenge-" || contextString
    byte_t challengeDST[100];
    byte_t challengeDSTPrefix[9] = "Challenge";
    const int challengeDSTLen = createContextString(
        challengeDST, MODE_VERIFIABLE,
        challengeDSTPrefix, sizeof challengeDSTPrefix
    );

    // h2Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(a0), 2) || a0 ||
    //           I2OSP(len(a1), 2) || a1 ||
    //           I2OSP(len(a2), 2) || a2 ||
    //           I2OSP(len(a3), 2) || a3 ||
    //           I2OSP(len(challengeDST), 2) || challengeDST
    byte_t h2Input[256];
    int h2InputLen = 0;
    ecc_I2OSP(&h2Input[h2InputLen], ELEMENTSIZE, 2);
    h2InputLen += 2;
    ecc_concat2(&h2Input[h2InputLen], Bm, ELEMENTSIZE, NULL, 0);
    h2InputLen += ELEMENTSIZE;
    ecc_I2OSP(&h2Input[h2InputLen], ELEMENTSIZE, 2);
    h2InputLen += 2;
    ecc_concat2(&h2Input[h2InputLen], a0, ELEMENTSIZE, NULL, 0);
    h2InputLen += ELEMENTSIZE;
    ecc_I2OSP(&h2Input[h2InputLen], ELEMENTSIZE, 2);
    h2InputLen += 2;
    ecc_concat2(&h2Input[h2InputLen], a1, ELEMENTSIZE, NULL, 0);
    h2InputLen += ELEMENTSIZE;
    ecc_I2OSP(&h2Input[h2InputLen], ELEMENTSIZE, 2);
    h2InputLen += 2;
    ecc_concat2(&h2Input[h2InputLen], a2, ELEMENTSIZE, NULL, 0);
    h2InputLen += ELEMENTSIZE;
    ecc_I2OSP(&h2Input[h2InputLen], ELEMENTSIZE, 2);
    h2InputLen += 2;
    ecc_concat2(&h2Input[h2InputLen], a3, ELEMENTSIZE, NULL, 0);
    h2InputLen += ELEMENTSIZE;
    ecc_I2OSP(&h2Input[h2InputLen], challengeDSTLen, 2);
    h2InputLen += 2;
    ecc_concat2(&h2Input[h2InputLen], challengeDST, challengeDSTLen, NULL, 0);
    h2InputLen += challengeDSTLen;

    // c = GG.HashToScalar(h2Input)
    byte_t c[SCALARSIZE];
    ecc_oprf_ristretto255_sha512_HashToScalar(c, h2Input, h2InputLen, MODE_VERIFIABLE);

    // s = (r - c * k) mod p
    byte_t t[SCALARSIZE];
    ecc_ristretto255_scalar_mul(t, c, k);
    byte_t s[SCALARSIZE];
    ecc_ristretto255_scalar_sub(s, r, t);

    // proof = GG.SerializeScalar(c) || GG.SerializeScalar(s)
    memcpy(proof->c, c, SCALARSIZE);
    memcpy(proof->s, s, SCALARSIZE);

    // stack memory cleanup
    ecc_memzero(M, sizeof M);
    ecc_memzero(Z, sizeof Z);
    ecc_memzero(t2, sizeof t2);
    ecc_memzero(t3, sizeof t3);
    ecc_memzero(h2Input, sizeof h2Input);
    ecc_memzero(c, sizeof c);
    ecc_memzero(t, sizeof t);
    ecc_memzero(s, sizeof s);
}

void ecc_oprf_ristretto255_sha512_GenerateProof(
    byte_t *proof,
    const byte_t *k,
    const byte_t *A,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D
) {
    byte_t r[SCALARSIZE];
    ecc_ristretto255_scalar_random(r);

    ecc_oprf_ristretto255_sha512_GenerateProofWithScalar(
        proof,
        k,
        A, B, C, D,
        r
    );

    // stack memory cleanup
    ecc_memzero(r, sizeof r);
}

void ecc_oprf_ristretto255_sha512_ComputeComposites(
    byte_t *M,
    byte_t *Z,
    const byte_t *B,
    const byte_t *Cs,
    const byte_t *Ds,
    const int m
) {
    // Bm = GG.SerializeElement(B)
    // seedDST = "Seed-" || contextString
    // compositeDST = "Composite-" || contextString
    //
    // h1Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(seedDST), 2) || seedDST
    // seed = Hash(h1Input)
    //
    // M = GG.Identity()
    // Z = GG.Identity()
    // for i = 0 to m-1:
    //   Ci = GG.SerializeElement(Cs[i])
    //   Di = GG.SerializeElement(Ds[i])
    //   h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
    //             I2OSP(len(Ci), 2) || Ci ||
    //             I2OSP(len(Di), 2) || Di ||
    //             I2OSP(len(compositeDST), 2) || compositeDST
    //   di = GG.HashToScalar(h2Input)
    //   M = di * Cs[i] + M
    //   Z = di * Ds[i] + Z
    //

    // seedDST = "Seed-" || contextString
    byte_t seedDST[100];
    byte_t seedDSTPrefix[4] = "Seed";
    const int seedDSTLen = createContextString(
        seedDST, MODE_VERIFIABLE,
        seedDSTPrefix, sizeof seedDSTPrefix
    );

    // compositeDST = "Composite-" || contextString
    byte_t compositeDST[100];
    byte_t compositeDSTPrefix[9] = "Composite";
    const int compositeDSTLen = createContextString(
        compositeDST, MODE_VERIFIABLE,
        compositeDSTPrefix, sizeof compositeDSTPrefix
    );

    // h1Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(seedDST), 2) || seedDST
    byte_t h1Input[256];
    int h1InputLen = 0;
    ecc_I2OSP(&h1Input[h1InputLen], ELEMENTSIZE, 2);
    h1InputLen += 2;
    ecc_concat2(&h1Input[h1InputLen], B, ELEMENTSIZE, NULL, 0);
    h1InputLen += ELEMENTSIZE;
    ecc_I2OSP(&h1Input[h1InputLen], seedDSTLen, 2);
    h1InputLen += 2;
    ecc_concat2(&h1Input[h1InputLen], seedDST, seedDSTLen, NULL, 0);
    h1InputLen += seedDSTLen;

    // seed = Hash(h1Input)
    byte_t seed[64];
    ecc_hash_sha512(seed, h1Input, h1InputLen);

    // M = GG.Identity()
    ecc_memzero(M, ELEMENTSIZE);
    // Z = GG.Identity()
    ecc_memzero(Z, ELEMENTSIZE);

    // for i = 0 to m-1:
    //   Ci = GG.SerializeElement(Cs[i])
    //   Di = GG.SerializeElement(Ds[i])
    //   h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
    //             I2OSP(len(Ci), 2) || Ci ||
    //             I2OSP(len(Di), 2) || Di ||
    //             I2OSP(len(compositeDST), 2) || compositeDST
    //   di = GG.HashToScalar(h2Input)
    //   M = di * Cs[i] + M
    //   Z = di * Ds[i] + Z
    byte_t Ci[ELEMENTSIZE];
    byte_t Di[ELEMENTSIZE];
    byte_t h2Input[256];
    int h2InputLen = 0;
    byte_t di[SCALARSIZE];
    byte_t t[ELEMENTSIZE];
    for (int i = 0; i < m; i++) {
        // Ci = GG.SerializeElement(Cs[i])
        memcpy(Ci, &Cs[i * ELEMENTSIZE], ELEMENTSIZE);
        // Di = GG.SerializeElement(Ds[i])
        memcpy(Di, &Ds[i * ELEMENTSIZE], ELEMENTSIZE);

        ecc_I2OSP(&h2Input[h2InputLen], 64, 2);
        h2InputLen += 2;
        ecc_concat2(&h2Input[h2InputLen], seed, 64, NULL, 0);
        h2InputLen += 64;
        ecc_I2OSP(&h2Input[h2InputLen], i, 2);
        h2InputLen += 2;
        ecc_I2OSP(&h2Input[h2InputLen], ELEMENTSIZE, 2);
        h2InputLen += 2;
        ecc_concat2(&h2Input[h2InputLen], Ci, ELEMENTSIZE, NULL, 0);
        h2InputLen += ELEMENTSIZE;
        ecc_I2OSP(&h2Input[h2InputLen], ELEMENTSIZE, 2);
        h2InputLen += 2;
        ecc_concat2(&h2Input[h2InputLen], Di, ELEMENTSIZE, NULL, 0);
        h2InputLen += ELEMENTSIZE;
        ecc_I2OSP(&h2Input[h2InputLen], compositeDSTLen, 2);
        h2InputLen += 2;
        ecc_concat2(&h2Input[h2InputLen], compositeDST, compositeDSTLen, NULL, 0);
        h2InputLen += compositeDSTLen;

        // di = GG.HashToScalar(h2Input)
        ecc_oprf_ristretto255_sha512_HashToScalar(di, h2Input, h2InputLen, MODE_VERIFIABLE);

        // M = di * Cs[i] + M
        ecc_ristretto255_scalarmult(t, di, &Cs[i * ELEMENTSIZE]);
        ecc_ristretto255_add(M, t, M);
        // Z = di * Ds[i] + Z
        ecc_ristretto255_scalarmult(t, di, &Ds[i * ELEMENTSIZE]);
        ecc_ristretto255_add(Z, t, Z);
    }

    // stack memory cleanup
    ecc_memzero(h1Input, sizeof h1Input);
    ecc_memzero(seed, sizeof seed);
    ecc_memzero(Ci, sizeof Ci);
    ecc_memzero(Di, sizeof Di);
    ecc_memzero(h2Input, sizeof h2Input);
    ecc_memzero(di, sizeof di);
    ecc_memzero(t, sizeof t);
}

void ecc_oprf_ristretto255_sha512_ComputeCompositesFast(
    byte_t *M,
    byte_t *Z,
    const byte_t *k,
    const byte_t *B,
    const byte_t *Cs,
    const byte_t *Ds,
    const int m
) {
    // Bm = GG.SerializeElement(B)
    // seedDST = "Seed-" || contextString
    // compositeDST = "Composite-" || contextString
    //
    // h1Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(seedDST), 2) || seedDST
    // seed = Hash(h1Input)
    //
    // M = GG.Identity()
    // for i = 0 to m-1:
    //   Ci = GG.SerializeElement(Cs[i])
    //   Di = GG.SerializeElement(Ds[i])
    //   h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
    //             I2OSP(len(Ci), 2) || Ci ||
    //             I2OSP(len(Di), 2) || Di ||
    //             I2OSP(len(compositeDST), 2) || compositeDST
    //   di = GG.HashToScalar(h2Input)
    //   M = di * Cs[i] + M
    //
    // Z = k * M

    // seedDST = "Seed-" || contextString
    byte_t seedDST[100];
    byte_t seedDSTPrefix[4] = "Seed";
    const int seedDSTLen = createContextString(
        seedDST, MODE_VERIFIABLE,
        seedDSTPrefix, sizeof seedDSTPrefix
    );

    // compositeDST = "Composite-" || contextString
    byte_t compositeDST[100];
    byte_t compositeDSTPrefix[9] = "Composite";
    const int compositeDSTLen = createContextString(
        compositeDST, MODE_VERIFIABLE,
        compositeDSTPrefix, sizeof compositeDSTPrefix
    );

    // h1Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(seedDST), 2) || seedDST
    byte_t h1Input[256];
    int h1InputLen = 0;
    ecc_I2OSP(&h1Input[h1InputLen], ELEMENTSIZE, 2);
    h1InputLen += 2;
    ecc_concat2(&h1Input[h1InputLen], B, ELEMENTSIZE, NULL, 0);
    h1InputLen += ELEMENTSIZE;
    ecc_I2OSP(&h1Input[h1InputLen], seedDSTLen, 2);
    h1InputLen += 2;
    ecc_concat2(&h1Input[h1InputLen], seedDST, seedDSTLen, NULL, 0);
    h1InputLen += seedDSTLen;

    // seed = Hash(h1Input)
    byte_t seed[64];
    ecc_hash_sha512(seed, h1Input, h1InputLen);

    // M = GG.Identity()
    ecc_memzero(M, ELEMENTSIZE);

    // for i = 0 to m-1:
    //   Ci = GG.SerializeElement(Cs[i])
    //   Di = GG.SerializeElement(Ds[i])
    //   h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
    //             I2OSP(len(Ci), 2) || Ci ||
    //             I2OSP(len(Di), 2) || Di ||
    //             I2OSP(len(compositeDST), 2) || compositeDST
    //   di = GG.HashToScalar(h2Input)
    //   M = di * Cs[i] + M
    byte_t Ci[ELEMENTSIZE];
    byte_t Di[ELEMENTSIZE];
    byte_t h2Input[256];
    int h2InputLen = 0;
    byte_t di[SCALARSIZE];
    byte_t t[ELEMENTSIZE];
    for (int i = 0; i < m; i++) {
        // Ci = GG.SerializeElement(Cs[i])
        memcpy(Ci, &Cs[i * ELEMENTSIZE], ELEMENTSIZE);
        // Di = GG.SerializeElement(Ds[i])
        memcpy(Di, &Ds[i * ELEMENTSIZE], ELEMENTSIZE);

        ecc_I2OSP(&h2Input[h2InputLen], 64, 2);
        h2InputLen += 2;
        ecc_concat2(&h2Input[h2InputLen], seed, 64, NULL, 0);
        h2InputLen += 64;
        ecc_I2OSP(&h2Input[h2InputLen], i, 2);
        h2InputLen += 2;
        ecc_I2OSP(&h2Input[h2InputLen], ELEMENTSIZE, 2);
        h2InputLen += 2;
        ecc_concat2(&h2Input[h2InputLen], Ci, ELEMENTSIZE, NULL, 0);
        h2InputLen += ELEMENTSIZE;
        ecc_I2OSP(&h2Input[h2InputLen], ELEMENTSIZE, 2);
        h2InputLen += 2;
        ecc_concat2(&h2Input[h2InputLen], Di, ELEMENTSIZE, NULL, 0);
        h2InputLen += ELEMENTSIZE;
        ecc_I2OSP(&h2Input[h2InputLen], compositeDSTLen, 2);
        h2InputLen += 2;
        ecc_concat2(&h2Input[h2InputLen], compositeDST, compositeDSTLen, NULL, 0);
        h2InputLen += compositeDSTLen;

        // di = GG.HashToScalar(h2Input)
        ecc_oprf_ristretto255_sha512_HashToScalar(di, h2Input, h2InputLen, MODE_VERIFIABLE);

        // M = di * Cs[i] + M
        ecc_ristretto255_scalarmult(t, di, &Cs[i * ELEMENTSIZE]);
        ecc_ristretto255_add(M, t, M);
    }

    // Z = k * M
    ecc_ristretto255_scalarmult(Z, k, M);

    // stack memory cleanup
    ecc_memzero(h1Input, sizeof h1Input);
    ecc_memzero(seed, sizeof seed);
    ecc_memzero(Ci, sizeof Ci);
    ecc_memzero(Di, sizeof Di);
    ecc_memzero(h2Input, sizeof h2Input);
    ecc_memzero(di, sizeof di);
    ecc_memzero(t, sizeof t);
}

void ecc_oprf_ristretto255_sha512_BlindWithScalar(
    byte_t *blindedElement, // 32
    const byte_t *input, const int inputLen,
    const byte_t *blind,
    const int mode
) {
    byte_t P[ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_HashToGroup(P, input, inputLen, mode);
    ecc_ristretto255_scalarmult(blindedElement, blind, P);

    // stack memory cleanup
    ecc_memzero(P, sizeof P);
}

void ecc_oprf_ristretto255_sha512_Blind(
    byte_t *blindedElement, // 32
    byte_t *blind, // 32
    const byte_t *input, const int inputLen,
    const int mode
) {
    ecc_ristretto255_scalar_random(blind);
    ecc_oprf_ristretto255_sha512_BlindWithScalar(
        blindedElement,
        input, inputLen,
        blind,
        mode
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
    byte_t blindInverted[ELEMENTSIZE];
    ecc_ristretto255_scalar_invert(blindInverted, blind); // blind^(-1)
    ecc_ristretto255_scalarmult(unblindedElement, blindInverted, evaluatedElement);

    // stack memory cleanup
    ecc_memzero(blindInverted, sizeof blindInverted);
}

void ecc_oprf_ristretto255_sha512_Finalize(
    byte_t *output, // 64 bytes
    const byte_t *input, const int inputLen,
    const byte_t *blind,
    const byte_t *evaluatedElement,
    const byte_t *info, const int infoLen
) {
    // unblindedElement = Unblind(blind, evaluatedElement)
    //
    // finalizeDST = "Finalize-" || self.contextString
    // hashInput = I2OSP(len(input), 2) || input ||
    //             I2OSP(len(info), 2) || info ||
    //             I2OSP(len(unblindedElement), 2) || unblindedElement ||
    //             I2OSP(len(finalizeDST), 2) || finalizeDST
    // return Hash(hashInput)

    byte_t unblindedElement[ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_Unblind(unblindedElement, blind, evaluatedElement);

    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);

    // I2OSP(len(input), 2)
    byte_t tmp[2];
    ecc_I2OSP(tmp, inputLen, 2);
    crypto_hash_sha512_update(&st, tmp, 2);
    // input
    crypto_hash_sha512_update(&st, input, (unsigned long long) inputLen);
    // I2OSP(len(info), 2)
    ecc_I2OSP(tmp, infoLen, 2);
    crypto_hash_sha512_update(&st, tmp, 2);
    // info
    crypto_hash_sha512_update(&st, info, (unsigned long long) infoLen);
    // I2OSP(len(unblindedElement), 2)
    ecc_I2OSP(tmp, ELEMENTSIZE, 2);
    crypto_hash_sha512_update(&st, tmp, 2);
    // unblindedElement
    crypto_hash_sha512_update(&st, unblindedElement, ELEMENTSIZE);

    byte_t finalizeDST[100];
    byte_t finalizeDSTPrefix[8] = "Finalize";
    const int finalizeDSTLen = createContextString(
        finalizeDST, MODE_BASE,
        finalizeDSTPrefix, sizeof finalizeDSTPrefix
    );

    // I2OSP(len(finalizeDST), 2)
    ecc_I2OSP(tmp, finalizeDSTLen, 2);
    crypto_hash_sha512_update(&st, tmp, 2);
    // finalizeDST
    crypto_hash_sha512_update(&st, finalizeDST, (unsigned long long) finalizeDSTLen);

    // return Hash(hashInput)
    crypto_hash_sha512_final(&st, output);

    // stack memory cleanup
    ecc_memzero(unblindedElement, sizeof unblindedElement);
    ecc_memzero((byte_t *) &st, sizeof st);
}

int ecc_oprf_ristretto255_sha512_VerifyProof(
    const byte_t *A,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D,
    const byte_t *proofPtr
) {
    const Proof_t *proof = (const Proof_t *) proofPtr;

    // Cs = [C]
    // Ds = [D]
    //
    // (M, Z) = ComputeComposites(B, Cs, Ds)
    // c = GG.DeserializeScalar(proof.c)
    // s = GG.DeserializeScalar(proof.s)
    //
    // t2 = ((s * A) + (c * B))
    // t3 = ((s * M) + (c * Z))
    //
    // Bm = GG.SerializeElement(B)
    // a0 = GG.SerializeElement(M)
    // a1 = GG.SerializeElement(Z)
    // a2 = GG.SerializeElement(t2)
    // a3 = GG.SerializeElement(t3)
    //
    // challengeDST = "Challenge-" || contextString
    // h2Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(a0), 2) || a0 ||
    //           I2OSP(len(a1), 2) || a1 ||
    //           I2OSP(len(a2), 2) || a2 ||
    //           I2OSP(len(a3), 2) || a3 ||
    //           I2OSP(len(challengeDST), 2) || challengeDST
    //
    // expectedC = GG.HashToScalar(h2Input)
    //
    // return CT_EQUAL(expectedC, c)

    // (M, Z) = ComputeComposites(B, Cs, Ds)
    byte_t M[ELEMENTSIZE];
    byte_t Z[ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_ComputeComposites(
        M,
        Z,
        B,
        C,
        D,
        1
    );

    // c = GG.DeserializeScalar(proof.c)
    // s = GG.DeserializeScalar(proof.s)
    const byte_t *c = proof->c;
    const byte_t *s = proof->s;

    byte_t mul1[ELEMENTSIZE];
    byte_t mul2[ELEMENTSIZE];
    // t2 = ((s * A) + (c * B))
    byte_t t2[ELEMENTSIZE];
    ecc_ristretto255_scalarmult(mul1, s, A); // (s * A)
    ecc_ristretto255_scalarmult(mul2, c, B); // (c * B)
    ecc_ristretto255_add(t2, mul1, mul2);
    // t3 = ((s * M) + (c * Z))
    byte_t t3[ELEMENTSIZE];
    ecc_ristretto255_scalarmult(mul1, s, M); // (s * M)
    ecc_ristretto255_scalarmult(mul2, c, Z); // (c * Z)
    ecc_ristretto255_add(t3, mul1, mul2);

    // Bm = GG.SerializeElement(B)
    // a0 = GG.SerializeElement(M)
    // a1 = GG.SerializeElement(Z)
    // a2 = GG.SerializeElement(t2)
    // a3 = GG.SerializeElement(t3)
    const byte_t *Bm = B;
    const byte_t *a0 = M;
    const byte_t *a1 = Z;
    const byte_t *a2 = t2;
    const byte_t *a3 = t3;

    // challengeDST = "Challenge-" || contextString
    byte_t challengeDST[100];
    byte_t challengeDSTPrefix[9] = "Challenge";
    const int challengeDSTLen = createContextString(
        challengeDST, MODE_VERIFIABLE,
        challengeDSTPrefix, sizeof challengeDSTPrefix
    );

    // h2Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(a0), 2) || a0 ||
    //           I2OSP(len(a1), 2) || a1 ||
    //           I2OSP(len(a2), 2) || a2 ||
    //           I2OSP(len(a3), 2) || a3 ||
    //           I2OSP(len(challengeDST), 2) || challengeDST
    byte_t h2Input[256];
    int h2InputLen = 0;
    ecc_I2OSP(&h2Input[h2InputLen], ELEMENTSIZE, 2);
    h2InputLen += 2;
    ecc_concat2(&h2Input[h2InputLen], Bm, ELEMENTSIZE, NULL, 0);
    h2InputLen += ELEMENTSIZE;
    ecc_I2OSP(&h2Input[h2InputLen], ELEMENTSIZE, 2);
    h2InputLen += 2;
    ecc_concat2(&h2Input[h2InputLen], a0, ELEMENTSIZE, NULL, 0);
    h2InputLen += ELEMENTSIZE;
    ecc_I2OSP(&h2Input[h2InputLen], ELEMENTSIZE, 2);
    h2InputLen += 2;
    ecc_concat2(&h2Input[h2InputLen], a1, ELEMENTSIZE, NULL, 0);
    h2InputLen += ELEMENTSIZE;
    ecc_I2OSP(&h2Input[h2InputLen], ELEMENTSIZE, 2);
    h2InputLen += 2;
    ecc_concat2(&h2Input[h2InputLen], a2, ELEMENTSIZE, NULL, 0);
    h2InputLen += ELEMENTSIZE;
    ecc_I2OSP(&h2Input[h2InputLen], ELEMENTSIZE, 2);
    h2InputLen += 2;
    ecc_concat2(&h2Input[h2InputLen], a3, ELEMENTSIZE, NULL, 0);
    h2InputLen += ELEMENTSIZE;
    ecc_I2OSP(&h2Input[h2InputLen], challengeDSTLen, 2);
    h2InputLen += 2;
    ecc_concat2(&h2Input[h2InputLen], challengeDST, challengeDSTLen, NULL, 0);
    h2InputLen += challengeDSTLen;

    // expectedC = GG.HashToScalar(h2Input)
    byte_t expectedC[SCALARSIZE];
    ecc_oprf_ristretto255_sha512_HashToScalar(expectedC, h2Input, h2InputLen, MODE_VERIFIABLE);

    // stack memory cleanup
    ecc_memzero(M, sizeof M);
    ecc_memzero(Z, sizeof Z);
    ecc_memzero(mul1, sizeof mul1);
    ecc_memzero(mul2, sizeof mul2);
    ecc_memzero(t2, sizeof t2);
    ecc_memzero(t3, sizeof t3);
    ecc_memzero(h2Input, sizeof h2Input);

    // return CT_EQUAL(expectedC, c)
    if (ecc_compare(expectedC, c, SCALARSIZE) == 0)
        return 1;
    else
        return 0;
}

int ecc_oprf_ristretto255_sha512_VerifiableUnblind(
    byte_t *unblindedElement,
    const byte_t *blind,
    const byte_t *evaluatedElement,
    const byte_t *blindedElement,
    const byte_t *pkS,
    const byte_t *proof,
    const byte_t *info, const int infoLen
) {
    // context = "Context-" || contextString ||
    //           I2OSP(len(info), 2) || info
    // m = GG.HashToScalar(context)
    //
    // R = GG.DeserializeElement(blindedElement)
    // Z = GG.DeserializeElement(evaluatedElement)
    //
    // T = ScalarBaseMult(m)
    // U = T + pkS
    // if VerifyProof(G, U, Z, R, proof) == false:
    //   raise VerifyError
    //
    // N = blind^(-1) * Z
    // unblindedElement = GG.SerializeElement(N)

    // context = "Context-" || contextString ||
    //           I2OSP(len(info), 2) || info
    byte_t context[256];
    byte_t contextPrefix[7] = "Context";
    int contextLen = createContextString(
        context, MODE_VERIFIABLE,
        contextPrefix, sizeof contextPrefix
    );
    ecc_I2OSP(&context[contextLen], infoLen, 2);
    ecc_concat2(&context[contextLen + 2], info, infoLen, NULL, 0);
    contextLen += 2 + infoLen;

    // m = GG.HashToScalar(context)
    byte_t m[SCALARSIZE];
    ecc_oprf_ristretto255_sha512_HashToScalar(m, context, contextLen, MODE_VERIFIABLE);

    // R = GG.DeserializeElement(blindedElement)
    // Z = GG.DeserializeElement(evaluatedElement)
    const byte_t *R = blindedElement;
    const byte_t *Z = evaluatedElement;

    // T = ScalarBaseMult(m)
    byte_t T[ELEMENTSIZE];
    ecc_ristretto255_scalarmult_base(T, m);

    // U = T + pkS
    byte_t U[ELEMENTSIZE];
    ecc_ristretto255_add(U, T, pkS);

    // G is the group generator
    byte_t G[ELEMENTSIZE];
    ecc_ristretto255_generator(G);

    // if VerifyProof(G, U, Z, R, proof) == false:
    //   raise VerifyError
    if (ecc_oprf_ristretto255_sha512_VerifyProof(G, U, Z, R, proof) != 1) {
        // stack memory cleanup
        ecc_memzero(context, sizeof context);
        ecc_memzero(m, sizeof m);
        ecc_memzero(T, sizeof T);
        ecc_memzero(U, sizeof U);
        return -1;
    }

    // N = blind^(-1) * Z
    // unblindedElement = GG.SerializeElement(N)
    byte_t blindInverted[ELEMENTSIZE];
    ecc_ristretto255_scalar_invert(blindInverted, blind); // blind^(-1)
    ecc_ristretto255_scalarmult(unblindedElement, blindInverted, evaluatedElement);

    // stack memory cleanup
    ecc_memzero(context, sizeof context);
    ecc_memzero(m, sizeof m);
    ecc_memzero(T, sizeof T);
    ecc_memzero(U, sizeof U);
    ecc_memzero(blindInverted, sizeof blindInverted);

    return 0;
}

int ecc_oprf_ristretto255_sha512_VerifiableFinalize(
    byte_t *output,
    const byte_t *input, const int inputLen,
    const byte_t *blind,
    const byte_t *evaluatedElement,
    const byte_t *blindedElement,
    const byte_t *pkS,
    const byte_t *proof,
    const byte_t *info, const int infoLen
) {
    // unblindedElement = VerifiableUnblind(blind, evaluatedElement, blindedElement, pkS, proof, info)
    //
    // finalizeDST = "Finalize-" || contextString
    // hashInput = I2OSP(len(input), 2) || input ||
    //             I2OSP(len(info), 2) || info ||
    //             I2OSP(len(unblindedElement), 2) || unblindedElement ||
    //             I2OSP(len(finalizeDST), 2) || finalizeDST
    // return Hash(hashInput)

    byte_t unblindedElement[ELEMENTSIZE];
    int r = ecc_oprf_ristretto255_sha512_VerifiableUnblind(
        unblindedElement,
        blind,
        evaluatedElement,
        blindedElement,
        pkS,
        proof,
        info, infoLen
    );

    if (r != 0) {
        // stack memory cleanup
        ecc_memzero(unblindedElement, sizeof unblindedElement);
        return -1;
    }

    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);

    // I2OSP(len(input), 2)
    byte_t tmp[2];
    ecc_I2OSP(tmp, inputLen, 2);
    crypto_hash_sha512_update(&st, tmp, 2);
    // input
    crypto_hash_sha512_update(&st, input, (unsigned long long) inputLen);
    // I2OSP(len(info), 2)
    ecc_I2OSP(tmp, infoLen, 2);
    crypto_hash_sha512_update(&st, tmp, 2);
    // info
    crypto_hash_sha512_update(&st, info, (unsigned long long) infoLen);
    // I2OSP(len(unblindedElement), 2)
    ecc_I2OSP(tmp, ELEMENTSIZE, 2);
    crypto_hash_sha512_update(&st, tmp, 2);
    // unblindedElement
    crypto_hash_sha512_update(&st, unblindedElement, ELEMENTSIZE);

    byte_t finalizeDST[100];
    byte_t finalizeDSTPrefix[8] = "Finalize";
    const int finalizeDSTLen = createContextString(
        finalizeDST, MODE_VERIFIABLE,
        finalizeDSTPrefix, sizeof finalizeDSTPrefix
    );

    // I2OSP(len(finalizeDST), 2)
    ecc_I2OSP(tmp, finalizeDSTLen, 2);
    crypto_hash_sha512_update(&st, tmp, 2);
    // finalizeDST
    crypto_hash_sha512_update(&st, finalizeDST, (unsigned long long) finalizeDSTLen);

    // return Hash(hashInput)
    crypto_hash_sha512_final(&st, output);

    // stack memory cleanup
    ecc_memzero(unblindedElement, sizeof unblindedElement);
    ecc_memzero((byte_t *) &st, sizeof st);

    return 0;
}

void ecc_oprf_ristretto255_sha512_HashToGroupWithDST(
    byte_t *out,
    const byte_t *input, int inputLen,
    const byte_t *dst, int dstLen
) {
    byte_t expand_message[64];
    ecc_h2c_expand_message_xmd_sha512(expand_message, input, inputLen, dst, dstLen, 64);

    ecc_ristretto255_from_hash(out, expand_message);

    // stack memory cleanup
    ecc_memzero(expand_message, sizeof expand_message);
}

void ecc_oprf_ristretto255_sha512_HashToGroup(
    byte_t *out,
    const byte_t *input, const int inputLen,
    const int mode
) {
    byte_t DST[100];
    byte_t DSTPrefix[11] = "HashToGroup";
    const int DSTLen = createContextString(
        DST, mode,
        DSTPrefix, sizeof DSTPrefix
    );

    ecc_oprf_ristretto255_sha512_HashToGroupWithDST(out, input, inputLen, DST, DSTLen);
}

void ecc_oprf_ristretto255_sha512_HashToScalarWithDST(
    byte_t *out,
    const byte_t *input, int inputLen,
    const byte_t *dst, int dstLen
) {
    byte_t expand_message[64];
    ecc_h2c_expand_message_xmd_sha512(expand_message, input, inputLen, dst, dstLen, 64);

    ecc_ristretto255_scalar_reduce(out, expand_message);

    // stack memory cleanup
    ecc_memzero(expand_message, sizeof expand_message);
}

void ecc_oprf_ristretto255_sha512_HashToScalar(
    byte_t *out,
    const byte_t *input, const int inputLen,
    const int mode
) {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-4.1

    byte_t DST[100];
    byte_t DSTPrefix[12] = "HashToScalar";
    const int DSTLen = createContextString(
        DST, mode,
        DSTPrefix, sizeof DSTPrefix
    );

    ecc_oprf_ristretto255_sha512_HashToScalarWithDST(out, input, inputLen, DST, DSTLen);
}
