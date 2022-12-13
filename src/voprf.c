/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "voprf.h"
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

#define ELEMENTSIZE ecc_voprf_ristretto255_sha512_ELEMENTSIZE
#define SCALARSIZE ecc_voprf_ristretto255_sha512_SCALARSIZE

typedef struct {
    byte_t c[SCALARSIZE];
    byte_t s[SCALARSIZE];
} Proof_t;

static_assert(ecc_voprf_ristretto255_sha512_ELEMENTSIZE == ecc_ristretto255_ELEMENTSIZE, "");
static_assert(ecc_voprf_ristretto255_sha512_SCALARSIZE == ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_voprf_ristretto255_sha512_PROOFSIZE == 2 * ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_voprf_ristretto255_sha512_Nh == ecc_hash_sha512_HASHSIZE, "");

static_assert(sizeof(Proof_t) == ecc_voprf_ristretto255_sha512_PROOFSIZE, "");

static int createContextString(
    byte_t *contextString,
    const int mode,
    byte_t *prefix,
    const int prefixLen
) {
    // contextString = "${RFC_ID}-" || I2OSP(mode, 1) || I2OSP(suite_id, 2)

    byte_t rfcId[7] = "VOPRF10"; // TODO: change to "RFCXXXX", where XXXX is the final number
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

void ecc_voprf_ristretto255_sha512_GenerateProofWithScalar(
    byte_t *proofPtr,
    const byte_t *k,
    const byte_t *A,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D,
    const int m,
    const int mode,
    const byte_t *r
) {
    // (M, Z) = ComputeCompositesFast(k, B, C, D)
    //
    // r = G.RandomScalar()
    // t2 = r * A
    // t3 = r * M
    //
    // Bm = G.SerializeElement(B)
    // a0 = G.SerializeElement(M)
    // a1 = G.SerializeElement(Z)
    // a2 = G.SerializeElement(t2)
    // a3 = G.SerializeElement(t3)
    //
    // h2Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(a0), 2) || a0 ||
    //           I2OSP(len(a1), 2) || a1 ||
    //           I2OSP(len(a2), 2) || a2 ||
    //           I2OSP(len(a3), 2) || a3 ||
    //           "Challenge"
    //
    // c = G.HashToScalar(h2Input)
    // s = (r - c * k) mod p
    //
    // proof = [c, s]

    Proof_t *proof = (Proof_t *) proofPtr;

    // (M, Z) = ComputeCompositesFast(k, B, Cs, Ds)
    byte_t M[ELEMENTSIZE];
    byte_t Z[ELEMENTSIZE];
    ecc_voprf_ristretto255_sha512_ComputeCompositesFast(
        M, Z,
        k,
        B,
        C, D, m,
        mode
    );

    // r = G.RandomScalar()
    // t2 = r * A
    byte_t t2[ELEMENTSIZE];
    ecc_ristretto255_scalarmult(t2, r, A);
    // t3 = r * M
    byte_t t3[ELEMENTSIZE];
    ecc_ristretto255_scalarmult(t3, r, M);

    // Bm = G.SerializeElement(B)
    // a0 = G.SerializeElement(M)
    // a1 = G.SerializeElement(Z)
    // a2 = G.SerializeElement(t2)
    // a3 = G.SerializeElement(t3)
    const byte_t *Bm = B;
    const byte_t *a0 = M;
    const byte_t *a1 = Z;
    const byte_t *a2 = t2;
    const byte_t *a3 = t3;

    byte_t challengeString[9] = "Challenge";

    // h2Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(a0), 2) || a0 ||
    //           I2OSP(len(a1), 2) || a1 ||
    //           I2OSP(len(a2), 2) || a2 ||
    //           I2OSP(len(a3), 2) || a3 ||
    //           "Challenge"
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
    ecc_concat2(&h2Input[h2InputLen], challengeString, sizeof challengeString, NULL, 0);
    h2InputLen += sizeof challengeString;

    // c = G.HashToScalar(h2Input)
    byte_t c[SCALARSIZE];
    ecc_voprf_ristretto255_sha512_HashToScalar(c, h2Input, h2InputLen, mode);

    // s = (r - c * k) mod p
    byte_t t[SCALARSIZE];
    ecc_ristretto255_scalar_mul(t, c, k);
    byte_t s[SCALARSIZE];
    ecc_ristretto255_scalar_sub(s, r, t);

    // proof = [c, s]
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

void ecc_voprf_ristretto255_sha512_GenerateProof(
    byte_t *proof,
    const byte_t *k,
    const byte_t *A,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D,
    const int m,
    const int mode
) {
    byte_t r[SCALARSIZE];
    ecc_ristretto255_scalar_random(r);

    ecc_voprf_ristretto255_sha512_GenerateProofWithScalar(
        proof,
        k,
        A, B,
        C, D, m,
        mode,
        r
    );

    // stack memory cleanup
    ecc_memzero(r, sizeof r);
}

void ecc_voprf_ristretto255_sha512_ComputeCompositesFast(
    byte_t *M,
    byte_t *Z,
    const byte_t *k,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D,
    const int m,
    const int mode
) {
    // Bm = G.SerializeElement(B)
    // seedDST = "Seed-" || contextString
    //
    // h1Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(seedDST), 2) || seedDST
    // seed = Hash(h1Input)
    //
    // M = G.Identity()
    // for i in range(m):
    //   Ci = G.SerializeElement(C[i])
    //   Di = G.SerializeElement(D[i])
    //   h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
    //             I2OSP(len(Ci), 2) || Ci ||
    //             I2OSP(len(Di), 2) || Di ||
    //             "Composite"
    //
    //   di = G.HashToScalar(h2Input)
    //   M = di * C[i] + M
    //
    // Z = k * M

    // seedDST = "Seed-" || contextString
    byte_t seedDST[100];
    byte_t seedDSTPrefix[4] = "Seed";
    const int seedDSTLen = createContextString(
        seedDST, mode,
        seedDSTPrefix, sizeof seedDSTPrefix
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

    // M = G.Identity()
    ecc_memzero(M, ELEMENTSIZE);

    byte_t compositeString[9] = "Composite";

    // for i in range(m):
    //   Ci = G.SerializeElement(C[i])
    //   Di = G.SerializeElement(D[i])
    //   h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
    //             I2OSP(len(Ci), 2) || Ci ||
    //             I2OSP(len(Di), 2) || Di ||
    //             "Composite"
    //
    //   di = G.HashToScalar(h2Input)
    //   M = di * C[i] + M
    byte_t Ci[ELEMENTSIZE];
    byte_t Di[ELEMENTSIZE];
    byte_t h2Input[256];
    int h2InputLen = 0;
    byte_t di[SCALARSIZE];
    byte_t t[ELEMENTSIZE];
    for (int i = 0; i < m; i++) {
        // Ci = G.SerializeElement(Cs[i])
        memcpy(Ci, &C[i * ELEMENTSIZE], ELEMENTSIZE);
        // Di = G.SerializeElement(Ds[i])
        memcpy(Di, &D[i * ELEMENTSIZE], ELEMENTSIZE);

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
        ecc_concat2(&h2Input[h2InputLen], compositeString, sizeof compositeString, NULL, 0);
        h2InputLen += sizeof compositeString;

        // di = G.HashToScalar(h2Input)
        ecc_voprf_ristretto255_sha512_HashToScalar(di, h2Input, h2InputLen, mode);

        // M = di * C[i] + M
        ecc_ristretto255_scalarmult(t, di, &C[i * ELEMENTSIZE]);
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

int ecc_voprf_ristretto255_sha512_VerifyProof(
    const byte_t *A,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D,
    const int m,
    const int mode,
    const byte_t *proofPtr
) {
    const Proof_t *proof = (const Proof_t *) proofPtr;

    // (M, Z) = ComputeComposites(B, C, D)
    // c = proof[0]
    // s = proof[1]
    //
    // t2 = ((s * A) + (c * B))
    // t3 = ((s * M) + (c * Z))
    //
    // Bm = G.SerializeElement(B)
    // a0 = G.SerializeElement(M)
    // a1 = G.SerializeElement(Z)
    // a2 = G.SerializeElement(t2)
    // a3 = G.SerializeElement(t3)
    //
    // h2Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(a0), 2) || a0 ||
    //           I2OSP(len(a1), 2) || a1 ||
    //           I2OSP(len(a2), 2) || a2 ||
    //           I2OSP(len(a3), 2) || a3 ||
    //           "Challenge"
    //
    // expectedC = G.HashToScalar(h2Input)
    //
    // return (expectedC == c)

    // (M, Z) = ComputeComposites(B, C, D)
    byte_t M[ELEMENTSIZE];
    byte_t Z[ELEMENTSIZE];
    ecc_voprf_ristretto255_sha512_ComputeComposites(
        M, Z,
        B,
        C, D, m,
        mode
    );

    // c = proof[0]
    // s = proof[1]
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

    // Bm = G.SerializeElement(B)
    // a0 = G.SerializeElement(M)
    // a1 = G.SerializeElement(Z)
    // a2 = G.SerializeElement(t2)
    // a3 = G.SerializeElement(t3)
    const byte_t *Bm = B;
    const byte_t *a0 = M;
    const byte_t *a1 = Z;
    const byte_t *a2 = t2;
    const byte_t *a3 = t3;

    byte_t challengeString[9] = "Challenge";

    // h2Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(a0), 2) || a0 ||
    //           I2OSP(len(a1), 2) || a1 ||
    //           I2OSP(len(a2), 2) || a2 ||
    //           I2OSP(len(a3), 2) || a3 ||
    //           "Challenge"
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
    ecc_concat2(&h2Input[h2InputLen], challengeString, sizeof challengeString, NULL, 0);
    h2InputLen += sizeof challengeString;

    // expectedC = G.HashToScalar(h2Input)
    byte_t expectedC[SCALARSIZE];
    ecc_voprf_ristretto255_sha512_HashToScalar(expectedC, h2Input, h2InputLen, mode);

    // stack memory cleanup
    ecc_memzero(M, sizeof M);
    ecc_memzero(Z, sizeof Z);
    ecc_memzero(mul1, sizeof mul1);
    ecc_memzero(mul2, sizeof mul2);
    ecc_memzero(t2, sizeof t2);
    ecc_memzero(t3, sizeof t3);
    ecc_memzero(h2Input, sizeof h2Input);

    // return (expectedC == c)
    if (ecc_compare(expectedC, c, SCALARSIZE) == 0)
        return 1;
    else
        return 0;
}

void ecc_voprf_ristretto255_sha512_ComputeComposites(
    byte_t *M,
    byte_t *Z,
    const byte_t *B,
    const byte_t *C,
    const byte_t *D,
    const int m,
    const int mode
) {
    // Bm = G.SerializeElement(B)
    // seedDST = "Seed-" || contextString
    //
    // h1Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(seedDST), 2) || seedDST
    // seed = Hash(h1Input)
    //
    // M = G.Identity()
    // Z = G.Identity()
    // for i in range(m):
    //   Ci = G.SerializeElement(C[i])
    //   Di = G.SerializeElement(D[i])
    //   h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
    //             I2OSP(len(Ci), 2) || Ci ||
    //             I2OSP(len(Di), 2) || Di ||
    //             "Composite"
    //
    //   di = G.HashToScalar(h2Input)
    //   M = di * C[i] + M
    //   Z = di * D[i] + Z
    //

    // seedDST = "Seed-" || contextString
    byte_t seedDST[100];
    byte_t seedDSTPrefix[4] = "Seed";
    const int seedDSTLen = createContextString(
        seedDST, mode,
        seedDSTPrefix, sizeof seedDSTPrefix
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

    byte_t compositeString[9] = "Composite";

    // M = G.Identity()
    ecc_memzero(M, ELEMENTSIZE);
    // Z = G.Identity()
    ecc_memzero(Z, ELEMENTSIZE);

    // for i = 0 to m-1:
    //   Ci = G.SerializeElement(C[i])
    //   Di = G.SerializeElement(D[i])
    //   h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
    //             I2OSP(len(Ci), 2) || Ci ||
    //             I2OSP(len(Di), 2) || Di ||
    //             "Composite"
    //
    //   di = G.HashToScalar(h2Input)
    //   M = di * C[i] + M
    //   Z = di * D[i] + Z
    byte_t Ci[ELEMENTSIZE];
    byte_t Di[ELEMENTSIZE];
    byte_t h2Input[256];
    int h2InputLen = 0;
    byte_t di[SCALARSIZE];
    byte_t t[ELEMENTSIZE];
    for (int i = 0; i < m; i++) {
        // Ci = GG.SerializeElement(Cs[i])
        memcpy(Ci, &C[i * ELEMENTSIZE], ELEMENTSIZE);
        // Di = GG.SerializeElement(Ds[i])
        memcpy(Di, &D[i * ELEMENTSIZE], ELEMENTSIZE);

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
        ecc_concat2(&h2Input[h2InputLen], compositeString, sizeof compositeString, NULL, 0);
        h2InputLen += sizeof compositeString;

        // di = G.HashToScalar(h2Input)
        ecc_voprf_ristretto255_sha512_HashToScalar(di, h2Input, h2InputLen, mode);

        // M = di * C[i] + M
        ecc_ristretto255_scalarmult(t, di, &C[i * ELEMENTSIZE]);
        ecc_ristretto255_add(M, t, M);
        // Z = di * D[i] + Z
        ecc_ristretto255_scalarmult(t, di, &D[i * ELEMENTSIZE]);
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

void ecc_voprf_ristretto255_sha512_HashToGroupWithDST(
    byte_t *out,
    const byte_t *input, const int inputLen,
    const byte_t *dst, const int dstLen
) {
    byte_t expand_message[64];
    ecc_h2c_expand_message_xmd_sha512(expand_message, input, inputLen, dst, dstLen, 64);

    ecc_ristretto255_from_hash(out, expand_message);

    // stack memory cleanup
    ecc_memzero(expand_message, sizeof expand_message);
}

void ecc_voprf_ristretto255_sha512_HashToGroup(
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

    ecc_voprf_ristretto255_sha512_HashToGroupWithDST(out, input, inputLen, DST, DSTLen);
}

void ecc_voprf_ristretto255_sha512_HashToScalarWithDST(
    byte_t *out,
    const byte_t *input, const int inputLen,
    const byte_t *dst, const int dstLen
) {
    byte_t expand_message[64];
    ecc_h2c_expand_message_xmd_sha512(expand_message, input, inputLen, dst, dstLen, 64);

    ecc_ristretto255_scalar_reduce(out, expand_message);

    // stack memory cleanup
    ecc_memzero(expand_message, sizeof expand_message);
}

void ecc_voprf_ristretto255_sha512_HashToScalar(
    byte_t *out,
    const byte_t *input, const int inputLen,
    const int mode
) {
    byte_t DST[100];
    byte_t DSTPrefix[12] = "HashToScalar";
    const int DSTLen = createContextString(
        DST, mode,
        DSTPrefix, sizeof DSTPrefix
    );

    ecc_voprf_ristretto255_sha512_HashToScalarWithDST(out, input, inputLen, DST, DSTLen);
}
