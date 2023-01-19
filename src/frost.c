/*
 * Copyright (c) 2022-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "frost.h"
#include <string.h>
#include <assert.h>
#include "util.h"
#include "hash.h"
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

#define SCALARSIZE ecc_frost_ristretto255_sha512_SCALARSIZE // 32
#define ELEMENTSIZE ecc_frost_ristretto255_sha512_ELEMENTSIZE // 32

typedef struct {
    byte_t x[SCALARSIZE];
    byte_t y[SCALARSIZE];
} Point_t;

typedef struct {
    byte_t identifier[SCALARSIZE];
    byte_t hiding_nonce_commitment[ELEMENTSIZE];
    byte_t binding_nonce_commitment[ELEMENTSIZE];
} Commitment_t;

typedef struct {
    byte_t identifier[SCALARSIZE];
    byte_t binding_factor[SCALARSIZE];
} BindingFactor_t;

typedef struct {
    byte_t R[ecc_ristretto255_ELEMENTSIZE];
    byte_t z[ecc_ristretto255_SCALARSIZE];
} Signature_t;

typedef struct {
    byte_t hiding_nonce[ecc_ristretto255_SCALARSIZE];
    byte_t binding_nonce[ecc_ristretto255_SCALARSIZE];
} NoncePair_t;

typedef struct {
    byte_t hiding_nonce_commitment[ecc_ristretto255_ELEMENTSIZE];
    byte_t binding_nonce_commitment[ecc_ristretto255_ELEMENTSIZE];
} NonceCommitmentPair_t;

static_assert(ecc_frost_ristretto255_sha512_SCALARSIZE == ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_ELEMENTSIZE == ecc_ristretto255_ELEMENTSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_POINTSIZE == 2 * ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_COMMITMENTSIZE == ecc_ristretto255_SCALARSIZE + 2 * ecc_ristretto255_ELEMENTSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE == 2 * ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_SECRETKEYSIZE == ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_PUBLICKEYSIZE == ecc_ristretto255_ELEMENTSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_SIGNATURESIZE == 2 * ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_NONCEPAIRSIZE == 2 * ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE == 2 * ecc_ristretto255_ELEMENTSIZE, "");

static_assert(sizeof(Point_t) == ecc_frost_ristretto255_sha512_POINTSIZE, "");
static_assert(sizeof(Commitment_t) == ecc_frost_ristretto255_sha512_COMMITMENTSIZE, "");
static_assert(sizeof(BindingFactor_t) == ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE, "");
static_assert(sizeof(Signature_t) == ecc_frost_ristretto255_sha512_SIGNATURESIZE, "");
static_assert(sizeof(NoncePair_t) == ecc_frost_ristretto255_sha512_NONCEPAIRSIZE, "");
static_assert(sizeof(NonceCommitmentPair_t) == ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE, "");

static int power(int x, int n) {
    int r = 1;

    for (int i = 0; i < n; i++) {
        r = r * x;
    }

    return r;
}

void ecc_frost_ristretto255_sha512_nonce_generate_with_randomness(
    byte_t *nonce,
    const byte_t *secret,
    const byte_t *random_bytes
) {
    // random_bytes = random_bytes(32)
    // secret_enc = G.SerializeScalar(secret)
    // return H3(random_bytes || secret_enc)

    ecc_frost_ristretto255_sha512_H3_2(
        nonce,
        random_bytes, 32,
        secret, SCALARSIZE
    );
}

void ecc_frost_ristretto255_sha512_nonce_generate(
    byte_t *nonce,
    const byte_t *secret
) {
    // random_bytes = random_bytes(32)
    // secret_enc = G.SerializeScalar(secret)
    // return H3(random_bytes || secret_enc)

    byte_t random_bytes[SCALARSIZE];
    ecc_randombytes(random_bytes, SCALARSIZE);

    ecc_frost_ristretto255_sha512_nonce_generate_with_randomness(
        nonce,
        secret,
        random_bytes
    );

    // cleanup stack memory
    ecc_memzero(random_bytes, sizeof random_bytes);
}

void ecc_frost_ristretto255_sha512_derive_interpolating_value(
    byte_t *L_i,
    const byte_t *x_i,
    const byte_t *L, int L_len
) {
    byte_t numerator[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t denominator[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};

    byte_t t[ecc_frost_ristretto255_sha512_SCALARSIZE];

    for (int n = 0; n < L_len; n++) {
        const byte_t *x_j = &L[n * ecc_frost_ristretto255_sha512_SCALARSIZE];
        if (ecc_compare(x_j, x_i, ecc_frost_ristretto255_sha512_SCALARSIZE) == 0) continue;

        // numerator *= x_j
        // denominator *= x_j - x_i

        ecc_ristretto255_scalar_mul(numerator, numerator, x_j);

        ecc_ristretto255_scalar_sub(t, x_j, x_i);
        ecc_ristretto255_scalar_mul(denominator, denominator, t);
    }

    // L_i = numerator / denominator
    byte_t denominator_inv[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_ristretto255_scalar_invert(denominator_inv, denominator);
    ecc_ristretto255_scalar_mul(L_i, numerator, denominator_inv);

    // cleanup stack memory
    ecc_memzero(numerator, sizeof numerator);
    ecc_memzero(denominator, sizeof denominator);
    ecc_memzero(t, sizeof t);
    ecc_memzero(denominator_inv, sizeof denominator_inv);
}

void ecc_frost_ristretto255_sha512_derive_interpolating_value_with_points(
    byte_t *L_i,
    const byte_t *x_i,
    const byte_t *L, int L_len
) {
    byte_t numerator[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t denominator[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};

    byte_t t[ecc_frost_ristretto255_sha512_SCALARSIZE];

    for (int n = 0; n < L_len; n++) {
        const Point_t *point = (const Point_t *) &L[n * ecc_frost_ristretto255_sha512_POINTSIZE];
        const byte_t *x_j = point->x;
        if (ecc_compare(x_j, x_i, ecc_frost_ristretto255_sha512_SCALARSIZE) == 0) continue;

        // numerator *= x_j
        // denominator *= x_j - x_i

        ecc_ristretto255_scalar_mul(numerator, numerator, x_j);

        ecc_ristretto255_scalar_sub(t, x_j, x_i);
        ecc_ristretto255_scalar_mul(denominator, denominator, t);
    }

    // L_i = numerator / denominator
    byte_t denominator_inv[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_ristretto255_scalar_invert(denominator_inv, denominator);
    ecc_ristretto255_scalar_mul(L_i, numerator, denominator_inv);

    // cleanup stack memory
    ecc_memzero(numerator, sizeof numerator);
    ecc_memzero(denominator, sizeof denominator);
    ecc_memzero(t, sizeof t);
    ecc_memzero(denominator_inv, sizeof denominator_inv);
}

void ecc_frost_ristretto255_sha512_encode_group_commitment_list(
    byte_t *out,
    const byte_t *commitment_list, const int commitment_list_len
) {
    // encoded_group_commitment = nil
    // for (identifier, hiding_nonce_commitment, binding_nonce_commitment) in commitment_list:
    //   encoded_commitment = G.SerializeScalar(identifier) ||
    //                        G.SerializeElement(hiding_nonce_commitment) ||
    //                        G.SerializeElement(binding_nonce_commitment)
    //   encoded_group_commitment = encoded_group_commitment || encoded_commitment
    // return encoded_group_commitment

    // NOTE: this is the same as returning `commitment_list`
    memcpy(out, commitment_list, commitment_list_len * ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
}

void ecc_frost_ristretto255_sha512_participants_from_commitment_list(
    byte_t *identifiers,
    const byte_t *commitment_list, const int commitment_list_len
) {
    // identifiers = []
    // for (identifier, _, _) in commitment_list:
    //   identifiers.append(identifier)
    // return identifiers

    for (int i = 0; i < commitment_list_len; i++ ) {
        const int pos = i * ecc_frost_ristretto255_sha512_COMMITMENTSIZE;
        const Commitment_t *comm = (const Commitment_t *) &commitment_list[pos];

        memcpy(&identifiers[i * SCALARSIZE], comm->identifier, SCALARSIZE);
    }
}

int ecc_frost_ristretto255_sha512_binding_factor_for_participant(
    byte_t *binding_factor,
    const byte_t *binding_factor_list, const int binding_factor_list_len,
    const byte_t *identifier
) {
    // for (i, binding_factor) in binding_factor_list:
    //   if identifier == i:
    //     return binding_factor
    // raise "invalid participant"

    for (int i = 0; i < binding_factor_list_len; i++) {
        const int pos = i * ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE;
        const BindingFactor_t *factor = (const BindingFactor_t *) &binding_factor_list[pos];

        if (ecc_compare(identifier, factor->identifier, SCALARSIZE) == 0) {
            memcpy(binding_factor, factor->binding_factor, SCALARSIZE);
            return 0;
        }
    }

    return -1;
}

void ecc_frost_ristretto255_sha512_compute_binding_factors(
    byte_t *binding_factor_list,
    const byte_t *commitment_list, const int commitment_list_len,
    const byte_t *msg, const int msg_len
) {
    // msg_hash = H4(msg)
    // encoded_commitment_hash = H5(encode_group_commitment_list(commitment_list))
    // rho_input_prefix = msg_hash || encoded_commitment_hash
    //
    // binding_factor_list = []
    // for (identifier, hiding_nonce_commitment, binding_nonce_commitment) in commitment_list:
    //   rho_input = rho_input_prefix || G.SerializeScalar(identifier)
    //   binding_factor = H1(rho_input)
    //   binding_factor_list.append((identifier, binding_factor))
    // return binding_factor_list

    // msg_hash = H4(msg)
    byte_t msg_hash[64];
    ecc_frost_ristretto255_sha512_H4(msg_hash, msg, msg_len);

    // encoded_commitment_hash = H5(encode_group_commitment_list(commitment_list))
    byte_t encoded_commitment_hash[64];
    ecc_frost_ristretto255_sha512_H5(
        encoded_commitment_hash,
        commitment_list, commitment_list_len * ecc_frost_ristretto255_sha512_COMMITMENTSIZE // encode_group_commitment_list is the identity
    );

    // rho_input_prefix = msg_hash || encoded_commitment_hash
    byte_t rho_input_prefix[128];
    ecc_concat2(
        rho_input_prefix,
        msg_hash, sizeof msg_hash,
        encoded_commitment_hash, sizeof encoded_commitment_hash
    );

    // binding_factor_list = []
    // for (identifier, hiding_nonce_commitment, binding_nonce_commitment) in commitment_list:
    //   rho_input = rho_input_prefix || G.SerializeScalar(identifier)
    //   binding_factor = H1(rho_input)
    //   binding_factor_list.append((identifier, binding_factor))
    byte_t rho_input[160];
    for (int i = 0; i < commitment_list_len; i++) {
        const Commitment_t *comm = (const Commitment_t *) &commitment_list[i * ecc_frost_ristretto255_sha512_COMMITMENTSIZE];
        BindingFactor_t *fact = (BindingFactor_t *) &binding_factor_list[i * ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE];

        // rho_input = rho_input_prefix || G.SerializeScalar(identifier)
        ecc_concat2(
            rho_input,
            rho_input_prefix, sizeof rho_input_prefix,
            comm->identifier, SCALARSIZE
        );

#if ECC_LOG
        ecc_log("frost:compute_binding_factors:rho_input", rho_input, sizeof rho_input);
#endif

        memcpy(fact->identifier, comm->identifier, SCALARSIZE);
        ecc_frost_ristretto255_sha512_H1(
            fact->binding_factor,
            rho_input, sizeof rho_input
        );
    }

    // cleanup stack memory
    ecc_memzero(msg_hash, sizeof msg_hash);
    ecc_memzero(encoded_commitment_hash, sizeof encoded_commitment_hash);
    ecc_memzero(rho_input, sizeof rho_input);
}

void ecc_frost_ristretto255_sha512_compute_group_commitment(
    byte_t *group_comm,
    const byte_t *commitment_list, int commitment_list_len,
    const byte_t *binding_factor_list, int binding_factor_list_len
) {
    // group_commitment = G.Identity()
    // for (identifier, hiding_nonce_commitment, binding_nonce_commitment) in commitment_list:
    //   binding_factor = binding_factor_for_participant(binding_factors, identifier)
    //   group_commitment = group_commitment +
    //                      hiding_nonce_commitment + G.ScalarMult(binding_nonce_commitment, binding_factor)
    // return group_commitment

    // group_commitment = G.Identity()
    ecc_memzero(group_comm, ELEMENTSIZE);

    // for (identifier, hiding_nonce_commitment, binding_nonce_commitment) in commitment_list:
    //   binding_factor = binding_factor_for_participant(binding_factors, identifier)
    //   group_commitment = group_commitment +
    //                      hiding_nonce_commitment + G.ScalarMult(binding_nonce_commitment, binding_factor)
    byte_t T[ecc_ristretto255_ELEMENTSIZE];
    for (int i = 0; i < commitment_list_len; i++) {
        const int pos = i * ecc_frost_ristretto255_sha512_COMMITMENTSIZE;
        const Commitment_t *comm = (const Commitment_t *) &commitment_list[pos];

        // binding_factor = binding_factor_for_participant(binding_factors, identifier)
        byte_t binding_factor[SCALARSIZE];
        ecc_frost_ristretto255_sha512_binding_factor_for_participant(
            binding_factor,
            binding_factor_list, binding_factor_list_len,
            comm->identifier
        );

        // group_commitment = group_commitment +
        //                    hiding_nonce_commitment + G.ScalarMult(binding_nonce_commitment, binding_factor)
        ecc_ristretto255_scalarmult(T, binding_factor, comm->binding_nonce_commitment);
        ecc_ristretto255_add(T, comm->hiding_nonce_commitment, T);
        ecc_ristretto255_add(group_comm, group_comm, T);
    }

    // cleanup stack memory
    ecc_memzero(T, sizeof T);
}

void ecc_frost_ristretto255_sha512_compute_challenge(
    byte_t *challenge,
    const byte_t *group_commitment,
    const byte_t *group_public_key,
    const byte_t *msg, const int msg_len
) {
    ecc_frost_ristretto255_sha512_H2_3(
        challenge,
        group_commitment, ELEMENTSIZE,
        group_public_key, ELEMENTSIZE,
        msg, msg_len
    );
}

void ecc_frost_ristretto255_sha512_commit_with_randomness(
    byte_t *nonce_ptr,
    byte_t *comm_ptr,
    const byte_t *sk_i,
    const byte_t *hiding_nonce_randomness,
    const byte_t *binding_nonce_randomness
) {
    // hiding_nonce = nonce_generate(sk_i)
    // binding_nonce = nonce_generate(sk_i)
    // hiding_nonce_commitment = G.ScalarBaseMult(hiding_nonce)
    // binding_nonce_commitment = G.ScalarBaseMult(binding_nonce)
    // nonce = (hiding_nonce, binding_nonce)
    // comm = (hiding_nonce_commitment, binding_nonce_commitment)
    // return (nonce, comm)

    NoncePair_t *nonce = (NoncePair_t *) nonce_ptr;
    NonceCommitmentPair_t *comm = (NonceCommitmentPair_t *) comm_ptr;

    // hiding_nonce = nonce_generate(sk_i)
    ecc_frost_ristretto255_sha512_nonce_generate_with_randomness(
        nonce->hiding_nonce,
        sk_i,
        hiding_nonce_randomness
    );
    // binding_nonce = nonce_generate(sk_i)
    ecc_frost_ristretto255_sha512_nonce_generate_with_randomness(
        nonce->binding_nonce,
        sk_i,
        binding_nonce_randomness
    );

    // hiding_nonce_commitment = G.ScalarBaseMult(hiding_nonce)
    // binding_nonce_commitment = G.ScalarBaseMult(binding_nonce)
    ecc_ristretto255_scalarmult_base(comm->hiding_nonce_commitment, nonce->hiding_nonce);
    ecc_ristretto255_scalarmult_base(comm->binding_nonce_commitment, nonce->binding_nonce);
}

void ecc_frost_ristretto255_sha512_commit(
    byte_t *nonce,
    byte_t *comm,
    const byte_t *sk_i
) {
    byte_t hiding_nonce_randomness[32];
    ecc_randombytes(hiding_nonce_randomness, sizeof hiding_nonce_randomness);
    byte_t binding_nonce_randomness[32];
    ecc_randombytes(binding_nonce_randomness, sizeof binding_nonce_randomness);

    ecc_frost_ristretto255_sha512_commit_with_randomness(
        nonce,
        comm,
        sk_i,
        hiding_nonce_randomness,
        binding_nonce_randomness
    );

    // cleanup stack memory
    ecc_memzero(hiding_nonce_randomness, sizeof hiding_nonce_randomness);
    ecc_memzero(binding_nonce_randomness, sizeof binding_nonce_randomness);
}

void ecc_frost_ristretto255_sha512_sign(
    byte_t *sig_share,
    const byte_t *identifier,
    const byte_t *sk_i,
    const byte_t *group_public_key,
    const byte_t *nonce_i_ptr,
    const byte_t *msg, const int msg_len,
    const byte_t *commitment_list, const int commitment_list_len
) {
    // # Compute the binding factor(s)
    // binding_factor_list = compute_binding_factors(commitment_list, msg)
    // binding_factor = binding_factor_for_participant(binding_factor_list, identifier)
    //
    // # Compute the group commitment
    // group_commitment = compute_group_commitment(commitment_list, binding_factor_list)
    //
    // # Compute Lagrange coefficient
    // participant_list = participants_from_commitment_list(commitment_list)
    // lambda_i = derive_lagrange_coefficient(identifier, participant_list)
    //
    // # Compute the per-message challenge
    // challenge = compute_challenge(group_commitment, group_public_key, msg)
    //
    // # Compute the signature share
    // (hiding_nonce, binding_nonce) = nonce_i
    // sig_share = hiding_nonce + (binding_nonce * binding_factor) + (lambda_i * sk_i * challenge)
    //
    // return sig_share

    // # Compute the binding factor(s)
    // binding_factor_list = compute_binding_factors(commitment_list, msg)
    // TODO: fix for variable size, for now 100 to not block
    byte_t binding_factor_list[100 * ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE];
    ecc_frost_ristretto255_sha512_compute_binding_factors(
        binding_factor_list,
        commitment_list, commitment_list_len,
        msg, msg_len
    );
    // binding_factor = binding_factor_for_participant(binding_factor_list, identifier)
    byte_t binding_factor[SCALARSIZE];
    ecc_frost_ristretto255_sha512_binding_factor_for_participant(
        binding_factor,
        binding_factor_list, commitment_list_len,
        identifier
    );

    // # Compute the group commitment
    // group_commitment = compute_group_commitment(commitment_list, binding_factor_list)
    byte_t group_commitment[ELEMENTSIZE];
    ecc_frost_ristretto255_sha512_compute_group_commitment(
        group_commitment,
        commitment_list, commitment_list_len,
        binding_factor_list, commitment_list_len
    );

    // # Compute Lagrange coefficient
    // participant_list = participants_from_commitment_list(commitment_list)
    // TODO: fix for variable size, for now 100 to not block
    byte_t participant_list[100 * SCALARSIZE];
    ecc_frost_ristretto255_sha512_participants_from_commitment_list(
        participant_list,
        commitment_list, commitment_list_len
    );
    // lambda_i = derive_lagrange_coefficient(identifier, participant_list)
    byte_t lambda_i[SCALARSIZE];
    ecc_frost_ristretto255_sha512_derive_interpolating_value(
        lambda_i,
        identifier,
        participant_list, commitment_list_len
    );

    // # Compute the per-message challenge
    // challenge = compute_challenge(group_commitment, group_public_key, msg)
    byte_t challenge[SCALARSIZE];
    ecc_frost_ristretto255_sha512_compute_challenge(
        challenge,
        group_commitment,
        group_public_key,
        msg, msg_len
    );

    // # Compute the signature share
    // (hiding_nonce, binding_nonce) = nonce_i
    const NoncePair_t *nonce_i = (const NoncePair_t *) nonce_i_ptr;
    // sig_share = hiding_nonce + (binding_nonce * binding_factor) + (lambda_i * sk_i * challenge)
    byte_t t1[ecc_ristretto255_SCALARSIZE];
    byte_t t2[ecc_ristretto255_SCALARSIZE];
    ecc_ristretto255_scalar_mul(t1, lambda_i, sk_i);
    ecc_ristretto255_scalar_mul(t1, t1, challenge); // (lambda_i * sk_i * challenge)
    ecc_ristretto255_scalar_mul(t2, nonce_i->binding_nonce, binding_factor); // (binding_nonce * binding_factor)
    ecc_ristretto255_scalar_add(sig_share, nonce_i->hiding_nonce, t1);
    ecc_ristretto255_scalar_add(sig_share, sig_share, t2);

    // cleanup stack memory
    ecc_memzero(binding_factor_list, sizeof binding_factor_list);
    ecc_memzero(binding_factor, sizeof binding_factor);
    ecc_memzero(group_commitment, sizeof group_commitment);
    ecc_memzero(participant_list, sizeof participant_list);
    ecc_memzero(lambda_i, sizeof lambda_i);
    ecc_memzero(challenge, sizeof challenge);
    ecc_memzero(t1, sizeof t1);
    ecc_memzero(t2, sizeof t2);
}

void ecc_frost_ristretto255_sha512_aggregate(
    byte_t *signature_ptr,
    const byte_t *commitment_list, const int commitment_list_len,
    const byte_t *msg, const int msg_len,
    const byte_t *sig_shares, const int sig_shares_len
) {
    // TODO: refactor, using 100 to not block
    byte_t binding_factor_list[100 * ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE];
    ecc_frost_ristretto255_sha512_compute_binding_factors(
        binding_factor_list,
        commitment_list, commitment_list_len,
        msg, sizeof msg_len
    );

    byte_t group_commitment[ELEMENTSIZE];
    ecc_frost_ristretto255_sha512_compute_group_commitment(
        group_commitment,
        commitment_list, commitment_list_len,
        binding_factor_list, commitment_list_len
    );

    Signature_t *signature = (Signature_t *) signature_ptr;

    byte_t z[SCALARSIZE] = {0};
    for (int i = 0; i < sig_shares_len; i++) {
        const int pos = i * SCALARSIZE;
        const byte_t *z_i = &sig_shares[pos];
        ecc_ristretto255_scalar_add(z, z, z_i);
    }

    memcpy(signature->R, group_commitment, ELEMENTSIZE);
    memcpy(signature->z, z, sizeof z);

    // cleanup stack memory
    ecc_memzero(binding_factor_list, sizeof binding_factor_list);
    ecc_memzero(group_commitment, sizeof group_commitment);
    ecc_memzero(z, sizeof z);
}

int ecc_frost_ristretto255_sha512_verify_signature_share(
    const byte_t *identifier,
    const byte_t *public_key_share_i,
    const byte_t *comm_i_ptr,
    const byte_t *sig_share_i,
    const byte_t *commitment_list, const int commitment_list_len,
    const byte_t *group_public_key,
    const byte_t *msg, const int msg_len
) {
    // # Compute the binding factors
    // binding_factor_list = compute_binding_factors(commitment_list, msg)
    // binding_factor = binding_factor_for_participant(binding_factor_list, identifier)
    //
    // # Compute the group commitment
    // group_commitment = compute_group_commitment(commitment_list, binding_factor_list)
    //
    // # Compute the commitment share
    // (hiding_nonce_commitment, binding_nonce_commitment) = comm_i
    // comm_share = hiding_nonce_commitment + G.ScalarMult(binding_nonce_commitment, binding_factor)
    //
    // # Compute the challenge
    // challenge = compute_challenge(group_commitment, group_public_key, msg)
    //
    // # Compute Lagrange coefficient
    // participant_list = participants_from_commitment_list(commitment_list)
    // lambda_i = derive_lagrange_coefficient(identifier, participant_list)
    //
    // # Compute relation values
    // l = G.ScalarBaseMult(sig_share_i)
    // r = comm_share + G.ScalarMult(PK_i, challenge * lambda_i)
    //
    // return l == r

    // # Compute the binding factor(s)
    // binding_factor_list = compute_binding_factors(commitment_list, msg)
    // TODO: fix for variable size, for now 100 to not block
    byte_t binding_factor_list[100 * ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE];
    ecc_frost_ristretto255_sha512_compute_binding_factors(
        binding_factor_list,
        commitment_list, commitment_list_len,
        msg, msg_len
    );
    // binding_factor = binding_factor_for_participant(binding_factor_list, identifier)
    byte_t binding_factor[SCALARSIZE];
    ecc_frost_ristretto255_sha512_binding_factor_for_participant(
        binding_factor,
        binding_factor_list, commitment_list_len,
        identifier
    );

    // # Compute the group commitment
    // group_commitment = compute_group_commitment(commitment_list, binding_factor_list)
    byte_t group_commitment[ELEMENTSIZE];
    ecc_frost_ristretto255_sha512_compute_group_commitment(
        group_commitment,
        commitment_list, commitment_list_len,
        binding_factor_list, commitment_list_len
    );

    // # Compute the commitment share
    // (hiding_nonce_commitment, binding_nonce_commitment) = comm_i
    const NonceCommitmentPair_t *comm_i = (const NonceCommitmentPair_t *) comm_i_ptr;
    // comm_share = hiding_nonce_commitment + G.ScalarMult(binding_nonce_commitment, binding_factor)
    byte_t T[ecc_ristretto255_ELEMENTSIZE];
    byte_t comm_share[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_scalarmult(T, binding_factor, comm_i->binding_nonce_commitment);
    ecc_ristretto255_add(comm_share, comm_i->hiding_nonce_commitment, T);
#if ECC_LOG
    ecc_log("frost:verify_signature_share:comm_share", comm_share, sizeof comm_share);
#endif

    // # Compute the challenge
    // challenge = compute_challenge(group_commitment, group_public_key, msg)
    byte_t challenge[SCALARSIZE];
    ecc_frost_ristretto255_sha512_compute_challenge(
        challenge,
        group_commitment,
        group_public_key,
        msg, msg_len
    );
#if ECC_LOG
    ecc_log("frost:verify_signature_share:challenge", challenge, sizeof challenge);
#endif

    // # Compute Lagrange coefficient
    // participant_list = participants_from_commitment_list(commitment_list)
    // TODO: fix for variable size, for now 100 to not block
    byte_t participant_list[100 * SCALARSIZE];
    ecc_frost_ristretto255_sha512_participants_from_commitment_list(
        participant_list,
        commitment_list, commitment_list_len
    );
    // lambda_i = derive_lagrange_coefficient(identifier, participant_list)
    byte_t lambda_i[SCALARSIZE];
    ecc_frost_ristretto255_sha512_derive_interpolating_value(
        lambda_i,
        identifier,
        participant_list, commitment_list_len
    );
#if ECC_LOG
    ecc_log("frost:verify_signature_share:lambda_i", lambda_i, sizeof lambda_i);
#endif

    // # Compute relation values
    // l = G.ScalarBaseMult(sig_share_i)
    byte_t l[ELEMENTSIZE];
    ecc_ristretto255_scalarmult_base(l, sig_share_i);
#if ECC_LOG
    ecc_log("frost:verify_signature_share:l", l, sizeof l);
#endif
    // r = comm_share + G.ScalarMult(PK_i, challenge * lambda_i)
    byte_t t[SCALARSIZE];
    byte_t r[ELEMENTSIZE];
    ecc_ristretto255_scalar_mul(t, challenge, lambda_i);
    ecc_ristretto255_scalarmult(r, t, public_key_share_i);
    ecc_ristretto255_add(r, comm_share, r);
#if ECC_LOG
    ecc_log("frost:verify_signature_share:public_key_share_i", public_key_share_i, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    ecc_log("frost:verify_signature_share:r", r, sizeof r);
#endif

    // return l == r
    // 1 if the signature share is valid, and 0 otherwise.
    int cmp = ecc_compare(l, r, ELEMENTSIZE);

    // cleanup stack memory
    ecc_memzero(binding_factor_list, sizeof binding_factor_list);
    ecc_memzero(binding_factor, sizeof binding_factor);
    ecc_memzero(group_commitment, sizeof group_commitment);
    ecc_memzero(T, sizeof T);
    ecc_memzero(comm_share, sizeof comm_share);
    ecc_memzero(challenge, sizeof challenge);
    ecc_memzero(participant_list, sizeof participant_list);
    ecc_memzero(lambda_i, sizeof lambda_i);
    ecc_memzero(l, sizeof l);
    ecc_memzero(t, sizeof t);
    ecc_memzero(r, sizeof r);

    return cmp == 0 ? 1 : 0;
}

void ecc_frost_ristretto255_sha512_H1(
    byte_t *h1,
    const byte_t *m, const int m_len
) {
    byte_t contextString[32] = "FROST-RISTRETTO255-SHA512-v11rho";

    byte_t digest[ecc_hash_sha512_HASHSIZE];
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, contextString, sizeof contextString);
    crypto_hash_sha512_update(&st, m, (unsigned long long) m_len);
    crypto_hash_sha512_final(&st, digest);

    ecc_ristretto255_scalar_reduce(h1, digest);

    // cleanup stack memory
    ecc_memzero(digest, sizeof digest);
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_frost_ristretto255_sha512_H1_2(
    byte_t *h1,
    const byte_t *m1, const int m1_len,
    const byte_t *m2, const int m2_len
) {
    byte_t contextString[32] = "FROST-RISTRETTO255-SHA512-v11rho";

    byte_t digest[ecc_hash_sha512_HASHSIZE];
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, contextString, sizeof contextString);
    crypto_hash_sha512_update(&st, m1, (unsigned long long) m1_len);
    crypto_hash_sha512_update(&st, m2, (unsigned long long) m2_len);
    crypto_hash_sha512_final(&st, digest);

    ecc_ristretto255_scalar_reduce(h1, digest);

    // cleanup stack memory
    ecc_memzero(digest, sizeof digest);
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_frost_ristretto255_sha512_H2(
    byte_t *h2,
    const byte_t *m, const int m_len
) {
    byte_t contextString[33] = "FROST-RISTRETTO255-SHA512-v11chal";

    byte_t digest[ecc_hash_sha512_HASHSIZE];
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, contextString, sizeof contextString);
    crypto_hash_sha512_update(&st, m, (unsigned long long) m_len);
    crypto_hash_sha512_final(&st, digest);

    ecc_ristretto255_scalar_reduce(h2, digest);

    // cleanup stack memory
    ecc_memzero(digest, sizeof digest);
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_frost_ristretto255_sha512_H2_3(
    byte_t *h2,
    const byte_t *m1, const int m1_len,
    const byte_t *m2, const int m2_len,
    const byte_t *m3, const int m3_len
) {
    byte_t contextString[33] = "FROST-RISTRETTO255-SHA512-v11chal";

    byte_t digest[ecc_hash_sha512_HASHSIZE];
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, contextString, sizeof contextString);
    crypto_hash_sha512_update(&st, m1, (unsigned long long) m1_len);
    crypto_hash_sha512_update(&st, m2, (unsigned long long) m2_len);
    crypto_hash_sha512_update(&st, m3, (unsigned long long) m3_len);
    crypto_hash_sha512_final(&st, digest);

    ecc_ristretto255_scalar_reduce(h2, digest);

    // cleanup stack memory
    ecc_memzero(digest, sizeof digest);
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_frost_ristretto255_sha512_H3(
    byte_t *h3,
    const byte_t *m, const int m_len
) {
    byte_t contextString[34] = "FROST-RISTRETTO255-SHA512-v11nonce";

    byte_t digest[ecc_hash_sha512_HASHSIZE];
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, contextString, sizeof contextString);
    crypto_hash_sha512_update(&st, m, (unsigned long long) m_len);
    crypto_hash_sha512_final(&st, digest);

    ecc_ristretto255_scalar_reduce(h3, digest);

    // cleanup stack memory
    ecc_memzero(digest, sizeof digest);
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_frost_ristretto255_sha512_H3_2(
    byte_t *h3,
    const byte_t *m1, int m1_len,
    const byte_t *m2, int m2_len
) {
    byte_t contextString[34] = "FROST-RISTRETTO255-SHA512-v11nonce";

    byte_t digest[ecc_hash_sha512_HASHSIZE];
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, contextString, sizeof contextString);
    crypto_hash_sha512_update(&st, m1, (unsigned long long) m1_len);
    crypto_hash_sha512_update(&st, m2, (unsigned long long) m2_len);
    crypto_hash_sha512_final(&st, digest);

    ecc_ristretto255_scalar_reduce(h3, digest);

    // cleanup stack memory
    ecc_memzero(digest, sizeof digest);
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_frost_ristretto255_sha512_H4(
    byte_t *h4,
    const byte_t *m, int m_len
) {
    byte_t contextString[29] = "FROST-RISTRETTO255-SHA512-v11";
    byte_t msgString[3] = "msg";

    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, contextString, sizeof contextString);
    crypto_hash_sha512_update(&st, msgString, sizeof msgString);
    crypto_hash_sha512_update(&st, m, (unsigned long long) m_len);
    crypto_hash_sha512_final(&st, h4);

    // cleanup stack memory
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_frost_ristretto255_sha512_H5(
    byte_t *h5,
    const byte_t *m, int m_len
) {
    byte_t contextString[29] = "FROST-RISTRETTO255-SHA512-v11";
    byte_t comString[3] = "com";

    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, contextString, sizeof contextString);
    crypto_hash_sha512_update(&st, comString, sizeof comString);
    crypto_hash_sha512_update(&st, m, (unsigned long long) m_len);
    crypto_hash_sha512_final(&st, h5);

    // cleanup stack memory
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_frost_ristretto255_sha512_prime_order_sign(
    byte_t *signature_ptr,
    const byte_t *msg, const int msg_len,
    const byte_t *SK
) {
//    PK = G.ScalarBaseMult(SK)
//    k = G.RandomScalar()
//    R = G.ScalarBaseMult(k)
//
//    comm_enc = G.SerializeElement(R)
//    pk_enc = G.SerializeElement(PK)
//    challenge_input = comm_enc || pk_enc || msg
//    c = H2(challenge_input)
//
//    z = k + (c * SK)
//    return (R, z)

    Signature_t *signature = (Signature_t *) signature_ptr;

    byte_t PK[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_scalarmult_base(PK, SK);
    byte_t k[ecc_ristretto255_SCALARSIZE];
    ecc_ristretto255_scalar_random(k);
    byte_t R[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_scalarmult_base(R, k);

    byte_t c[ecc_ristretto255_SCALARSIZE];
    ecc_frost_ristretto255_sha512_H2_3(
        c,
        R, sizeof R,
        PK, sizeof PK,
        msg, sizeof msg_len
    );

    // z = k + (c * SK)
    byte_t t[ecc_ristretto255_SCALARSIZE];
    ecc_ristretto255_scalar_mul(t, c, SK); // c * SK
    byte_t z[ecc_ristretto255_SCALARSIZE];
    ecc_ristretto255_scalar_add(z, k, t); // k + (c * SK)

#if ECC_LOG
    ecc_log("schnorr_signature_generate:PK", PK, sizeof PK);
    ecc_log("schnorr_signature_generate:c", c, sizeof c);
    ecc_log("schnorr_signature_generate:R", R, sizeof R);
    ecc_log("schnorr_signature_generate:z", z, sizeof z);
#endif

    memcpy(signature->R, R, sizeof R);
    memcpy(signature->z, z, sizeof z);

    // cleanup stack memory
    ecc_memzero(PK, sizeof PK);
    ecc_memzero(k, sizeof k);
    ecc_memzero(R, sizeof R);
    ecc_memzero(c, sizeof c);
    ecc_memzero(t, sizeof t);
    ecc_memzero(z, sizeof z);
}

int ecc_frost_ristretto255_sha512_prime_order_verify(
    const byte_t *msg, const int msg_len,
    const byte_t *signature_ptr,
    const byte_t *PK
) {
//    comm_enc = G.SerializeElement(R)
//    pk_enc = G.SerializeElement(PK)
//    challenge_input = comm_enc || pk_enc || msg
//    c = H2(challenge_input)
//
//    l = G.ScalarBaseMult(z)
//    r = R + (c * PK)
//    if l == r:
//      return 1
//    return 0

    const Signature_t *signature = (const Signature_t *) signature_ptr;

    byte_t c[ecc_ristretto255_SCALARSIZE];
    ecc_frost_ristretto255_sha512_H2_3(
        c,
        signature->R, sizeof signature->R,
        PK, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE,
        msg, sizeof msg_len
    );

#if ECC_LOG
    ecc_log("schnorr_signature_generate:PK", PK, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    ecc_log("schnorr_signature_verify:c", c, sizeof c);
    ecc_log("schnorr_signature_generate:R", signature->R, sizeof signature->R);
    ecc_log("schnorr_signature_generate:z", signature->z, sizeof signature->z);
#endif

    byte_t l[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_scalarmult_base(l, signature->z);

    // r = R + (c * PK)
    byte_t t[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_scalarmult(t, c, PK); // c * PK
    byte_t r[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_add(r, signature->R, t); // R + (c * PK)

    int cmp = ecc_compare(l, r, ecc_ristretto255_ELEMENTSIZE);

    // cleanup stack memory
    ecc_memzero(c, sizeof c);
    ecc_memzero(l, sizeof l);
    ecc_memzero(t, sizeof t);
    ecc_memzero(r, sizeof r);

    if (cmp == 0)
        return 1;
    return 0;
}

void ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_coefficients(
    byte_t *participant_private_keys,
    byte_t *group_public_key,
    byte_t *vss_commitment,
    byte_t *polynomial_coefficients,
    const byte_t *secret_key,
    const int n,
    const int t,
    const byte_t *coefficients
) {
    // participant_private_keys, coefficients = secret_share_shard(secret_key, coefficients, MAX_PARTICIPANTS, MIN_PARTICIPANTS)
    // vss_commitment = vss_commit(coefficients):
    // return participant_private_keys, vss_commitment[0], vss_commitment
    ecc_frost_ristretto255_sha512_secret_share_shard(
        participant_private_keys,
        polynomial_coefficients,
        secret_key,
        coefficients,
        n, t
    );

    ecc_frost_ristretto255_sha512_vss_commit(
        vss_commitment,
        polynomial_coefficients, t
    );

    memcpy(group_public_key, &vss_commitment[0], ELEMENTSIZE);
}

int ecc_frost_ristretto255_sha512_secret_share_shard(
    byte_t *secret_key_shares,
    byte_t *polynomial_coefficients,
    const byte_t *s,
    const byte_t *coefficients,
    const int n,
    const int t
) {
    // if MIN_PARTICIPANTS > MAX_PARTICIPANTS:
    //   raise "invalid parameters"
    // if MIN_PARTICIPANTS < 2:
    //   raise "invalid parameters"
    //
    // # Prepend the secret to the coefficients
    // coefficients = [s] + coefficients
    //
    // # Evaluate the polynomial for each point x=1,...,n
    // secret_key_shares = []
    // for x_i in range(1, MAX_PARTICIPANTS + 1):
    //   y_i = polynomial_evaluate(Scalar(x_i), coefficients)
    //   secret_key_share_i = (x_i, y_i)
    //   secret_key_shares.append(secret_key_share_i)
    // return secret_key_shares, coefficients

    if (t > n)
        return -1;
    if (t < 2)
        return -1;

    // # Prepend the secret to the coefficients
    // coefficients = [s] + coefficients
    memcpy(&polynomial_coefficients[0], s, SCALARSIZE);
    for (int i = 0; i < t - 1; i++)
        memcpy(&polynomial_coefficients[(i + 1) * SCALARSIZE], &coefficients[i * SCALARSIZE], SCALARSIZE);

    // # Evaluate the polynomial for each point x=1,...,n
    // secret_key_shares = []
    // for x_i in range(1, MAX_PARTICIPANTS + 1):
    //   y_i = polynomial_evaluate(Scalar(x_i), coefficients)
    //   secret_key_share_i = (x_i, y_i)
    //   secret_key_shares.append(secret_key_share_i)
    byte_t y_i[SCALARSIZE];
    for (int i = 1; i <= n; i++) {
        byte_t x_i[SCALARSIZE] = {(byte_t) i, 0};

        ecc_frost_ristretto255_sha512_polynomial_evaluate(y_i, x_i, polynomial_coefficients, t);
#if ECC_LOG
        ecc_log("frost:secret_share_shard:y_i", y_i, SCALARSIZE);
#endif
        const int pos = (i - 1) * ecc_frost_ristretto255_sha512_POINTSIZE;
        Point_t *secret_key_share_i = (Point_t *) &secret_key_shares[pos];
        memcpy(secret_key_share_i->x, x_i, SCALARSIZE);
        memcpy(secret_key_share_i->y, y_i, SCALARSIZE);
    }

    // cleanup stack memory
    ecc_memzero(y_i, sizeof y_i);

    // return secret_key_shares, coefficients
    return 0;
}

int ecc_frost_ristretto255_sha512_secret_share_combine(
    byte_t *s,
    const byte_t *shares, const int shares_len
) {
    // if len(shares) < MIN_PARTICIPANTS:
    //   raise "invalid parameters"
    // s = polynomial_interpolate_constant(shares)
    // return s

    ecc_frost_ristretto255_sha512_polynomial_interpolate_constant(
        s,
        shares, shares_len
    );

    return 0;
}

void ecc_frost_ristretto255_sha512_polynomial_evaluate(
    byte_t *value,
    const byte_t *x,
    const byte_t *coeffs, const int coeffs_len
) {
    ecc_memzero(value, SCALARSIZE);

    for (int i = coeffs_len - 1; i >= 0; i--) {
        ecc_ristretto255_scalar_mul(value, x, value);
        ecc_ristretto255_scalar_add(value, value, &coeffs[i * SCALARSIZE]);
    }
}

void ecc_frost_ristretto255_sha512_polynomial_interpolate_constant(
    byte_t *f_zero,
    const byte_t *points, const int points_len
) {
    // x_coords = []
    // for (x, y) in points:
    //   x_coords.append(x)
    //
    // f_zero = Scalar(0)
    // for (x, y) in points:
    //   delta = y * derive_interpolating_value(x, x_coords)
    //   f_zero += delta
    //
    // return f_zero

    ecc_memzero(f_zero, SCALARSIZE);

    byte_t delta[SCALARSIZE];
    byte_t interpolating_value[SCALARSIZE];

    for (int i = 0; i < points_len; i++) {
        const Point_t *point = (const Point_t *) &points[i * ecc_frost_ristretto255_sha512_POINTSIZE];

        ecc_frost_ristretto255_sha512_derive_interpolating_value_with_points(interpolating_value, point->x, points, points_len);
        ecc_ristretto255_scalar_mul(delta, point->y, interpolating_value);

        ecc_ristretto255_scalar_add(f_zero, f_zero, delta);
    }

    // cleanup stack memory
    ecc_memzero(delta, sizeof delta);
    ecc_memzero(interpolating_value, sizeof interpolating_value);
}

void ecc_frost_ristretto255_sha512_vss_commit(
    byte_t *vss_commitment,
    const byte_t *coeffs,
    const int coeffs_len
) {
    // vss_commitment = []
    // for coeff in coeffs:
    //   A_i = G.ScalarBaseMult(coeff)
    //   vss_commitment.append(A_i)
    // return vss_commitment
    for (int i = 0; i < coeffs_len; i++) {
        ecc_ristretto255_scalarmult_base(
            &vss_commitment[i * ELEMENTSIZE],
            &coeffs[i * SCALARSIZE]
        );
    }
}

int ecc_frost_ristretto255_sha512_vss_verify(
    const byte_t *share_i_ptr,
    const byte_t *vss_commitment,
    const int t
) {
    // (i, sk_i) = share_i
    // S_i = ScalarBaseMult(sk_i)
    // S_i' = G.Identity()
    // for j in range(0, MIN_PARTICIPANTS):
    //   S_i' += G.ScalarMult(vss_commitment[j], pow(i, j))
    // return S_i == S_i'

    const Point_t *share_i = (const Point_t *) share_i_ptr;

    byte_t S_i[ELEMENTSIZE];
    ecc_ristretto255_scalarmult_base(S_i, share_i->y);
#if ECC_LOG
    ecc_log("frost:vss_verify:S_i", S_i, ELEMENTSIZE);
#endif

    byte_t S_i_p[ELEMENTSIZE] = {0};
    byte_t q[ELEMENTSIZE];
    for (int j = 0; j < t; j++) {
        // TODO: fix overflow
        const int i = share_i->x[0];
        const int p = power(i, j);
        // TODO: fix overflow
        byte_t s[SCALARSIZE] = {(byte_t) p, 0};
        ecc_ristretto255_scalarmult(
            q,
            s,
            &vss_commitment[j * ELEMENTSIZE]
        );
        ecc_ristretto255_add(S_i_p, S_i_p, q);
    }

    const int r = ecc_compare(S_i, S_i_p, ELEMENTSIZE) == 0 ? 1 : 0;

    // cleanup stack memory
    ecc_memzero(S_i, sizeof S_i);
    ecc_memzero(S_i_p, sizeof S_i_p);
    ecc_memzero(q, sizeof q);

    return r;
}

void ecc_frost_ristretto255_sha512_derive_group_info(
    byte_t *PK,
    byte_t *participant_public_keys,
    const int n,
    const int t,
    const byte_t *vss_commitment
) {
    // PK = vss_commitment[0]
    // participant_public_keys = []
    // for i in range(1, MAX_PARTICIPANTS+1):
    //   PK_i = G.Identity()
    //   for j in range(0, MIN_PARTICIPANTS):
    //     PK_i += G.ScalarMult(vss_commitment[j], pow(i, j))
    //   participant_public_keys.append(PK_i)
    // return PK, participant_public_keys

    memcpy(PK, &vss_commitment[0], ELEMENTSIZE);

    byte_t PK_i[ELEMENTSIZE];
    byte_t q[ELEMENTSIZE];
    for (int i = 1; i < n + 1; i++) {
        ecc_memzero(PK_i, ELEMENTSIZE);

        for (int j = 0; j < t; j++) {
            const int p = power(i, j);
            // TODO: fix overflow
            byte_t s[SCALARSIZE] = {(byte_t) p, 0};
            ecc_ristretto255_scalarmult(
                q,
                s,
                &vss_commitment[j * ELEMENTSIZE]
            );
            ecc_ristretto255_add(PK_i, PK_i, q);
        }
#if ECC_LOG
        ecc_log("frost:derive_group_info:PK_i", PK_i, sizeof PK_i);
#endif

        memcpy(&participant_public_keys[(i - 1) * ELEMENTSIZE], PK_i, ELEMENTSIZE);
    }

    // cleanup stack memory
    ecc_memzero(PK_i, sizeof PK_i);
    ecc_memzero(q, sizeof q);
}
