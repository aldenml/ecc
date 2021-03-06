/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

static void test_ecc_frost_ristretto255_sha512_poc_test_vectors(void **state) {
    ECC_UNUSED(state);

    const int MAX_SIGNERS = 3;
    const int THRESHOLD_LIMIT = 2;
    //const int NUM_SIGNERS = THRESHOLD_LIMIT;

    byte_t message[4] = "test";
    ecc_log("message", message, sizeof message);

    byte_t participant_list[2 * ecc_frost_ristretto255_sha512_SCALARSIZE] = {0};
    participant_list[0] = 1;
    participant_list[ecc_frost_ristretto255_sha512_SCALARSIZE] = 2;

    byte_t group_secret_key[ecc_frost_ristretto255_sha512_SECRETKEYSIZE];
    ecc_hex2bin(group_secret_key, "b120be204b5e758960458ca9c4675b56b12a8faff2be9c94891d5e1cd75c880e", 64);

    byte_t coefficients[2 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(&coefficients[0], "b120be204b5e758960458ca9c4675b56b12a8faff2be9c94891d5e1cd75c880e", 64);
    ecc_hex2bin(&coefficients[ecc_frost_ristretto255_sha512_SCALARSIZE], "d0619df75f08a757c6d60b09199b62acd3f169e7eb9b6fc2c501e876066fdf06", 64);

    byte_t group_public_key[ecc_frost_ristretto255_sha512_PUBLICKEYSIZE];
    byte_t signer_keys[3 * ecc_frost_ristretto255_sha512_POINTSIZE];
    ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_secret_and_coefficients(
        group_public_key,
        signer_keys,
        MAX_SIGNERS,
        THRESHOLD_LIMIT,
        group_secret_key,
        coefficients
    );

    ecc_log("group_public_key", group_public_key, sizeof group_public_key);

    byte_t signer_public_keys[3 * ecc_frost_ristretto255_sha512_PUBLICKEYSIZE];
    for (int i = 1; i <= MAX_SIGNERS; i++) {
        ecc_ristretto255_scalarmult_base(
            &signer_public_keys[(i - 1) * ecc_frost_ristretto255_sha512_PUBLICKEYSIZE],
            &signer_keys[(i - 1) * ecc_frost_ristretto255_sha512_POINTSIZE + ecc_frost_ristretto255_sha512_SCALARSIZE]
        );
    }
    ecc_log("S1 signer_share", &signer_keys[ecc_frost_ristretto255_sha512_SCALARSIZE], ecc_frost_ristretto255_sha512_SCALARSIZE);
    ecc_log("S2 signer_share", &signer_keys[ecc_frost_ristretto255_sha512_POINTSIZE + ecc_frost_ristretto255_sha512_SCALARSIZE], ecc_frost_ristretto255_sha512_SCALARSIZE);
    ecc_log("S3 signer_share", &signer_keys[2 * ecc_frost_ristretto255_sha512_POINTSIZE + ecc_frost_ristretto255_sha512_SCALARSIZE], ecc_frost_ristretto255_sha512_SCALARSIZE);

    // Round one: commitment

    byte_t nonce_1[ecc_frost_ristretto255_sha512_NONCEPAIRSIZE];
    byte_t nonce_2[ecc_frost_ristretto255_sha512_NONCEPAIRSIZE];
    byte_t comm_1[ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE];
    byte_t comm_2[ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE];
    ecc_hex2bin(&nonce_1[0], "349b3bb8464a1d87f7d6b56f4559a3f9a6335261a3266089a9b12d9d6f6ce209", 64);
    ecc_hex2bin(&nonce_1[32], "ce7406016a854be4291f03e7d24fe30e77994c3465de031515a4c116f22ca901", 64);
    ecc_hex2bin(&nonce_2[0], "4d66d319f20a728ec3d491cbf260cc6be687bd87cc2b5fdb4d5f528f65fd650d", 64);
    ecc_hex2bin(&nonce_2[32], "278b9b1e04632e6af3f1a3c144d07922ffcf5efd3a341b47abc19c43f48ce306", 64);
    ecc_frost_ristretto255_sha512_commit_with_nonce(comm_1, nonce_1);
    ecc_frost_ristretto255_sha512_commit_with_nonce(comm_2, nonce_2);

//    group_comm_list = signers[1].encode_group_commitment_list(commitment_list)
//    msg_hash = signers[1].H.H3(message)
//    rho_input = bytes(group_comm_list + msg_hash)
//    binding_factor = signers[1].H.H1(rho_input)
//    group_comm = signers[1].group_commitment(commitment_list, binding_factor)
    byte_t commitment_list[2 * ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE];
    ecc_I2OSP(&commitment_list[0], 1, 2);
    memcpy(&commitment_list[2], comm_1, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    ecc_I2OSP(&commitment_list[ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE], 2, 2);
    memcpy(&commitment_list[2 + ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE], comm_2, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);

    byte_t msg_hash[64];
    ecc_frost_ristretto255_sha512_H3(msg_hash, message, sizeof message);
    byte_t rho_input[2 * ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE + 64];
    ecc_concat2(
        rho_input,
        commitment_list, sizeof commitment_list,
        msg_hash, sizeof msg_hash
    );
    ecc_log("group_binding_factor_input", rho_input, sizeof rho_input);

    // binding_factor = signers[1].H.H1(rho_input)
    byte_t binding_factor[32];
    ecc_frost_ristretto255_sha512_H1(binding_factor, rho_input, sizeof rho_input);
    ecc_log("binding_factor", binding_factor, sizeof binding_factor);

    // group_comm = signers[1].group_commitment(commitment_list, binding_factor)
    byte_t group_comm[ecc_frost_ristretto255_sha512_ELEMENTSIZE];
    ecc_frost_ristretto255_sha512_group_commitment(group_comm, commitment_list, 2, binding_factor);
    ecc_log("group_comm", group_comm, sizeof group_comm);

    // Round two: sign
    byte_t sig_shares[2 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    byte_t comm_shares[2 * ecc_frost_ristretto255_sha512_ELEMENTSIZE];
    ecc_frost_ristretto255_sha512_sign(
        &sig_shares[0],
        &comm_shares[0],
        1,
        &signer_keys[ecc_frost_ristretto255_sha512_SCALARSIZE],
        group_public_key,
        nonce_1,
        comm_1,
        message, sizeof message,
        commitment_list, 2,
        participant_list, 2
    );
    ecc_frost_ristretto255_sha512_sign(
        &sig_shares[ecc_frost_ristretto255_sha512_SCALARSIZE],
        &comm_shares[ecc_frost_ristretto255_sha512_ELEMENTSIZE],
        2,
        &signer_keys[ecc_frost_ristretto255_sha512_POINTSIZE + ecc_frost_ristretto255_sha512_SCALARSIZE],
        group_public_key,
        nonce_2,
        comm_2,
        message, sizeof message,
        commitment_list, 2,
        participant_list, 2
    );
    ecc_log("S1 sig_share", &sig_shares[0], ecc_frost_ristretto255_sha512_SCALARSIZE);
    ecc_log("S1 group_commitment_share", &comm_shares[0], ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    ecc_log("S2 sig_share", &sig_shares[ecc_frost_ristretto255_sha512_SCALARSIZE], ecc_frost_ristretto255_sha512_SCALARSIZE);
    ecc_log("S2 group_commitment_share", &comm_shares[ecc_frost_ristretto255_sha512_ELEMENTSIZE], ecc_frost_ristretto255_sha512_ELEMENTSIZE);

    byte_t signature[ecc_frost_ristretto255_sha512_SIGNATURESIZE];
    ecc_frost_ristretto255_sha512_frost_aggregate(signature, group_comm, sig_shares, 2);

    char signature_hex[2 * ecc_frost_ristretto255_sha512_SIGNATURESIZE + 1];
    ecc_bin2hex(signature_hex, signature, sizeof signature);
    assert_string_equal(signature_hex, "7e92309bf40993141acd5f2c7680a302cc5aa5dd291a833906da8e35bc39b03e733ad4238fcb01b83703b1b0e83872d8ec0d164164a4eaea06242f3c8acc2405");
    ecc_log("sig", signature, sizeof signature);

    int v1 = ecc_frost_ristretto255_sha512_verify_signature_share(
        1,
        &signer_public_keys[0],
        comm_1,
        &sig_shares[0],
        commitment_list, 2,
        participant_list, 2,
        group_public_key,
        message, sizeof message
    );
    assert_int_equal(v1, 1);

    int v2 = ecc_frost_ristretto255_sha512_verify_signature_share(
        2,
        &signer_public_keys[ecc_frost_ristretto255_sha512_PUBLICKEYSIZE],
        comm_2,
        &sig_shares[ecc_frost_ristretto255_sha512_SCALARSIZE],
        commitment_list, 2,
        participant_list, 2,
        group_public_key,
        message, sizeof message
    );
    assert_int_equal(v2, 1);

    int r = ecc_frost_ristretto255_sha512_schnorr_signature_verify(
        message, sizeof message,
        signature,
        group_public_key
    );
    assert_int_equal(r, 1);
}

static void test_ecc_frost_ristretto255_sha512_schnorr_signature(void **state) {
    ECC_UNUSED(state);

    byte_t sk[ecc_frost_ristretto255_sha512_SECRETKEYSIZE];
    byte_t pk[ecc_frost_ristretto255_sha512_PUBLICKEYSIZE];
    byte_t msg[5] = "hello";

    ecc_ristretto255_scalar_random(sk);
    ecc_ristretto255_scalarmult_base(pk, sk);

    byte_t signature[ecc_frost_ristretto255_sha512_SIGNATURESIZE];
    ecc_frost_ristretto255_sha512_schnorr_signature_generate(signature, msg, sizeof msg, sk);

    int r = ecc_frost_ristretto255_sha512_schnorr_signature_verify(msg, sizeof msg, signature, pk);
    assert_int_equal(r, 1);
}

static void test_ecc_frost_ristretto255_sha512_polynomial_evaluate_small_numbers(void **state) {
    ECC_UNUSED(state);

    byte_t a0[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t a1[ecc_frost_ristretto255_sha512_SCALARSIZE] = {2, 0};
    byte_t a2[ecc_frost_ristretto255_sha512_SCALARSIZE] = {3, 0};
    byte_t a3[ecc_frost_ristretto255_sha512_SCALARSIZE] = {4, 0};

    byte_t coeffs[4 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_concat4(
        coeffs,
        a0, sizeof a0,
        a1, sizeof a1,
        a2, sizeof a2,
        a3, sizeof a3
    );

    // f(0)
    byte_t x1[ecc_frost_ristretto255_sha512_SCALARSIZE] = {0};
    byte_t r1[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t v1[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_polynomial_evaluate(v1, x1, coeffs, 4);
    assert_memory_equal(v1, r1, ecc_frost_ristretto255_sha512_SCALARSIZE);

    // f(1)
    byte_t x2[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t r2[ecc_frost_ristretto255_sha512_SCALARSIZE] = {10, 0};
    byte_t v2[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_polynomial_evaluate(v2, x2, coeffs, 4);
    assert_memory_equal(v2, r2, ecc_frost_ristretto255_sha512_SCALARSIZE);

    // f(2)
    byte_t x3[ecc_frost_ristretto255_sha512_SCALARSIZE] = {2, 0};
    byte_t r3[ecc_frost_ristretto255_sha512_SCALARSIZE] = {49, 0};
    byte_t v3[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_polynomial_evaluate(v3, x3, coeffs, 4);
    assert_memory_equal(v3, r3, ecc_frost_ristretto255_sha512_SCALARSIZE);
}

static void test_ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_1(void **state) {
    ECC_UNUSED(state);

    byte_t x0[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t x1[ecc_frost_ristretto255_sha512_SCALARSIZE] = {2, 0};
    byte_t x2[ecc_frost_ristretto255_sha512_SCALARSIZE] = {3, 0};
    byte_t x3[ecc_frost_ristretto255_sha512_SCALARSIZE] = {4, 0};

    byte_t L[4 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_concat4(
        L,
        x0, sizeof x0,
        x1, sizeof x1,
        x2, sizeof x2,
        x3, sizeof x3
    );

    byte_t L_0[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_derive_lagrange_coefficient(L_0, x0, L, 4);
    ecc_log("L_0", L_0, sizeof L_0);
    char L_0_hex[2 * ecc_frost_ristretto255_sha512_SCALARSIZE + 1];
    ecc_bin2hex(L_0_hex, L_0, sizeof L_0);
    assert_string_equal(L_0_hex, "0400000000000000000000000000000000000000000000000000000000000000");

    byte_t L_1[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_derive_lagrange_coefficient(L_1, x1, L, 4);
    ecc_log("L_1", L_1, sizeof L_1);
    char L_1_hex[2 * ecc_frost_ristretto255_sha512_SCALARSIZE + 1];
    ecc_bin2hex(L_1_hex, L_1, sizeof L_1);
    assert_string_equal(L_1_hex, "e7d3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
}

static void test_ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points_1(void **state) {
    ECC_UNUSED(state);

    byte_t p0[ecc_frost_ristretto255_sha512_POINTSIZE] = {1, 0};
    byte_t p1[ecc_frost_ristretto255_sha512_POINTSIZE] = {2, 0};
    byte_t p2[ecc_frost_ristretto255_sha512_POINTSIZE] = {3, 0};
    byte_t p3[ecc_frost_ristretto255_sha512_POINTSIZE] = {4, 0};

    byte_t L[4 * ecc_frost_ristretto255_sha512_POINTSIZE];
    ecc_concat4(
        L,
        p0, sizeof p0,
        p1, sizeof p1,
        p2, sizeof p2,
        p3, sizeof p3
    );

    byte_t L_0[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points(L_0, p0, L, 4); // x is first in p
    ecc_log("L_0", L_0, sizeof L_0);
    char L_0_hex[2 * ecc_frost_ristretto255_sha512_SCALARSIZE + 1];
    ecc_bin2hex(L_0_hex, L_0, sizeof L_0);
    assert_string_equal(L_0_hex, "0400000000000000000000000000000000000000000000000000000000000000");

    byte_t L_1[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points(L_1, p1, L, 4); // x is first in p
    ecc_log("L_1", L_1, sizeof L_1);
    char L_1_hex[2 * ecc_frost_ristretto255_sha512_SCALARSIZE + 1];
    ecc_bin2hex(L_1_hex, L_1, sizeof L_1);
    assert_string_equal(L_1_hex, "e7d3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
}

static void test_ecc_frost_ristretto255_sha512_polynomial_interpolation_small_numbers_1(void **state) {
    ECC_UNUSED(state);

    byte_t a0[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t a1[ecc_frost_ristretto255_sha512_SCALARSIZE] = {2, 0};
    byte_t a2[ecc_frost_ristretto255_sha512_SCALARSIZE] = {3, 0};
    byte_t a3[ecc_frost_ristretto255_sha512_SCALARSIZE] = {4, 0};

    byte_t coeffs[4 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_concat4(
        coeffs,
        a0, sizeof a0,
        a1, sizeof a1,
        a2, sizeof a2,
        a3, sizeof a3
    );

    byte_t p0[ecc_frost_ristretto255_sha512_POINTSIZE] = {1, 0};
    byte_t p1[ecc_frost_ristretto255_sha512_POINTSIZE] = {2, 0};
    byte_t p2[ecc_frost_ristretto255_sha512_POINTSIZE] = {3, 0};
    byte_t p3[ecc_frost_ristretto255_sha512_POINTSIZE] = {4, 0};

    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p0[ecc_frost_ristretto255_sha512_SCALARSIZE], p0, coeffs, 4);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p1[ecc_frost_ristretto255_sha512_SCALARSIZE], p1, coeffs, 4);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p2[ecc_frost_ristretto255_sha512_SCALARSIZE], p2, coeffs, 4);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p3[ecc_frost_ristretto255_sha512_SCALARSIZE], p3, coeffs, 4);

    byte_t points[4 * ecc_frost_ristretto255_sha512_POINTSIZE];
    ecc_concat4(
        points,
        p0, sizeof p0,
        p1, sizeof p1,
        p2, sizeof p2,
        p3, sizeof p3
    );

    byte_t constant_term[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_polynomial_interpolation(constant_term, points, 4);
    assert_memory_equal(constant_term, a0, ecc_frost_ristretto255_sha512_SCALARSIZE);
}

static void test_ecc_frost_ristretto255_sha512_polynomial_interpolation_small_numbers_2(void **state) {
    ECC_UNUSED(state);

    byte_t a0[ecc_frost_ristretto255_sha512_SCALARSIZE] = {4, 0};
    byte_t a1[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t a2[ecc_frost_ristretto255_sha512_SCALARSIZE] = {2, 0};
    byte_t a3[ecc_frost_ristretto255_sha512_SCALARSIZE] = {3, 0};

    byte_t coeffs[4 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_concat4(
        coeffs,
        a0, sizeof a0,
        a1, sizeof a1,
        a2, sizeof a2,
        a3, sizeof a3
    );

    byte_t p0[ecc_frost_ristretto255_sha512_POINTSIZE] = {4, 0};
    byte_t p1[ecc_frost_ristretto255_sha512_POINTSIZE] = {1, 0};
    byte_t p2[ecc_frost_ristretto255_sha512_POINTSIZE] = {2, 0};
    byte_t p3[ecc_frost_ristretto255_sha512_POINTSIZE] = {3, 0};

    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p0[ecc_frost_ristretto255_sha512_SCALARSIZE], p0, coeffs, 4);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p1[ecc_frost_ristretto255_sha512_SCALARSIZE], p1, coeffs, 4);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p2[ecc_frost_ristretto255_sha512_SCALARSIZE], p2, coeffs, 4);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p3[ecc_frost_ristretto255_sha512_SCALARSIZE], p3, coeffs, 4);

    byte_t points[4 * ecc_frost_ristretto255_sha512_POINTSIZE];
    ecc_concat4(
        points,
        p0, sizeof p0,
        p1, sizeof p1,
        p2, sizeof p2,
        p3, sizeof p3
    );

    byte_t constant_term[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_polynomial_interpolation(constant_term, points, 4);
    assert_memory_equal(constant_term, a0, ecc_frost_ristretto255_sha512_SCALARSIZE);
}

static void test_ecc_frost_ristretto255_sha512_commit_with_nonce(void **state) {
    ECC_UNUSED(state);

    byte_t nonce[64];
    ecc_hex2bin(&nonce[0], "0100000000000000000000000000000000000000000000000000000000000000", 64);
    ecc_hex2bin(&nonce[32], "0200000000000000000000000000000000000000000000000000000000000000", 64);

    byte_t comm[64];
    ecc_frost_ristretto255_sha512_commit_with_nonce(comm, nonce);
    ecc_log("comm", comm, sizeof comm);

    char comm_hex[129];
    ecc_bin2hex(comm_hex, comm, sizeof comm);
    assert_string_equal(comm_hex,
        "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d766a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_poc_test_vectors),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_schnorr_signature),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_polynomial_evaluate_small_numbers),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_1),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points_1),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_polynomial_interpolation_small_numbers_1),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_polynomial_interpolation_small_numbers_2),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_commit_with_nonce),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
