/*
 * Copyright (c) 2022-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

static void test_ecc_frost_ristretto255_sha512_poc(void **state) {
    ECC_UNUSED(state);

    const int MAX_SIGNERS = 3;
    const int THRESHOLD_LIMIT = 2;
    //const int NUM_SIGNERS = THRESHOLD_LIMIT;

    byte_t message[4] = "test";
    ecc_log("message", message, sizeof message);

    byte_t group_secret_key[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(group_secret_key, "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304", 64);
    byte_t coefficients[1 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(&coefficients[0 * ecc_frost_ristretto255_sha512_SCALARSIZE], "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204", 64);

    byte_t participant_private_keys[3 * ecc_frost_ristretto255_sha512_POINTSIZE];
    byte_t group_public_key[ecc_frost_ristretto255_sha512_ELEMENTSIZE];
    byte_t vss_commitment[3 * ecc_frost_ristretto255_sha512_ELEMENTSIZE];
    byte_t polynomial_coefficients[2 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_coefficients(
        participant_private_keys,
        group_public_key,
        vss_commitment,
        polynomial_coefficients,
        group_secret_key,
        MAX_SIGNERS, THRESHOLD_LIMIT,
        coefficients
    );

    ecc_log("group_public_key", group_public_key, sizeof group_public_key);

    // Round one: commitment
    // (1,3)

    byte_t hiding_nonce_randomness_1[ecc_frost_ristretto255_sha512_SCALARSIZE];
    byte_t binding_nonce_randomness_1[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(hiding_nonce_randomness_1, "83836336490fbc2c3d0bdd3c85cba9327a3a33d9eb7fefc9b07e8468d19cde19", 64);
    ecc_hex2bin(binding_nonce_randomness_1, "88801c95d9272c85e760d00ee0892d8554c09251d74757088648fdb10bdadcae", 64);

    byte_t hiding_nonce_randomness_3[ecc_frost_ristretto255_sha512_SCALARSIZE];
    byte_t binding_nonce_randomness_3[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(hiding_nonce_randomness_3, "9860858cc25ef8273ea97c5aaf6ab87aa30131e89a5f42d3dc5cfbddd824f3e8", 64);
    ecc_hex2bin(binding_nonce_randomness_3, "bd18a98f01e6b5ba3805d3d3d29b2eafcb9b7cc5738ca3bb4321daa833af86c3", 64);

    char value_hex[65];

    byte_t nonce_1[ecc_frost_ristretto255_sha512_NONCEPAIRSIZE];
    byte_t comm_1[ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE];
    ecc_frost_ristretto255_sha512_commit_with_randomness(
        nonce_1,
        comm_1,
        &participant_private_keys[0 * ecc_frost_ristretto255_sha512_POINTSIZE + ecc_frost_ristretto255_sha512_SCALARSIZE],
        hiding_nonce_randomness_1,
        binding_nonce_randomness_1
    );
    ecc_bin2hex(value_hex, &nonce_1[0], 32);
    assert_string_equal(value_hex, "7eb748ecae44153acf19a4cb2a50b1a64066abd713952d587963fb81c259c50a");
    ecc_bin2hex(value_hex, &nonce_1[32], 32);
    assert_string_equal(value_hex, "605febdea1948c6a0cff7be40bfdc66eba8b98c1659f9395b05f6e96d8360405");
    ecc_bin2hex(value_hex, &comm_1[0], 32);
    assert_string_equal(value_hex, "b6f21fbe8199c91b12c8271a4e027747cb16ce475acb53f7972d6d828eb9862b");
    ecc_bin2hex(value_hex, &comm_1[32], 32);
    assert_string_equal(value_hex, "362b4503aeb10102788f9d48dbf0d06ffda8c50c36457880c40c321da8078d41");

    byte_t nonce_3[ecc_frost_ristretto255_sha512_NONCEPAIRSIZE];
    byte_t comm_3[ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE];
    ecc_frost_ristretto255_sha512_commit_with_randomness(
        nonce_3,
        comm_3,
        &participant_private_keys[2 * ecc_frost_ristretto255_sha512_POINTSIZE + ecc_frost_ristretto255_sha512_SCALARSIZE],
        hiding_nonce_randomness_3,
        binding_nonce_randomness_3
    );
    ecc_bin2hex(value_hex, &nonce_3[0], 32);
    assert_string_equal(value_hex, "50435e25750ff83a894a849bfc485eedba1476daec6f3301465d0bdaef21990b");
    ecc_bin2hex(value_hex, &nonce_3[32], 32);
    assert_string_equal(value_hex, "19f1e69a83f57fc6738e56a881583f5cf0a2a5f8888a20a698b3c3fef0391b06");
    ecc_bin2hex(value_hex, &comm_3[0], 32);
    assert_string_equal(value_hex, "b0a3bda761f94941d5571a765ec1dc445d3d85d1d3e9bbb87edfa9a04e58b902");
    ecc_bin2hex(value_hex, &comm_3[32], 32);
    assert_string_equal(value_hex, "18f5abb580988106526dc8238fbc404ea71bd41f9ebaf44275979b5619a12676");

    byte_t commitment_list[2 * ecc_frost_ristretto255_sha512_COMMITMENTSIZE] = {0};
    commitment_list[0] = 1;
    memcpy(&commitment_list[32], comm_1, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    commitment_list[ecc_frost_ristretto255_sha512_COMMITMENTSIZE] = 3;
    memcpy(&commitment_list[ecc_frost_ristretto255_sha512_COMMITMENTSIZE + 32], comm_3, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);

    byte_t binding_factor_list[2 * ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE];
    ecc_frost_ristretto255_sha512_compute_binding_factors(
        binding_factor_list,
        commitment_list, 2,
        message, sizeof message
    );

    ecc_bin2hex(value_hex, &binding_factor_list[32], 32);
    assert_string_equal(value_hex, "c83bf4ae5dd46e7cb67b64802074cefc3c5eac1175f1338b7ff147307f0f2409");
    ecc_bin2hex(value_hex, &binding_factor_list[96], 32);
    assert_string_equal(value_hex, "097d00ca708107cd38c9143b9424ae71302ed48b6b7d883d5eae26aa318d0406");

    // Round two: sign

    byte_t sig_shares[2 * ecc_frost_ristretto255_sha512_SCALARSIZE];

    byte_t identifier_1[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    ecc_frost_ristretto255_sha512_sign(
        &sig_shares[0],
        identifier_1,
        &participant_private_keys[0 * ecc_frost_ristretto255_sha512_POINTSIZE +
                                  ecc_frost_ristretto255_sha512_SCALARSIZE],
        group_public_key,
        nonce_1,
        message, sizeof message,
        commitment_list, 2
    );
    ecc_bin2hex(value_hex, &sig_shares[0], 32);
    assert_string_equal(value_hex, "3910300eee4b7c7faf81230a151e5faafa6521080edfaab1ce2451eb52de4702");

    byte_t identifier_3[ecc_frost_ristretto255_sha512_SCALARSIZE] = {3, 0};
    ecc_frost_ristretto255_sha512_sign(
        &sig_shares[32],
        identifier_3,
        &participant_private_keys[2 * ecc_frost_ristretto255_sha512_POINTSIZE +
                                  ecc_frost_ristretto255_sha512_SCALARSIZE],
        group_public_key,
        nonce_3,
        message, sizeof message,
        commitment_list, 2
    );
    ecc_bin2hex(value_hex, &sig_shares[32], 32);
    assert_string_equal(value_hex, "2e2bb818ab5edfb8be7f935551b66039764f54dfac796522d41f25895702120a");

    // Final step: aggregate

    byte_t signature[ecc_frost_ristretto255_sha512_SIGNATURESIZE];
    ecc_frost_ristretto255_sha512_aggregate(
        signature,
        commitment_list, 2,
        message, sizeof message,
        sig_shares, 2
    );

    char signature_hex[2 * ecc_frost_ristretto255_sha512_SIGNATURESIZE + 1];
    ecc_bin2hex(signature_hex, signature, sizeof signature);
    assert_string_equal(signature_hex, "7c1f15c5b12c1e8e5a4516126bdf3d6084d14f5e1e662cae942ccd00e33ae954673be82699aa5b386e01b75f66d4bfe370b575e7ba5810d4a2447674aae0590c");
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
    ecc_frost_ristretto255_sha512_derive_interpolating_value(L_0, x0, L, 4);
    ecc_log("L_0", L_0, sizeof L_0);
    char L_0_hex[2 * ecc_frost_ristretto255_sha512_SCALARSIZE + 1];
    ecc_bin2hex(L_0_hex, L_0, sizeof L_0);
    assert_string_equal(L_0_hex, "0400000000000000000000000000000000000000000000000000000000000000");

    byte_t L_1[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_derive_interpolating_value(L_1, x1, L, 4);
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
    ecc_frost_ristretto255_sha512_derive_interpolating_value_with_points(L_0, p0, L, 4); // x is first in p
    ecc_log("L_0", L_0, sizeof L_0);
    char L_0_hex[2 * ecc_frost_ristretto255_sha512_SCALARSIZE + 1];
    ecc_bin2hex(L_0_hex, L_0, sizeof L_0);
    assert_string_equal(L_0_hex, "0400000000000000000000000000000000000000000000000000000000000000");

    byte_t L_1[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_derive_interpolating_value_with_points(L_1, p1, L, 4); // x is first in p
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

static void test_ecc_frost_ristretto255_sha512_polynomial_evaluate(void **state) {
    ECC_UNUSED(state);

    byte_t x[ecc_frost_ristretto255_sha512_SCALARSIZE];

    byte_t coeffs[2 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(&coeffs[0 * ecc_frost_ristretto255_sha512_SCALARSIZE], "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304", 64);
    ecc_hex2bin(&coeffs[1 * ecc_frost_ristretto255_sha512_SCALARSIZE], "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204", 64);

    byte_t value[ecc_frost_ristretto255_sha512_SCALARSIZE];
    char value_hex[65];

    ecc_hex2bin(x, "0100000000000000000000000000000000000000000000000000000000000000", 64);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(
        value,
        x,
        coeffs, 2
    );
    ecc_bin2hex(value_hex, value, sizeof value);
    assert_string_equal(value_hex, "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509");

    ecc_hex2bin(x, "0200000000000000000000000000000000000000000000000000000000000000", 64);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(
        value,
        x,
        coeffs, 2
    );
    ecc_bin2hex(value_hex, value, sizeof value);
    assert_string_equal(value_hex, "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d");

    ecc_hex2bin(x, "0300000000000000000000000000000000000000000000000000000000000000", 64);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(
        value,
        x,
        coeffs, 2
    );
    ecc_bin2hex(value_hex, value, sizeof value);
    assert_string_equal(value_hex, "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02");
}

static void test_ecc_frost_ristretto255_sha512_secret_share_shard(void **state) {
    ECC_UNUSED(state);

    byte_t group_secret_key[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(group_secret_key, "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304", 64);
    byte_t share_polynomial_coefficients[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(share_polynomial_coefficients, "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204", 64);

    byte_t secret_key_shares[3 * ecc_frost_ristretto255_sha512_POINTSIZE];
    byte_t coefficients[2 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_secret_share_shard(
        secret_key_shares,
        coefficients,
        group_secret_key,
        share_polynomial_coefficients,
        3, 2
    );

    char value_hex[65]; // temp for hex

    ecc_bin2hex(
        value_hex,
        &secret_key_shares[0 * ecc_frost_ristretto255_sha512_POINTSIZE + ecc_frost_ristretto255_sha512_SCALARSIZE],
        ecc_frost_ristretto255_sha512_SCALARSIZE
    );
    assert_string_equal(value_hex, "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509");
    ecc_bin2hex(
        value_hex,
        &secret_key_shares[1 * ecc_frost_ristretto255_sha512_POINTSIZE + ecc_frost_ristretto255_sha512_SCALARSIZE],
        ecc_frost_ristretto255_sha512_SCALARSIZE
    );
    assert_string_equal(value_hex, "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d");
    ecc_bin2hex(
        value_hex,
        &secret_key_shares[2 * ecc_frost_ristretto255_sha512_POINTSIZE + ecc_frost_ristretto255_sha512_SCALARSIZE],
        ecc_frost_ristretto255_sha512_SCALARSIZE
    );
    assert_string_equal(value_hex, "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02");
}

static void test_ecc_frost_ristretto255_sha512_vss_commit(void **state) {
    ECC_UNUSED(state);

    byte_t coeffs[2 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(&coeffs[0 * ecc_frost_ristretto255_sha512_SCALARSIZE], "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304", 64);
    ecc_hex2bin(&coeffs[1 * ecc_frost_ristretto255_sha512_SCALARSIZE], "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204", 64);

    byte_t vss_commitment[2 * ecc_frost_ristretto255_sha512_ELEMENTSIZE];
    ecc_frost_ristretto255_sha512_vss_commit(
        vss_commitment,
        coeffs,
        2
    );

    char value_hex[65]; // temp for hex

    ecc_bin2hex(
        value_hex,
        &vss_commitment[0 * ecc_frost_ristretto255_sha512_ELEMENTSIZE],
        ecc_frost_ristretto255_sha512_ELEMENTSIZE
    );
    assert_string_equal(value_hex, "526fc12a5eede0474f8a1b7e7e51b4bd27399f3185a4fa569bfb821d361feb03");
    ecc_bin2hex(
        value_hex,
        &vss_commitment[1 * ecc_frost_ristretto255_sha512_ELEMENTSIZE],
        ecc_frost_ristretto255_sha512_ELEMENTSIZE
    );
    assert_string_equal(value_hex, "ea96f279ad44af6f3e6ad96fbeeca26ab1d2f5ea69b817580ae3f2c3525a0930");
}

static void test_ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_coefficients(void **state) {
    ECC_UNUSED(state);

    byte_t group_secret_key[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(group_secret_key, "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304", 64);
    byte_t coefficients[1 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(&coefficients[0 * ecc_frost_ristretto255_sha512_SCALARSIZE], "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204", 64);

    byte_t participant_private_keys[3 * ecc_frost_ristretto255_sha512_POINTSIZE];
    byte_t group_public_key[ecc_frost_ristretto255_sha512_ELEMENTSIZE];
    byte_t vss_commitment[3 * ecc_frost_ristretto255_sha512_ELEMENTSIZE];
    byte_t polynomial_coefficients[2 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_coefficients(
        participant_private_keys,
        group_public_key,
        vss_commitment,
        polynomial_coefficients,
        group_secret_key,
        3, 2,
        coefficients
    );

    char value_hex[65]; // temp for hex

    ecc_bin2hex(
        value_hex,
        group_public_key,
        ecc_frost_ristretto255_sha512_ELEMENTSIZE
    );
    assert_string_equal(value_hex, "526fc12a5eede0474f8a1b7e7e51b4bd27399f3185a4fa569bfb821d361feb03");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_poc),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_schnorr_signature),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_polynomial_evaluate_small_numbers),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_1),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points_1),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_polynomial_interpolation_small_numbers_1),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_polynomial_interpolation_small_numbers_2),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_polynomial_evaluate),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_secret_share_shard),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_vss_commit),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_coefficients),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
