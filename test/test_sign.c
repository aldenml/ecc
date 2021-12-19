/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc.h"
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>
#include "ecc_log.h"

static void ecc_sign_bls12_381_keygen_test(void **state) {
    ECC_UNUSED(state);

    byte_t seed[64] = {0};
    ecc_hex2bin(seed,
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                128);
    byte_t sk[ecc_sign_bls12_381_PRIVATEKEYSIZE];
    ecc_sign_bls12_381_KeyGen(sk, seed, sizeof seed);
    ecc_log("sk", sk, sizeof sk);
}

static void ecc_sign_bls12_381_test(void **state) {
    ECC_UNUSED(state);

    byte_t seed[64] = {0};
    ecc_hex2bin(seed,
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                128);

    byte_t pk[ecc_sign_bls12_381_PUBLICKEYSIZE];
    byte_t sk[ecc_sign_bls12_381_PRIVATEKEYSIZE];
    ecc_sign_bls12_381_KeyGen(sk, seed, sizeof seed);
    ecc_sign_bls12_381_SkToPk(pk, sk);

    ecc_log("pk", pk, sizeof pk);
    ecc_log("sk", sk, sizeof sk);

    byte_t msg[5] = "hello";

    byte_t sig[ecc_sign_bls12_381_SIGNATURESIZE];
    ecc_sign_bls12_381_CoreSign(sig, msg, sizeof msg, sk);
    ecc_log("sig", sig, sizeof sig);

    int r = ecc_sign_bls12_381_CoreVerify(pk, msg, sizeof msg, sig);
    assert_int_equal(r, 0);

    // mess with the sig
    sig[0] = 0;
    r = ecc_sign_bls12_381_CoreVerify(pk, msg, sizeof msg, sig);
    assert_int_equal(r, -1);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(ecc_sign_bls12_381_keygen_test),
        cmocka_unit_test(ecc_sign_bls12_381_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
