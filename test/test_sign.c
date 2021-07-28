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

static void ecc_sign_bls_eth2_keygen_test(void **state) {
    ECC_UNUSED(state);

    byte_t seed[32] = {0};
    //ecc_hex2bin(seed, "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04", 128);
    byte_t sk[ecc_sign_bls_eth2_PRIVATEKEYSIZE];
    ecc_sign_bls_eth2_keygen(sk, seed, sizeof seed);
    ecc_log("sk", sk, sizeof sk);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(ecc_sign_bls_eth2_keygen_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
