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
#include <cmocka.h>
#include <stdio.h>

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#appendix-C.1

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#appendix-C.1.2
static void opaque_ristretto255_sha512_test1(void **state) {
    byte_t password[25];
    ecc_hex2bin(password, "436f7272656374486f72736542617474657279537461706c65", 50);
    byte_t envelope_nonce[32];
    ecc_hex2bin(envelope_nonce, "71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c4676775", 64);
    byte_t envelope_nonce_ex[42];
    byte_t suffix[10] = "PrivateKey";
    ecc_concat2(envelope_nonce_ex, envelope_nonce, 32, suffix, 10);

//    byte_t seed[32];
//    ecc_kdf_hkdf_sha512_expand(seed, 32, envelope_nonce_ex, 42, )
//
//    byte_t private_key[32];
//    byte_t public_key[32];
//    ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(blindedElement, input, 1, blind);
//
//    char blindedElementHex[65];
//    ecc_bin2hex(blindedElementHex, blindedElement, 32);
//    assert_string_equal(blindedElementHex, "3c7f2d901c0d4f245503a186086fbdf5d8b4408432b25c5163e8b5a19c258348");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(opaque_ristretto255_sha512_test1),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
