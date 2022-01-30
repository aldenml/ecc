/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include <stdio.h>

static void hkdf_sha512_extract_test(void **state) {
    ECC_UNUSED(state);

    byte_t salt[10];
    ecc_hex2bin(salt, "8e94ef805b93e683ff18", 20);
    byte_t ikm[5];
    ecc_hex2bin(ikm, "68656c6c6f", 10);

    byte_t prk[64];
    ecc_kdf_hkdf_sha512_extract(
        prk,
        salt, sizeof salt,
        ikm, sizeof ikm
    );

    char hex[129];
    ecc_bin2hex(hex, prk, sizeof prk);
    assert_string_equal(hex, "457c311719813785096ef45f466aead3db4e535f4a7b0d06084621c0e01220a6b43b90879fc23189d4fed6456e31529905bdc83056feda5940444893a83808bd");
}

static void hkdf_sha512_expand_test(void **state) {
    ECC_UNUSED(state);

    byte_t prk[64];
    ecc_hex2bin(prk, "457c311719813785096ef45f466aead3db4e535f4a7b0d06084621c0e01220a6b43b90879fc23189d4fed6456e31529905bdc83056feda5940444893a83808bd", 128);
    byte_t info[4];
    ecc_hex2bin(info, "01020304", 8);

    byte_t okm1[16];
    ecc_kdf_hkdf_sha512_expand(
        okm1,
        prk,
        info, sizeof info,
        16
    );
    byte_t okm2[32];
    ecc_kdf_hkdf_sha512_expand(
        okm2,
        prk,
        info, sizeof info,
        32
    );
    byte_t okm3[64];
    ecc_kdf_hkdf_sha512_expand(
        okm3,
        prk,
        info, sizeof info,
        64
    );

    char hex1[33];
    ecc_bin2hex(hex1, okm1, sizeof okm1);
    assert_string_equal(hex1, "3f78dfe76193f8ca9761f28f0e58453c");
    char hex2[65];
    ecc_bin2hex(hex2, okm2, sizeof okm2);
    assert_string_equal(hex2, "3f78dfe76193f8ca9761f28f0e58453cc8ec97db968b4eebe95a2c664382ccea");
    char hex3[129];
    ecc_bin2hex(hex3, okm3, sizeof okm3);
    assert_string_equal(hex3, "3f78dfe76193f8ca9761f28f0e58453cc8ec97db968b4eebe95a2c664382ccea9fdff742512ff986cc7faae377461d5e455bdf62de4b862bdafcc966f9cfe527");
}

static void test_scrypt_1(void **state) {
    ECC_UNUSED(state);

    const byte_t *P = NULL;
    const byte_t *S = NULL;

    byte_t out[64];
    ecc_kdf_scrypt(out, P, 0, S, 0,
        16, 1, 1,
        64
    );

    char hex[129];
    ecc_bin2hex(hex, out, sizeof out);
    assert_string_equal(hex, "77d6576238657b203b19ca42c18a0497"
                             "f16b4844e3074ae8dfdffa3fede21442"
                             "fcd0069ded0948f8326a753a0fc81f17"
                             "e8d3e0fb2e0d3628cf35e20c38d18906");
}

static void test_scrypt_2(void **state) {
    ECC_UNUSED(state);

    byte_t P[8] = "password";
    byte_t S[4] = "NaCl";

    byte_t out[64];
    ecc_kdf_scrypt(out, P, sizeof P, S, sizeof S,
        1024, 8, 16,
        64
    );

    char hex[129];
    ecc_bin2hex(hex, out, sizeof out);
    assert_string_equal(hex, "fdbabe1c9d3472007856e7190d01e9fe"
                             "7c6ad7cbc8237830e77376634b373162"
                             "2eaf30d92e22a3886ff109279d9830da"
                             "c727afb94a83ee6d8360cbdfa2cc0640");
}

static void test_scrypt_3(void **state) {
    ECC_UNUSED(state);

    byte_t P[13] = "pleaseletmein";
    byte_t S[14] = "SodiumChloride";

    byte_t out[64];
    ecc_kdf_scrypt(out, P, sizeof P, S, sizeof S,
        16384, 8, 1,
        64
    );

    char hex[129];
    ecc_bin2hex(hex, out, sizeof out);
    assert_string_equal(hex, "7023bdcb3afd7348461c06cd81fd38eb"
                             "fda8fbba904f8e3ea9b543f6545da1f2"
                             "d5432955613f0fcf62d49705242a9af9"
                             "e61e85dc0d651e40dfcf017b45575887");
}

static void test_scrypt_4(void **state) {
    ECC_UNUSED(state);

    byte_t P[13] = "pleaseletmein";
    byte_t S[14] = "SodiumChloride";

    byte_t out[64];
    ecc_kdf_scrypt(out, P, sizeof P, S, sizeof S,
        1048576, 8, 1,
        64
    );

    char hex[129];
    ecc_bin2hex(hex, out, sizeof out);
    assert_string_equal(hex, "2101cb9b6a511aaeaddbbe09cf70f881"
                             "ec568d574a2ffd4dabe5ee9820adaa47"
                             "8e56fd8f4ba5d09ffa1c6d927c40f4c3"
                             "37304049e8a952fbcbf45c6fa77a41a4");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(hkdf_sha512_extract_test),
        cmocka_unit_test(hkdf_sha512_expand_test),
        cmocka_unit_test(test_scrypt_1),
        cmocka_unit_test(test_scrypt_2),
        cmocka_unit_test(test_scrypt_3),
        cmocka_unit_test(test_scrypt_4),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
