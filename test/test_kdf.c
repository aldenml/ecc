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
#include "test_util.h"

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
    char hex3[33];
    ecc_bin2hex(hex3, okm3, sizeof okm3);
    assert_string_equal(hex3, "3f78dfe76193f8ca9761f28f0e58453cc8ec97db968b4eebe95a2c664382ccea9fdff742512ff986cc7faae377461d5e455bdf62de4b862bdafcc966f9cfe527");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(hkdf_sha512_extract_test),
        cmocka_unit_test(hkdf_sha512_expand_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
