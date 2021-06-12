#include "../hash.h"
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include <stdio.h>

void str2hex(const unsigned char *in, int len, char *out) {
    for (int i = 0; i < len; i++) {
        sprintf((char *) (out + 2 * i), "%02x", in[i]);
    }
    out[2 * len + 1] = '\0';
}

// Test vectors
// https://www.di-mgt.com.au/sha_testvectors.html#FIPS-180

static void ecc_hash_sha256_input_abc(void **state) {
    const unsigned char *s = (const unsigned char *) "abc";
    unsigned char r[32];
    char hex[65];
    ecc_hash_sha256(s, 3, r);
    str2hex(r, 32, hex);

    assert_string_equal(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static void ecc_hash_sha256_input_empty_string(void **state) {
    const unsigned char *s = (const unsigned char *) "";
    unsigned char r[32];
    char hex[65];
    ecc_hash_sha256(s, 0, r);
    str2hex(r, 32, hex);

    assert_string_equal(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

static void ecc_hash_sha256_input_abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq(void **state) {
    const unsigned char *s = (const unsigned char *) "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    unsigned char r[32];
    char hex[65];
    ecc_hash_sha256(s, 56, r);
    str2hex(r, 32, hex);

    assert_string_equal(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

static void ecc_hash_sha256_input_abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu(void **state) {
    const unsigned char *s = (const unsigned char *) "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    unsigned char r[32];
    char hex[65];
    ecc_hash_sha256(s, 112, r);
    str2hex(r, 32, hex);

    assert_string_equal(hex, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(ecc_hash_sha256_input_abc),
        cmocka_unit_test(ecc_hash_sha256_input_empty_string),
        cmocka_unit_test(ecc_hash_sha256_input_abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq),
        cmocka_unit_test(ecc_hash_sha256_input_abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
