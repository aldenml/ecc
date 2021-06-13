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
// https://www.di-mgt.com.au/sha_testvectors.html

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

static void ecc_hash_sha512_input_abc(void **state) {
    const unsigned char *s = (const unsigned char *) "abc";
    unsigned char r[64];
    char hex[129];
    ecc_hash_sha512(s, 3, r);
    str2hex(r, 64, hex);

    assert_string_equal(hex,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

static void ecc_hash_sha512_input_empty_string(void **state) {
    const unsigned char *s = (const unsigned char *) "";
    unsigned char r[64];
    char hex[129];
    ecc_hash_sha512(s, 0, r);
    str2hex(r, 64, hex);

    assert_string_equal(hex,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

static void ecc_hash_sha512_input_abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq(void **state) {
    const unsigned char *s = (const unsigned char *) "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    unsigned char r[64];
    char hex[129];
    ecc_hash_sha512(s, 56, r);
    str2hex(r, 64, hex);

    assert_string_equal(hex,
        "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
        "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
}

static void ecc_hash_sha512_input_abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu(void **state) {
    const unsigned char *s = (const unsigned char *) "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    unsigned char r[64];
    char hex[129];
    ecc_hash_sha512(s, 112, r);
    str2hex(r, 64, hex);

    assert_string_equal(hex,
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
        "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

int main() {
    const struct CMUnitTest tests[] = {
        // sha256
        cmocka_unit_test(ecc_hash_sha256_input_abc),
        cmocka_unit_test(ecc_hash_sha256_input_empty_string),
        cmocka_unit_test(ecc_hash_sha256_input_abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq),
        cmocka_unit_test(ecc_hash_sha256_input_abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu),
        // sha512
        cmocka_unit_test(ecc_hash_sha512_input_abc),
        cmocka_unit_test(ecc_hash_sha512_input_empty_string),
        cmocka_unit_test(ecc_hash_sha512_input_abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq),
        cmocka_unit_test(ecc_hash_sha512_input_abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
