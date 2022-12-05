/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

static void test_read_string(void **state) {
    ECC_UNUSED(state);

    ecc_json_t *json = ecc_json_load("../test/data/read_json_test.json");

    const char *v1 = ecc_json_string(json, "p1");
    const char *v2 = ecc_json_string(json, "p2.p3");

    assert_string_equal(v1, "a");
    assert_string_equal(v2, "b");

    ecc_json_destroy(json);
}

static void test_read_array(void **state) {
    ECC_UNUSED(state);

    ecc_json_t *json = ecc_json_load("../test/data/read_json_test.json");

    const int len = ecc_json_array_size(json, "a1.a2");
    const char *v1 = ecc_json_array_string(json, "a1.a2", 1);

    assert_int_equal(len, 3);
    assert_string_equal(v1, "t1");

    ecc_json_destroy(json);
}

static void test_ecc_json_array_items(void **state) {
    ECC_UNUSED(state);

    ecc_json_t *json = ecc_json_load("../test/data/read_json_test.json");

    const int len = ecc_json_array_size(json, "vec");
    ecc_json_t *item1 = ecc_json_array_item(json, "vec", 0);
    const char *v1 = ecc_json_string(item1, "val");
    ecc_json_t *item2 = ecc_json_array_item(json, "vec", 1);
    const char *v2 = ecc_json_string(item2, "val");

    assert_int_equal(len, 2);
    assert_string_equal(v1, "a");
    assert_string_equal(v2, "b");

    ecc_json_destroy(json);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_string),
        cmocka_unit_test(test_read_array),
        cmocka_unit_test(test_ecc_json_array_items),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
