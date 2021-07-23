/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_TEST_UTIL_H
#define ECC_TEST_UTIL_H

#include "ecc.h"
#include <stdlib.h>

static void logd(const char *label, const byte_t *data, const int data_len) {
    char *hex = malloc(2 * (data_len + 1));
    ecc_bin2hex(hex, data, data_len);
    printf("%s: %s\n", label, hex);
    free(hex);
}

#endif // ECC_TEST_UTIL_H
