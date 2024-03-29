/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_TEST_H
#define ECC_TEST_H

#include "ecc.h"
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpadded"
#endif

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic ignored "-Wreserved-id-macro"
#endif

#include <cmocka.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#if !ECC_LOG
void ecc_log(const char *label, const byte_t *data, int data_len);
#endif

typedef struct {
    void *handle;
} ecc_json_t;

ecc_json_t ecc_json_load(const char *filename);

void ecc_json_destroy(ecc_json_t json);

int ecc_json_is_valid(ecc_json_t json);

ecc_json_t ecc_json_object(ecc_json_t json, const char *path);

const char *ecc_json_string(ecc_json_t json, const char *path);

double ecc_json_number(ecc_json_t json, const char *path);

int ecc_json_array_size(ecc_json_t json, const char *path);

ecc_json_t ecc_json_array_item(ecc_json_t json, const char *path, int index);

const char *ecc_json_array_string(ecc_json_t json, const char *path, int index);

double ecc_json_array_number(ecc_json_t json, const char *path, int index);

/**
 * Utility function to read an hex string from a json string value.
 */
void ecc_json_hex(
    byte_t *bin, int *bin_len,
    ecc_json_t json, const char *path
);

#endif // ECC_TEST_H
