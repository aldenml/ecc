/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"
#include <stdint.h>
#include <math.h>
#include "cJSON.h"

char *readfile(const char *filename);
char *str_split(char **p_str, const char *sep);

// find a json node given a path
cJSON *json_node(cJSON *node, const char *path);

#if !ECC_LOG
void ecc_log(const char *label, const byte_t *data, const int data_len) {
    char *hex = malloc(2 * ((size_t) data_len) + 1);
    ecc_bin2hex(hex, data, data_len);
    printf("%s: %s\n", label, hex);
    free(hex);
}
#endif

char *readfile(const char *filename) {

    FILE *f = fopen(filename, "rb");

    if (f == NULL || fseek(f, 0, SEEK_END))
        return NULL;

    const long length = ftell(f);
    rewind(f);

    if (length == -1 || ((unsigned long long) length) >= SIZE_MAX) {
        fclose(f);
        return NULL;
    }

    size_t ulength = (size_t) length;
    char *buffer = malloc(ulength + 1);

    if (buffer == NULL || fread(buffer, 1, ulength, f) != ulength) {
        free(buffer);
        fclose(f);
        return NULL;
    }

    buffer[ulength] = '\0';

    fclose(f);
    return buffer;
}

char *str_split(char **p_str, const char *sep) {
    char *token = NULL;

    if (*p_str && **p_str) {
        char *p_end;

        // skip separator
        *p_str += strspn(*p_str, sep);

        p_end = *p_str;

        // find separator
        p_end = strpbrk(p_end, sep);

        // strpbrk() returns null pointer if no such character
        // exists in the input string which is part of sep argument.
        if (!p_end)
            p_end = *p_str + strlen(*p_str);

        const char *start = *p_str;
        const char *end = p_end;
        if (!start || !end || (start >= end))
            token = NULL;

        token = malloc((size_t) (end - start + 1));
        if (token) {
            memcpy (token, start, end - start);
            token[end - start] = '\0';
        } else
            return NULL;

        *p_str = p_end;
    }

    return token;
}

cJSON *json_node(cJSON *node, const char *path) {

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
#endif

    char *ptr = (char *) path;

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
    char *token = NULL;

    while ((token = str_split(&ptr, ".")) != NULL) {
        node = cJSON_GetObjectItemCaseSensitive(node, token);
        free(token);
    }

    return node;
}

static ecc_json_t invalid_json = {NULL};

ecc_json_t ecc_json_load(const char *filename) {

    char *value = readfile(filename);

    ecc_json_t ret = invalid_json;

    if (value) {
        ret.handle = cJSON_Parse(value);
        free(value);
    }

    return ret;
}

void ecc_json_destroy(ecc_json_t json) {
    if (json.handle) {
        cJSON_Delete(json.handle);
        json.handle = NULL;
    }
}

int ecc_json_is_valid(ecc_json_t json) {
    if (json.handle)
        return 1;
    else
        return 0;
}

ecc_json_t ecc_json_object(ecc_json_t json, const char *path) {
    if (!ecc_json_is_valid(json))
        return invalid_json;

    cJSON *node = json_node(json.handle, path);
    ecc_json_t ret = {node};

    return ret;
}

const char *ecc_json_string(ecc_json_t json, const char *path) {
    ecc_json_t obj = ecc_json_object(json, path);
    return obj.handle ? cJSON_GetStringValue(obj.handle) : NULL;
}

double ecc_json_number(ecc_json_t json, const char *path) {
    ecc_json_t obj = ecc_json_object(json, path);
    return obj.handle ? cJSON_GetNumberValue(obj.handle) : (double) NAN;
}

int ecc_json_array_size(ecc_json_t json, const char *path) {
    if (!ecc_json_is_valid(json))
        return -1;

    cJSON *node = json_node(json.handle, path);

    if (!cJSON_IsArray(node))
        return -1;

    return cJSON_GetArraySize(node);
}

ecc_json_t ecc_json_array_item(ecc_json_t json, const char *path, const int index) {
    if (!ecc_json_is_valid(json))
        return invalid_json;

    cJSON *node = json_node(json.handle, path);

    if (!cJSON_IsArray(node))
        return invalid_json;

    node = cJSON_GetArrayItem(node, index);
    ecc_json_t ret = {node};

    return ret;
}

const char *ecc_json_array_string(ecc_json_t json, const char *path, const int index) {
    ecc_json_t item = ecc_json_array_item(json, path, index);
    return item.handle ? cJSON_GetStringValue(item.handle) : NULL;
}

double ecc_json_array_number(ecc_json_t json, const char *path, const int index) {
    ecc_json_t item = ecc_json_array_item(json, path, index);
    return item.handle ? cJSON_GetNumberValue(item.handle) : (double) NAN;
}

void ecc_json_hex(
    byte_t *bin, int *bin_len,
    ecc_json_t json, const char *path
) {
    const char *hex = ecc_json_string(json, path);
    if (hex != NULL) {
        const int hex_len = (int) strlen(hex);
        *bin_len = hex_len / 2;
        ecc_hex2bin(bin, hex, hex_len);
    } else
        *bin_len = 0;
}
