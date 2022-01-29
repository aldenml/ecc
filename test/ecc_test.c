/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "cJSON.h"

#if !ECC_LOG
void ecc_log(const char *label, const byte_t *data, const int data_len) {
    char *hex = malloc(2 * data_len + 1);
    ecc_bin2hex(hex, data, data_len);
    printf("%s: %s\n", label, hex);
    free(hex);
}
#endif

struct ecc_json {
    cJSON *handle;
};

char *readfile(const char *filename) {

    FILE *f = fopen(filename, "rb");

    if (f == NULL || fseek(f, 0, SEEK_END))
        return NULL;

    const long length = ftell(f);
    rewind(f);

    if (length == -1 || (unsigned long) length >= SIZE_MAX) {
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

        token = malloc(end - start + 1);
        if (token) {
            memcpy (token, start, end - start);
            token[end - start] = '\0';
        } else
            return NULL;

        *p_str = p_end;
    }

    return token;
}

ecc_json_t *ecc_json_load(const char *filename) {

    char *value = readfile(filename);

    ecc_json_t *ret = NULL;

    if (value) {
        ret = malloc(sizeof(ecc_json_t));
        ret->handle = cJSON_Parse(value);
        if (ret->handle == NULL)
            ret = NULL;
        free(value);
    }

    return ret;
}

void ecc_json_destroy(ecc_json_t *json) {
    if (json && json->handle) {
        cJSON_Delete(json->handle);
        json->handle = NULL;
        free(json);
    }
}

int ecc_json_is_valid(ecc_json_t *json) {
    if (json && json->handle)
        return 1;
    else
        return 0;
}

const char *ecc_json_string(ecc_json_t *json, const char *path) {
    if (!ecc_json_is_valid(json))
        return NULL;

    cJSON *node = json->handle;

    char *ptr = (char *) path;
    char *token = NULL;

    while ((token = str_split(&ptr, ".")) != NULL) {
        node = cJSON_GetObjectItemCaseSensitive(node, token);
        free(token);
    }

    return cJSON_GetStringValue(node);
}

int ecc_json_array_size(ecc_json_t *json, const char *path) {
    if (!ecc_json_is_valid(json))
        return -1;

    cJSON *node = json->handle;

    char *ptr = (char *) path;
    char *token = NULL;

    while ((token = str_split(&ptr, ".")) != NULL) {
        node = cJSON_GetObjectItemCaseSensitive(node, token);
        free(token);
    }

    if (!cJSON_IsArray(node))
        return -1;

    return cJSON_GetArraySize(node);
}

const char *ecc_json_array_string(ecc_json_t *json, const char *path, int index) {
    if (!ecc_json_is_valid(json))
        return NULL;

    cJSON *node = json->handle;

    char *ptr = (char *) path;
    char *token = NULL;

    while ((token = str_split(&ptr, ".")) != NULL) {
        node = cJSON_GetObjectItemCaseSensitive(node, token);
        free(token);
    }

    if (!cJSON_IsArray(node))
        return NULL;

    node = cJSON_GetArrayItem(node, index);

    return cJSON_GetStringValue(node);
}
