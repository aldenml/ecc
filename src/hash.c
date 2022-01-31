/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "hash.h"

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcpp"
#endif

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcpp"
#endif

#ifdef _MSC_VER
#pragma warning(push, 1)
//#pragma warning(disable: ?)
#endif

#include <sodium.h>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

void ecc_hash_sha256(byte_t *digest, const byte_t *input, const int input_len) {
    crypto_hash_sha256(digest, input, (unsigned long long) input_len);
}

void ecc_hash_sha512(byte_t *digest, const byte_t *input, const int input_len) {
    crypto_hash_sha512(digest, input, (unsigned long long) input_len);
}
