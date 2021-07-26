/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_UTIL_H
#define ECC_UTIL_H

#include "export.h"

// internal
#define ECC_UNUSED(x) (void)(x)

/**
 * Tries to effectively zero the memory pointed by `buf` even
 * if optimizations are being applied to the compiler.
 *
 * @param buf the memory pointer
 * @param len the length of `buf`
 */
ECC_OPRF_EXPORT
ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_memzero(byte_t *buf, int len);

/**
 * Fills `n` bytes at buf with an unpredictable sequence of bytes.
 *
 * @param buf (output) the byte array to fill
 * @param n the number of bytes to fill
 */
ECC_OPRF_EXPORT
ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_randombytes(byte_t *buf, int n);

/**
 * Converts a byte array to the hex string.
 *
 * @param hex (output) the hex encoded string
 * @param bin the input byte array
 * @param bin_len the length of `bin`
 */
ECC_EXPORT
void ecc_bin2hex(char *hex, const byte_t *bin, int bin_len);

/**
 * Converts an hex string to a byte array.
 *
 * @param bin (output) the byte array
 * @param hex the input hex string
 * @param hex_len the length of `hex`
 */
ECC_EXPORT
void ecc_hex2bin(byte_t *bin, const char *hex, int hex_len);

/**
 * Concatenates two byte arrays. Sames as a || b.
 *
 * a || b: denotes the concatenation of byte strings a and b. For
 * example, "ABC" || "DEF" == "ABCDEF".
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-4
 *
 * @param out (output) result of the concatenation
 * @param a1 first byte array
 * @param a1_len the length of `a1`
 * @param a2 second byte array
 * @param a2_len the length of `a2`
 */
ECC_EXPORT
void ecc_concat2(
    byte_t *out,
    const byte_t *a1, int a1_len,
    const byte_t *a2, int a2_len
);

/**
 * Same as calling ecc_concat2 but with three byte arrays.
 *
 * @param out (output) result of the concatenation
 * @param a1 first byte array
 * @param a1_len the length of `a1`
 * @param a2 second byte array
 * @param a2_len the length of `a2`
 * @param a3 third byte array
 * @param a3_len the length of `a3`
 */
ECC_EXPORT
void ecc_concat3(
    byte_t *out,
    const byte_t *a1, int a1_len,
    const byte_t *a2, int a2_len,
    const byte_t *a3, int a3_len
);

/**
 * Same as calling ecc_concat2 but with four byte arrays.
 *
 * @param out (output) result of the concatenation
 * @param a1 first byte array
 * @param a1_len the length of `a1`
 * @param a2 second byte array
 * @param a2_len the length of `a2`
 * @param a3 third byte array
 * @param a3_len the length of `a4`
 * @param a4 fourth byte array
 * @param a4_len the length of `a4`
 */
ECC_EXPORT
void ecc_concat4(
    byte_t *out,
    const byte_t *a1, int a1_len,
    const byte_t *a2, int a2_len,
    const byte_t *a3, int a3_len,
    const byte_t *a4, int a4_len
);

/**
 * For byte strings a and b, ecc_strxor(a, b) returns the bitwise XOR of
 * the two byte strings. For example, ecc_strxor("abc", "XYZ") == "9;9" (the
 * strings in this example are ASCII literals, but ecc_strxor is defined for
 * arbitrary byte strings).
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-4
 *
 * @param out (output) result of the operation
 * @param a first byte array
 * @param b second byte array
 * @param len length of both `a` and `b`
 */
ECC_EXPORT
void ecc_strxor(byte_t *out, const byte_t *a, const byte_t *b, int len);

/**
 * I2OSP converts a nonnegative integer to an octet string of a
 * specified length.
 *
 * See https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
 *
 * @param out (output) corresponding octet string of length xLen
 * @param x nonnegative integer to be converted
 * @param xLen intended length of the resulting octet string
 */
ECC_EXPORT
void ecc_I2OSP(byte_t *out, int x, int xLen);

/**
 * Takes two pointers to unsigned numbers encoded in little-endian
 * format and returns:
 *
 * -1 if a < b
 * 0 if a == b
 * 1 if a > b
 *
 * The comparison is done in constant time
 *
 * @param a first unsigned integer argument
 * @param b second unsigned integer argument
 * @param len the length of both `a` and `b`
 */
ECC_EXPORT
int ecc_compare(const byte_t *a, const byte_t *b, int len);

/**
 * Takes a byte array and test if it contains only zeros. It runs
 * in constant-time.
 *
 * @param n the byte array
 * @param len the length of `n`
 * @return 0 if non-zero bits are found
 */
ECC_EXPORT
int ecc_is_zero(const byte_t *n, int len);

/**
 * Allocates size bytes of uninitialized storage.
 *
 * To avoid a memory leak, the returned pointer must be deallocated
 * with `ecc_free`.
 *
 * NOTE: this is mostly to help binding implementations.
 *
 * @param size number of bytes to allocate
 * @return the pointer to the beginning of newly allocated memory
 */
ECC_EXPORT
byte_t *ecc_malloc(int size);

/**
 * Deallocates the space previously allocated by `ecc_malloc`.
 *
 * NOTE: this is mostly to help binding implementations.
 *
 * @param p pointer to the memory to deallocate
 * @param size size of the allocated memory
 */
ECC_EXPORT
void ecc_free(byte_t *p, int size);

// the following is a private log facility, used mostly to
// verify partial state values in protocols implementations
#ifndef ECC_LOG
#define ECC_LOG 0
#endif
#if ECC_LOG
void ecc_log(const char *label, const byte_t *data, int data_len);
#endif

#endif // ECC_UTIL_H
