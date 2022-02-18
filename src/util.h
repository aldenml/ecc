/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_UTIL_H
#define ECC_UTIL_H

#include "export.h"

// This is useful to avoid warnings of unused arguments in the
// implementations. You can use it in your own code.
#define ECC_UNUSED(x) (void)(x)

/**
 * Tries to effectively zero the memory pointed by `buf` even
 * if optimizations are being applied to the compiler.
 *
 * @param buf the memory pointer, size:len
 * @param len the length of `buf`
 */
ECC_EXPORT
void ecc_memzero(byte_t *buf, int len);

/**
 * Fills `n` bytes at `buf` with an unpredictable sequence of bytes.
 *
 * @param[out] buf the byte array to fill, size:n
 * @param n the number of bytes to fill
 */
ECC_EXPORT
void ecc_randombytes(byte_t *buf, int n);

/**
 * Converts a byte array to the hex string.
 *
 * @param[out] hex the hex encoded string, size:2*bin_len+1
 * @param bin the input byte array, size:bin_len
 * @param bin_len the length of `bin`
 */
ECC_EXPORT
void ecc_bin2hex(char *hex, const byte_t *bin, int bin_len);

/**
 * Converts an hex string to a byte array.
 *
 * @param[out] bin the byte array, size:hex_len/2
 * @param hex the input hex string, size:hex_len
 * @param hex_len the length of `hex`
 */
ECC_EXPORT
void ecc_hex2bin(byte_t *bin, const char *hex, int hex_len);

/**
 * Concatenates two byte arrays. Same as a || b.
 *
 * a || b: denotes the concatenation of byte strings a and b. For
 * example, "ABC" || "DEF" == "ABCDEF".
 *
 * @param[out] out result of the concatenation, size:a1_len+a2_len
 * @param a1 first byte array, size:a1_len
 * @param a1_len the length of `a1`
 * @param a2 second byte array, size:a2_len
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
 * @param[out] out result of the concatenation, size:a1_len+a2_len+a3_len
 * @param a1 first byte array, size:a1_len
 * @param a1_len the length of `a1`
 * @param a2 second byte array, size:a2_len
 * @param a2_len the length of `a2`
 * @param a3 third byte array, size:a3_len
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
 * @param[out] out result of the concatenation, size:a1_len+a2_len+a3_len+a4_len
 * @param a1 first byte array, size:a1_len
 * @param a1_len the length of `a1`
 * @param a2 second byte array, size:a2_len
 * @param a2_len the length of `a2`
 * @param a3 third byte array, size:a3_len
 * @param a3_len the length of `a4`
 * @param a4 fourth byte array, size:a4_len
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
 * @param[out] out result of the operation, size:len
 * @param a first byte array, size:len
 * @param b second byte array, size:len
 * @param len length of both `a` and `b`
 */
ECC_EXPORT
void ecc_strxor(byte_t *out, const byte_t *a, const byte_t *b, int len);

/**
 * I2OSP converts a non-negative integer to an octet string of a
 * specified length.
 *
 * See https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
 *
 * @param[out] out corresponding octet string of length xLen, size:xLen
 * @param x non-negative integer to be converted
 * @param xLen intended length of the resulting octet string
 */
ECC_EXPORT
void ecc_I2OSP(byte_t *out, int x, int xLen);

/**
 * Takes two pointers to unsigned numbers encoded in little-endian
 * format and returns:
 *
 * -1 if a is less than b
 * 0 if a is equals to b
 * 1 if a is greater than b
 *
 * The comparison is done in constant time
 *
 * @param a first unsigned integer argument, size:len
 * @param b second unsigned integer argument, size:len
 * @param len the length of both `a` and `b`
 * @return the result of the comparison
 */
ECC_EXPORT
int ecc_compare(const byte_t *a, const byte_t *b, int len);

/**
 * Takes a byte array and test if it contains only zeros. It runs
 * in constant time.
 *
 * @param n the byte array, size:len
 * @param len the length of `n`
 * @return 0 if non-zero bits are found
 */
ECC_EXPORT
int ecc_is_zero(const byte_t *n, int len);

/**
 * Allocates `size` bytes of uninitialized storage.
 *
 * To avoid a memory leak and for security reasons, the returned
 * pointer must be deallocated with `ecc_free`.
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
 * @param p pointer to the memory to deallocate, size:size
 * @param size size of the allocated memory
 */
ECC_EXPORT
void ecc_free(byte_t *p, int size);

// the following is a private log facility, used mostly to
// verify partial state values in protocols implementations
#ifndef ECC_LOG
#define ECC_LOG 1
#endif
#if ECC_LOG
ECC_EXPORT
void ecc_log(const char *label, const byte_t *data, int data_len);
#endif

#endif // ECC_UTIL_H
