/**
 * @param {Uint8Array} src
 * @param {number} srcPos
 * @param {Uint8Array} dest
 * @param {number} destPos
 * @param {number} length
 */
function arraycopy(src, srcPos, dest, destPos, length) {
    dest.set(src.subarray(srcPos, srcPos + length), destPos);
}

/**
 * @param {Uint8Array} src
 * @param {number} size
 * @return {number}
 */
function mput(src, size) {
    if (!src) return 0;
    const pos = _ecc_malloc(size);
    arraycopy(src, 0, HEAPU8, pos, size);
    return pos;
}

/**
 * @param {Uint8Array} dest
 * @param {number} pos
 * @param {number} size
 */
function mget(dest, pos, size) {
    arraycopy(HEAPU8, pos, dest, 0, size);
}

/**
 * @param {number} ptr
 * @param {number} size
 */
function mfree(ptr, size) {
    _ecc_free(ptr, size);
}

// util


/**
 * Fills `n` bytes at `buf` with an unpredictable sequence of bytes.
 *
 * @param {Uint8Array} buf (output) the byte array to fill, size:n
 * @param {number} n the number of bytes to fill
 */
Module.ecc_randombytes = (
    buf,
    n,
) => {
    const ptr_buf = mput(buf, n);
    _ecc_randombytes(
        ptr_buf,
        n,
    );
    mget(buf, ptr_buf, n);
    mfree(ptr_buf, n);
}

/**
 * Concatenates two byte arrays. Same as a || b.
 *
 * a || b: denotes the concatenation of byte strings a and b. For
 * example, "ABC" || "DEF" == "ABCDEF".
 *
 * @param {Uint8Array} out (output) result of the concatenation, size:a1_len+a2_len
 * @param {Uint8Array} a1 first byte array, size:a1_len
 * @param {number} a1_len the length of `a1`
 * @param {Uint8Array} a2 second byte array, size:a2_len
 * @param {number} a2_len the length of `a2`
 */
Module.ecc_concat2 = (
    out,
    a1,
    a1_len,
    a2,
    a2_len,
) => {
    const ptr_out = mput(out, a1_len+a2_len);
    const ptr_a1 = mput(a1, a1_len);
    const ptr_a2 = mput(a2, a2_len);
    _ecc_concat2(
        ptr_out,
        ptr_a1,
        a1_len,
        ptr_a2,
        a2_len,
    );
    mget(out, ptr_out, a1_len+a2_len);
    mfree(ptr_out, a1_len+a2_len);
    mfree(ptr_a1, a1_len);
    mfree(ptr_a2, a2_len);
}

/**
 * Same as calling ecc_concat2 but with three byte arrays.
 *
 * @param {Uint8Array} out (output) result of the concatenation, size:a1_len+a2_len+a3_len
 * @param {Uint8Array} a1 first byte array, size:a1_len
 * @param {number} a1_len the length of `a1`
 * @param {Uint8Array} a2 second byte array, size:a2_len
 * @param {number} a2_len the length of `a2`
 * @param {Uint8Array} a3 third byte array, size:a3_len
 * @param {number} a3_len the length of `a3`
 */
Module.ecc_concat3 = (
    out,
    a1,
    a1_len,
    a2,
    a2_len,
    a3,
    a3_len,
) => {
    const ptr_out = mput(out, a1_len+a2_len+a3_len);
    const ptr_a1 = mput(a1, a1_len);
    const ptr_a2 = mput(a2, a2_len);
    const ptr_a3 = mput(a3, a3_len);
    _ecc_concat3(
        ptr_out,
        ptr_a1,
        a1_len,
        ptr_a2,
        a2_len,
        ptr_a3,
        a3_len,
    );
    mget(out, ptr_out, a1_len+a2_len+a3_len);
    mfree(ptr_out, a1_len+a2_len+a3_len);
    mfree(ptr_a1, a1_len);
    mfree(ptr_a2, a2_len);
    mfree(ptr_a3, a3_len);
}

/**
 * Same as calling ecc_concat2 but with four byte arrays.
 *
 * @param {Uint8Array} out (output) result of the concatenation, size:a1_len+a2_len+a3_len+a4_len
 * @param {Uint8Array} a1 first byte array, size:a1_len
 * @param {number} a1_len the length of `a1`
 * @param {Uint8Array} a2 second byte array, size:a2_len
 * @param {number} a2_len the length of `a2`
 * @param {Uint8Array} a3 third byte array, size:a3_len
 * @param {number} a3_len the length of `a4`
 * @param {Uint8Array} a4 fourth byte array, size:a4_len
 * @param {number} a4_len the length of `a4`
 */
Module.ecc_concat4 = (
    out,
    a1,
    a1_len,
    a2,
    a2_len,
    a3,
    a3_len,
    a4,
    a4_len,
) => {
    const ptr_out = mput(out, a1_len+a2_len+a3_len+a4_len);
    const ptr_a1 = mput(a1, a1_len);
    const ptr_a2 = mput(a2, a2_len);
    const ptr_a3 = mput(a3, a3_len);
    const ptr_a4 = mput(a4, a4_len);
    _ecc_concat4(
        ptr_out,
        ptr_a1,
        a1_len,
        ptr_a2,
        a2_len,
        ptr_a3,
        a3_len,
        ptr_a4,
        a4_len,
    );
    mget(out, ptr_out, a1_len+a2_len+a3_len+a4_len);
    mfree(ptr_out, a1_len+a2_len+a3_len+a4_len);
    mfree(ptr_a1, a1_len);
    mfree(ptr_a2, a2_len);
    mfree(ptr_a3, a3_len);
    mfree(ptr_a4, a4_len);
}

/**
 * For byte strings a and b, ecc_strxor(a, b) returns the bitwise XOR of
 * the two byte strings. For example, ecc_strxor("abc", "XYZ") == "9;9" (the
 * strings in this example are ASCII literals, but ecc_strxor is defined for
 * arbitrary byte strings).
 *
 * @param {Uint8Array} out (output) result of the operation, size:len
 * @param {Uint8Array} a first byte array, size:len
 * @param {Uint8Array} b second byte array, size:len
 * @param {number} len length of both `a` and `b`
 */
Module.ecc_strxor = (
    out,
    a,
    b,
    len,
) => {
    const ptr_out = mput(out, len);
    const ptr_a = mput(a, len);
    const ptr_b = mput(b, len);
    _ecc_strxor(
        ptr_out,
        ptr_a,
        ptr_b,
        len,
    );
    mget(out, ptr_out, len);
    mfree(ptr_out, len);
    mfree(ptr_a, len);
    mfree(ptr_b, len);
}

/**
 * I2OSP converts a non-negative integer to an octet string of a
 * specified length.
 *
 * See https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
 *
 * @param {Uint8Array} out (output) corresponding octet string of length xLen, size:xLen
 * @param {number} x non-negative integer to be converted
 * @param {number} xLen intended length of the resulting octet string
 */
Module.ecc_I2OSP = (
    out,
    x,
    xLen,
) => {
    const ptr_out = mput(out, xLen);
    _ecc_I2OSP(
        ptr_out,
        x,
        xLen,
    );
    mget(out, ptr_out, xLen);
    mfree(ptr_out, xLen);
}

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
 * @param {Uint8Array} a first unsigned integer argument, size:len
 * @param {Uint8Array} b second unsigned integer argument, size:len
 * @param {number} len the length of both `a` and `b`
 * @return {number} the result of the comparison
 */
Module.ecc_compare = (
    a,
    b,
    len,
) => {
    const ptr_a = mput(a, len);
    const ptr_b = mput(b, len);
    const fun_ret = _ecc_compare(
        ptr_a,
        ptr_b,
        len,
    );
    mfree(ptr_a, len);
    mfree(ptr_b, len);
    return fun_ret;
}

/**
 * Takes a byte array and test if it contains only zeros. It runs
 * in constant time.
 *
 * @param {Uint8Array} n the byte array, size:len
 * @param {number} len the length of `n`
 * @return {number} 0 if non-zero bits are found
 */
Module.ecc_is_zero = (
    n,
    len,
) => {
    const ptr_n = mput(n, len);
    const fun_ret = _ecc_is_zero(
        ptr_n,
        len,
    );
    mfree(ptr_n, len);
    return fun_ret;
}

// hash

const ecc_hash_sha256_HASHSIZE = 32;
/**
 * The size of a SHA-256 digest.
 *
 * @type {number}
 */
Module.ecc_hash_sha256_HASHSIZE = ecc_hash_sha256_HASHSIZE;

const ecc_hash_sha512_HASHSIZE = 64;
/**
 * The size of a SHA-512 digest.
 *
 * @type {number}
 */
Module.ecc_hash_sha512_HASHSIZE = ecc_hash_sha512_HASHSIZE;

/**
 * Computes the SHA-256 of a given input.
 *
 * See https://en.wikipedia.org/wiki/SHA-2
 *
 * @param {Uint8Array} digest (output) the SHA-256 of the input, size:ecc_hash_sha256_HASHSIZE
 * @param {Uint8Array} input the input message, size:input_len
 * @param {number} input_len the length of `input`
 */
Module.ecc_hash_sha256 = (
    digest,
    input,
    input_len,
) => {
    const ptr_digest = mput(digest, ecc_hash_sha256_HASHSIZE);
    const ptr_input = mput(input, input_len);
    _ecc_hash_sha256(
        ptr_digest,
        ptr_input,
        input_len,
    );
    mget(digest, ptr_digest, ecc_hash_sha256_HASHSIZE);
    mfree(ptr_digest, ecc_hash_sha256_HASHSIZE);
    mfree(ptr_input, input_len);
}

/**
 * Computes the SHA-512 of a given input.
 *
 * See https://en.wikipedia.org/wiki/SHA-2
 *
 * @param {Uint8Array} digest (output) the SHA-512 of the input, size:ecc_hash_sha512_HASHSIZE
 * @param {Uint8Array} input the input message, size:input_len
 * @param {number} input_len the length of `input`
 */
Module.ecc_hash_sha512 = (
    digest,
    input,
    input_len,
) => {
    const ptr_digest = mput(digest, ecc_hash_sha512_HASHSIZE);
    const ptr_input = mput(input, input_len);
    _ecc_hash_sha512(
        ptr_digest,
        ptr_input,
        input_len,
    );
    mget(digest, ptr_digest, ecc_hash_sha512_HASHSIZE);
    mfree(ptr_digest, ecc_hash_sha512_HASHSIZE);
    mfree(ptr_input, input_len);
}

// mac

const ecc_mac_hmac_sha256_HASHSIZE = 32;
/**
 * Size of the HMAC-SHA-256 digest.
 *
 * @type {number}
 */
Module.ecc_mac_hmac_sha256_HASHSIZE = ecc_mac_hmac_sha256_HASHSIZE;

const ecc_mac_hmac_sha512_HASHSIZE = 64;
/**
 * Size of the HMAC-SHA-512 digest.
 *
 * @type {number}
 */
Module.ecc_mac_hmac_sha512_HASHSIZE = ecc_mac_hmac_sha512_HASHSIZE;

/**
 * Computes the HMAC-SHA-256 of the input stream.
 *
 * See https://datatracker.ietf.org/doc/html/rfc2104
 * See https://datatracker.ietf.org/doc/html/rfc4868
 *
 * @param {Uint8Array} digest (output) the HMAC-SHA-256 of the input, size:ecc_mac_hmac_sha256_HASHSIZE
 * @param {Uint8Array} text the input message, size:text_len
 * @param {number} text_len the length of `input`
 * @param {Uint8Array} key authentication key, size:key_len
 * @param {number} key_len the length of `key`
 */
Module.ecc_mac_hmac_sha256 = (
    digest,
    text,
    text_len,
    key,
    key_len,
) => {
    const ptr_digest = mput(digest, ecc_mac_hmac_sha256_HASHSIZE);
    const ptr_text = mput(text, text_len);
    const ptr_key = mput(key, key_len);
    _ecc_mac_hmac_sha256(
        ptr_digest,
        ptr_text,
        text_len,
        ptr_key,
        key_len,
    );
    mget(digest, ptr_digest, ecc_mac_hmac_sha256_HASHSIZE);
    mfree(ptr_digest, ecc_mac_hmac_sha256_HASHSIZE);
    mfree(ptr_text, text_len);
    mfree(ptr_key, key_len);
}

/**
 * Computes the HMAC-SHA-512 of the input stream.
 *
 * See https://datatracker.ietf.org/doc/html/rfc2104
 * See https://datatracker.ietf.org/doc/html/rfc4868
 *
 * @param {Uint8Array} digest (output) the HMAC-SHA-512 of the input, size:ecc_mac_hmac_sha512_HASHSIZE
 * @param {Uint8Array} text the input message, size:text_len
 * @param {number} text_len the length of `input`
 * @param {Uint8Array} key authentication key, size:key_len
 * @param {number} key_len the length of `key`
 */
Module.ecc_mac_hmac_sha512 = (
    digest,
    text,
    text_len,
    key,
    key_len,
) => {
    const ptr_digest = mput(digest, ecc_mac_hmac_sha512_HASHSIZE);
    const ptr_text = mput(text, text_len);
    const ptr_key = mput(key, key_len);
    _ecc_mac_hmac_sha512(
        ptr_digest,
        ptr_text,
        text_len,
        ptr_key,
        key_len,
    );
    mget(digest, ptr_digest, ecc_mac_hmac_sha512_HASHSIZE);
    mfree(ptr_digest, ecc_mac_hmac_sha512_HASHSIZE);
    mfree(ptr_text, text_len);
    mfree(ptr_key, key_len);
}

// kdf

const ecc_kdf_hkdf_sha256_KEYSIZE = 32;
/**
 * Key size for HKDF-SHA-256.
 *
 * @type {number}
 */
Module.ecc_kdf_hkdf_sha256_KEYSIZE = ecc_kdf_hkdf_sha256_KEYSIZE;

const ecc_kdf_hkdf_sha512_KEYSIZE = 64;
/**
 * Key size for HKDF-SHA-512.
 *
 * @type {number}
 */
Module.ecc_kdf_hkdf_sha512_KEYSIZE = ecc_kdf_hkdf_sha512_KEYSIZE;

/**
 * Computes the HKDF-SHA-256 extract of the input using a key material.
 *
 * See https://datatracker.ietf.org/doc/html/rfc5869
 *
 * @param {Uint8Array} prk (output) a pseudorandom key, size:ecc_kdf_hkdf_sha256_KEYSIZE
 * @param {Uint8Array} salt optional salt value (a non-secret random value), size:salt_len
 * @param {number} salt_len the length of `salt`
 * @param {Uint8Array} ikm input keying material, size:ikm_len
 * @param {number} ikm_len the length of `ikm`
 */
Module.ecc_kdf_hkdf_sha256_extract = (
    prk,
    salt,
    salt_len,
    ikm,
    ikm_len,
) => {
    const ptr_prk = mput(prk, ecc_kdf_hkdf_sha256_KEYSIZE);
    const ptr_salt = mput(salt, salt_len);
    const ptr_ikm = mput(ikm, ikm_len);
    _ecc_kdf_hkdf_sha256_extract(
        ptr_prk,
        ptr_salt,
        salt_len,
        ptr_ikm,
        ikm_len,
    );
    mget(prk, ptr_prk, ecc_kdf_hkdf_sha256_KEYSIZE);
    mfree(ptr_prk, ecc_kdf_hkdf_sha256_KEYSIZE);
    mfree(ptr_salt, salt_len);
    mfree(ptr_ikm, ikm_len);
}

/**
 * Computes the HKDF-SHA-256 expand of the input using a key.
 *
 * See https://datatracker.ietf.org/doc/html/rfc5869
 *
 * @param {Uint8Array} okm (output) output keying material of length `len`, size:len
 * @param {Uint8Array} prk a pseudorandom key, size:ecc_kdf_hkdf_sha256_KEYSIZE
 * @param {Uint8Array} info optional context and application specific information, size:info_len
 * @param {number} info_len length of `info`
 * @param {number} len length of output keying material in octets, max allowed value is 8160
 */
Module.ecc_kdf_hkdf_sha256_expand = (
    okm,
    prk,
    info,
    info_len,
    len,
) => {
    const ptr_okm = mput(okm, len);
    const ptr_prk = mput(prk, ecc_kdf_hkdf_sha256_KEYSIZE);
    const ptr_info = mput(info, info_len);
    _ecc_kdf_hkdf_sha256_expand(
        ptr_okm,
        ptr_prk,
        ptr_info,
        info_len,
        len,
    );
    mget(okm, ptr_okm, len);
    mfree(ptr_okm, len);
    mfree(ptr_prk, ecc_kdf_hkdf_sha256_KEYSIZE);
    mfree(ptr_info, info_len);
}

/**
 * Computes the HKDF-SHA-512 extract of the input using a key material.
 *
 * See https://datatracker.ietf.org/doc/html/rfc5869
 *
 * @param {Uint8Array} prk (output) a pseudorandom key, size:ecc_kdf_hkdf_sha512_KEYSIZE
 * @param {Uint8Array} salt optional salt value (a non-secret random value), size:salt_len
 * @param {number} salt_len the length of `salt`
 * @param {Uint8Array} ikm input keying material, size:ikm_len
 * @param {number} ikm_len the length of `ikm`
 */
Module.ecc_kdf_hkdf_sha512_extract = (
    prk,
    salt,
    salt_len,
    ikm,
    ikm_len,
) => {
    const ptr_prk = mput(prk, ecc_kdf_hkdf_sha512_KEYSIZE);
    const ptr_salt = mput(salt, salt_len);
    const ptr_ikm = mput(ikm, ikm_len);
    _ecc_kdf_hkdf_sha512_extract(
        ptr_prk,
        ptr_salt,
        salt_len,
        ptr_ikm,
        ikm_len,
    );
    mget(prk, ptr_prk, ecc_kdf_hkdf_sha512_KEYSIZE);
    mfree(ptr_prk, ecc_kdf_hkdf_sha512_KEYSIZE);
    mfree(ptr_salt, salt_len);
    mfree(ptr_ikm, ikm_len);
}

/**
 * Computes the HKDF-SHA-512 expand of the input using a key.
 *
 * See https://datatracker.ietf.org/doc/html/rfc5869
 *
 * @param {Uint8Array} okm (output) output keying material of length `len`, size:len
 * @param {Uint8Array} prk a pseudorandom key, size:ecc_kdf_hkdf_sha512_KEYSIZE
 * @param {Uint8Array} info optional context and application specific information, size:info_len
 * @param {number} info_len length of `info`
 * @param {number} len length of output keying material in octets, max allowed value is 16320
 */
Module.ecc_kdf_hkdf_sha512_expand = (
    okm,
    prk,
    info,
    info_len,
    len,
) => {
    const ptr_okm = mput(okm, len);
    const ptr_prk = mput(prk, ecc_kdf_hkdf_sha512_KEYSIZE);
    const ptr_info = mput(info, info_len);
    _ecc_kdf_hkdf_sha512_expand(
        ptr_okm,
        ptr_prk,
        ptr_info,
        info_len,
        len,
    );
    mget(okm, ptr_okm, len);
    mfree(ptr_okm, len);
    mfree(ptr_prk, ecc_kdf_hkdf_sha512_KEYSIZE);
    mfree(ptr_info, info_len);
}

/**
 * See https://datatracker.ietf.org/doc/html/rfc7914
 *
 * @param {Uint8Array} out (output) size:len
 * @param {Uint8Array} passphrase size:passphrase_len
 * @param {number} passphrase_len the length of `passphrase`
 * @param {Uint8Array} salt size:salt_len
 * @param {number} salt_len the length of `salt`
 * @param {number} cost cpu/memory cost
 * @param {number} block_size block size
 * @param {number} parallelization parallelization
 * @param {number} len intended output length
 * @return {number} 0 on success and -1 if the computation didn't complete
 */
Module.ecc_kdf_scrypt = (
    out,
    passphrase,
    passphrase_len,
    salt,
    salt_len,
    cost,
    block_size,
    parallelization,
    len,
) => {
    const ptr_out = mput(out, len);
    const ptr_passphrase = mput(passphrase, passphrase_len);
    const ptr_salt = mput(salt, salt_len);
    const fun_ret = _ecc_kdf_scrypt(
        ptr_out,
        ptr_passphrase,
        passphrase_len,
        ptr_salt,
        salt_len,
        cost,
        block_size,
        parallelization,
        len,
    );
    mget(out, ptr_out, len);
    mfree(ptr_out, len);
    mfree(ptr_passphrase, passphrase_len);
    mfree(ptr_salt, salt_len);
    return fun_ret;
}

// ed25519

const ecc_ed25519_ELEMENTSIZE = 32;
/**
 * Size of the serialized group elements.
 *
 * @type {number}
 */
Module.ecc_ed25519_ELEMENTSIZE = ecc_ed25519_ELEMENTSIZE;

const ecc_ed25519_UNIFORMSIZE = 32;
/**
 * Size of the input to perform the Elligator 2 map operation.
 *
 * @type {number}
 */
Module.ecc_ed25519_UNIFORMSIZE = ecc_ed25519_UNIFORMSIZE;

const ecc_ed25519_SCALARSIZE = 32;
/**
 * Size of the scalar used in the curve operations.
 *
 * @type {number}
 */
Module.ecc_ed25519_SCALARSIZE = ecc_ed25519_SCALARSIZE;

const ecc_ed25519_NONREDUCEDSCALARSIZE = 64;
/**
 * Size of a non reduced scalar.
 *
 * @type {number}
 */
Module.ecc_ed25519_NONREDUCEDSCALARSIZE = ecc_ed25519_NONREDUCEDSCALARSIZE;

/**
 * Checks that p represents a point on the edwards25519 curve, in canonical
 * form, on the main subgroup, and that the point doesn't have a small order.
 *
 * @param {Uint8Array} p potential point to test, size:ecc_ed25519_ELEMENTSIZE
 * @return {number} 1 on success, and 0 if the checks didn't pass
 */
Module.ecc_ed25519_is_valid_point = (
    p,
) => {
    const ptr_p = mput(p, ecc_ed25519_ELEMENTSIZE);
    const fun_ret = _ecc_ed25519_is_valid_point(
        ptr_p,
    );
    mfree(ptr_p, ecc_ed25519_ELEMENTSIZE);
    return fun_ret;
}

/**
 * Adds the point p to the point q and stores the resulting point into r.
 *
 * @param {Uint8Array} r (output) the result, size:ecc_ed25519_ELEMENTSIZE
 * @param {Uint8Array} p input point operand, size:ecc_ed25519_ELEMENTSIZE
 * @param {Uint8Array} q input point operand, size:ecc_ed25519_ELEMENTSIZE
 * @return {number} 0 on success, or -1 if p and/or q are not valid points
 */
Module.ecc_ed25519_add = (
    r,
    p,
    q,
) => {
    const ptr_r = mput(r, ecc_ed25519_ELEMENTSIZE);
    const ptr_p = mput(p, ecc_ed25519_ELEMENTSIZE);
    const ptr_q = mput(q, ecc_ed25519_ELEMENTSIZE);
    const fun_ret = _ecc_ed25519_add(
        ptr_r,
        ptr_p,
        ptr_q,
    );
    mget(r, ptr_r, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_r, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_p, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_q, ecc_ed25519_ELEMENTSIZE);
    return fun_ret;
}

/**
 * Subtracts the point p to the point q and stores the resulting point into r.
 *
 * @param {Uint8Array} r (output) the result, size:ecc_ed25519_ELEMENTSIZE
 * @param {Uint8Array} p input point operand, size:ecc_ed25519_ELEMENTSIZE
 * @param {Uint8Array} q input point operand, size:ecc_ed25519_ELEMENTSIZE
 * @return {number} 0 on success, or -1 if p and/or q are not valid points
 */
Module.ecc_ed25519_sub = (
    r,
    p,
    q,
) => {
    const ptr_r = mput(r, ecc_ed25519_ELEMENTSIZE);
    const ptr_p = mput(p, ecc_ed25519_ELEMENTSIZE);
    const ptr_q = mput(q, ecc_ed25519_ELEMENTSIZE);
    const fun_ret = _ecc_ed25519_sub(
        ptr_r,
        ptr_p,
        ptr_q,
    );
    mget(r, ptr_r, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_r, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_p, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_q, ecc_ed25519_ELEMENTSIZE);
    return fun_ret;
}

/**
 * Main group base point (x, 4/5), generator of the prime group.
 *
 * @param {Uint8Array} g (output) size:ecc_ed25519_ELEMENTSIZE
 */
Module.ecc_ed25519_generator = (
    g,
) => {
    const ptr_g = mput(g, ecc_ed25519_ELEMENTSIZE);
    _ecc_ed25519_generator(
        ptr_g,
    );
    mget(g, ptr_g, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_g, ecc_ed25519_ELEMENTSIZE);
}

/**
 * Maps a 32 bytes vector r to a point, and stores its compressed
 * representation into p. The point is guaranteed to be on the main
 * subgroup.
 *
 * This function directly exposes the Elligator 2 map. Uses the high
 * bit to set the sign of the X coordinate, and the resulting point is
 * multiplied by the cofactor.
 *
 * @param {Uint8Array} p (output) point in the main subgroup, size:ecc_ed25519_ELEMENTSIZE
 * @param {Uint8Array} r input vector, size:ecc_ed25519_UNIFORMSIZE
 */
Module.ecc_ed25519_from_uniform = (
    p,
    r,
) => {
    const ptr_p = mput(p, ecc_ed25519_ELEMENTSIZE);
    const ptr_r = mput(r, ecc_ed25519_UNIFORMSIZE);
    _ecc_ed25519_from_uniform(
        ptr_p,
        ptr_r,
    );
    mget(p, ptr_p, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_p, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_r, ecc_ed25519_UNIFORMSIZE);
}

/**
 * Fills p with the representation of a random group element.
 *
 * @param {Uint8Array} p (output) random group element, size:ecc_ed25519_ELEMENTSIZE
 */
Module.ecc_ed25519_random = (
    p,
) => {
    const ptr_p = mput(p, ecc_ed25519_ELEMENTSIZE);
    _ecc_ed25519_random(
        ptr_p,
    );
    mget(p, ptr_p, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_p, ecc_ed25519_ELEMENTSIZE);
}

/**
 * Chose a random scalar in the [0..L[ interval, L being the order of the
 * main subgroup (2^252 + 27742317777372353535851937790883648493) and fill
 * r with the bytes.
 *
 * @param {Uint8Array} r (output) scalar, size:ecc_ed25519_SCALARSIZE
 */
Module.ecc_ed25519_scalar_random = (
    r,
) => {
    const ptr_r = mput(r, ecc_ed25519_SCALARSIZE);
    _ecc_ed25519_scalar_random(
        ptr_r,
    );
    mget(r, ptr_r, ecc_ed25519_SCALARSIZE);
    mfree(ptr_r, ecc_ed25519_SCALARSIZE);
}

/**
 * Computes the multiplicative inverse of s over L, and puts it into recip.
 *
 * @param {Uint8Array} recip (output) the result, size:ecc_ed25519_SCALARSIZE
 * @param {Uint8Array} s an scalar, size:ecc_ed25519_SCALARSIZE
 * @return {number} 0 on success, or -1 if s is zero
 */
Module.ecc_ed25519_scalar_invert = (
    recip,
    s,
) => {
    const ptr_recip = mput(recip, ecc_ed25519_SCALARSIZE);
    const ptr_s = mput(s, ecc_ed25519_SCALARSIZE);
    const fun_ret = _ecc_ed25519_scalar_invert(
        ptr_recip,
        ptr_s,
    );
    mget(recip, ptr_recip, ecc_ed25519_SCALARSIZE);
    mfree(ptr_recip, ecc_ed25519_SCALARSIZE);
    mfree(ptr_s, ecc_ed25519_SCALARSIZE);
    return fun_ret;
}

/**
 * Returns neg so that s + neg = 0 (mod L).
 *
 * @param {Uint8Array} neg (output) the result, size:ecc_ed25519_SCALARSIZE
 * @param {Uint8Array} s an scalar, size:ecc_ed25519_SCALARSIZE
 */
Module.ecc_ed25519_scalar_negate = (
    neg,
    s,
) => {
    const ptr_neg = mput(neg, ecc_ed25519_SCALARSIZE);
    const ptr_s = mput(s, ecc_ed25519_SCALARSIZE);
    _ecc_ed25519_scalar_negate(
        ptr_neg,
        ptr_s,
    );
    mget(neg, ptr_neg, ecc_ed25519_SCALARSIZE);
    mfree(ptr_neg, ecc_ed25519_SCALARSIZE);
    mfree(ptr_s, ecc_ed25519_SCALARSIZE);
}

/**
 * Returns comp so that s + comp = 1 (mod L).
 *
 * @param {Uint8Array} comp (output) the result, size:ecc_ed25519_SCALARSIZE
 * @param {Uint8Array} s an scalar, size:ecc_ed25519_SCALARSIZE
 */
Module.ecc_ed25519_scalar_complement = (
    comp,
    s,
) => {
    const ptr_comp = mput(comp, ecc_ed25519_SCALARSIZE);
    const ptr_s = mput(s, ecc_ed25519_SCALARSIZE);
    _ecc_ed25519_scalar_complement(
        ptr_comp,
        ptr_s,
    );
    mget(comp, ptr_comp, ecc_ed25519_SCALARSIZE);
    mfree(ptr_comp, ecc_ed25519_SCALARSIZE);
    mfree(ptr_s, ecc_ed25519_SCALARSIZE);
}

/**
 * Stores x + y (mod L) into z.
 *
 * @param {Uint8Array} z (output) the result, size:ecc_ed25519_SCALARSIZE
 * @param {Uint8Array} x input scalar operand, size:ecc_ed25519_SCALARSIZE
 * @param {Uint8Array} y input scalar operand, size:ecc_ed25519_SCALARSIZE
 */
Module.ecc_ed25519_scalar_add = (
    z,
    x,
    y,
) => {
    const ptr_z = mput(z, ecc_ed25519_SCALARSIZE);
    const ptr_x = mput(x, ecc_ed25519_SCALARSIZE);
    const ptr_y = mput(y, ecc_ed25519_SCALARSIZE);
    _ecc_ed25519_scalar_add(
        ptr_z,
        ptr_x,
        ptr_y,
    );
    mget(z, ptr_z, ecc_ed25519_SCALARSIZE);
    mfree(ptr_z, ecc_ed25519_SCALARSIZE);
    mfree(ptr_x, ecc_ed25519_SCALARSIZE);
    mfree(ptr_y, ecc_ed25519_SCALARSIZE);
}

/**
 * Stores x - y (mod L) into z.
 *
 * @param {Uint8Array} z (output) the result, size:ecc_ed25519_SCALARSIZE
 * @param {Uint8Array} x input scalar operand, size:ecc_ed25519_SCALARSIZE
 * @param {Uint8Array} y input scalar operand, size:ecc_ed25519_SCALARSIZE
 */
Module.ecc_ed25519_scalar_sub = (
    z,
    x,
    y,
) => {
    const ptr_z = mput(z, ecc_ed25519_SCALARSIZE);
    const ptr_x = mput(x, ecc_ed25519_SCALARSIZE);
    const ptr_y = mput(y, ecc_ed25519_SCALARSIZE);
    _ecc_ed25519_scalar_sub(
        ptr_z,
        ptr_x,
        ptr_y,
    );
    mget(z, ptr_z, ecc_ed25519_SCALARSIZE);
    mfree(ptr_z, ecc_ed25519_SCALARSIZE);
    mfree(ptr_x, ecc_ed25519_SCALARSIZE);
    mfree(ptr_y, ecc_ed25519_SCALARSIZE);
}

/**
 * Stores x * y (mod L) into z.
 *
 * @param {Uint8Array} z (output) the result, size:ecc_ed25519_SCALARSIZE
 * @param {Uint8Array} x input scalar operand, size:ecc_ed25519_SCALARSIZE
 * @param {Uint8Array} y input scalar operand, size:ecc_ed25519_SCALARSIZE
 */
Module.ecc_ed25519_scalar_mul = (
    z,
    x,
    y,
) => {
    const ptr_z = mput(z, ecc_ed25519_SCALARSIZE);
    const ptr_x = mput(x, ecc_ed25519_SCALARSIZE);
    const ptr_y = mput(y, ecc_ed25519_SCALARSIZE);
    _ecc_ed25519_scalar_mul(
        ptr_z,
        ptr_x,
        ptr_y,
    );
    mget(z, ptr_z, ecc_ed25519_SCALARSIZE);
    mfree(ptr_z, ecc_ed25519_SCALARSIZE);
    mfree(ptr_x, ecc_ed25519_SCALARSIZE);
    mfree(ptr_y, ecc_ed25519_SCALARSIZE);
}

/**
 * Reduces s to s mod L and puts the bytes representing the integer
 * into r where L = (2^252 + 27742317777372353535851937790883648493) is
 * the order of the group.
 *
 * The interval `s` is sampled from should be at least 317 bits to
 * ensure almost uniformity of `r` over `L`.
 *
 * @param {Uint8Array} r (output) the reduced scalar, size:ecc_ed25519_SCALARSIZE
 * @param {Uint8Array} s the integer to reduce, size:ecc_ed25519_NONREDUCEDSCALARSIZE
 */
Module.ecc_ed25519_scalar_reduce = (
    r,
    s,
) => {
    const ptr_r = mput(r, ecc_ed25519_SCALARSIZE);
    const ptr_s = mput(s, ecc_ed25519_NONREDUCEDSCALARSIZE);
    _ecc_ed25519_scalar_reduce(
        ptr_r,
        ptr_s,
    );
    mget(r, ptr_r, ecc_ed25519_SCALARSIZE);
    mfree(ptr_r, ecc_ed25519_SCALARSIZE);
    mfree(ptr_s, ecc_ed25519_NONREDUCEDSCALARSIZE);
}

/**
 * Multiplies a point p by a valid scalar n (clamped) and puts
 * the Y coordinate of the resulting point into q.
 *
 * This function returns 0 on success, or -1 if n is 0 or if p is not
 * on the curve, not on the main subgroup, is a point of small order,
 * or is not provided in canonical form.
 *
 * Note that n is "clamped" (the 3 low bits are cleared to make it a
 * multiple of the cofactor, bit 254 is set and bit 255 is cleared to
 * respect the original design). This prevents attacks using small
 * subgroups. If you want to implement protocols that involve blinding
 * operations, use ristretto255.
 *
 * @param {Uint8Array} q (output) the result, size:ecc_ed25519_ELEMENTSIZE
 * @param {Uint8Array} n the valid input scalar, size:ecc_ed25519_SCALARSIZE
 * @param {Uint8Array} p the point on the curve, size:ecc_ed25519_ELEMENTSIZE
 * @return {number} 0 on success, or -1 otherwise.
 */
Module.ecc_ed25519_scalarmult = (
    q,
    n,
    p,
) => {
    const ptr_q = mput(q, ecc_ed25519_ELEMENTSIZE);
    const ptr_n = mput(n, ecc_ed25519_SCALARSIZE);
    const ptr_p = mput(p, ecc_ed25519_ELEMENTSIZE);
    const fun_ret = _ecc_ed25519_scalarmult(
        ptr_q,
        ptr_n,
        ptr_p,
    );
    mget(q, ptr_q, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_q, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_n, ecc_ed25519_SCALARSIZE);
    mfree(ptr_p, ecc_ed25519_ELEMENTSIZE);
    return fun_ret;
}

/**
 * Multiplies the base point (x, 4/5) by a scalar n (clamped) and puts
 * the Y coordinate of the resulting point into q.
 *
 * Note that n is "clamped" (the 3 low bits are cleared to make it a
 * multiple of the cofactor, bit 254 is set and bit 255 is cleared to
 * respect the original design). This prevents attacks using small
 * subgroups. If you want to implement protocols that involve blinding
 * operations, use ristretto255.
 *
 * @param {Uint8Array} q (output) the result, size:ecc_ed25519_ELEMENTSIZE
 * @param {Uint8Array} n the valid input scalar, size:ecc_ed25519_SCALARSIZE
 * @return {number} -1 if n is 0, and 0 otherwise.
 */
Module.ecc_ed25519_scalarmult_base = (
    q,
    n,
) => {
    const ptr_q = mput(q, ecc_ed25519_ELEMENTSIZE);
    const ptr_n = mput(n, ecc_ed25519_SCALARSIZE);
    const fun_ret = _ecc_ed25519_scalarmult_base(
        ptr_q,
        ptr_n,
    );
    mget(q, ptr_q, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_q, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_n, ecc_ed25519_SCALARSIZE);
    return fun_ret;
}

// ristretto255

const ecc_ristretto255_ELEMENTSIZE = 32;
/**
 * Size of the serialized group elements.
 *
 * @type {number}
 */
Module.ecc_ristretto255_ELEMENTSIZE = ecc_ristretto255_ELEMENTSIZE;

const ecc_ristretto255_HASHSIZE = 64;
/**
 * Size of the hash input to use on the hash to map operation.
 *
 * @type {number}
 */
Module.ecc_ristretto255_HASHSIZE = ecc_ristretto255_HASHSIZE;

const ecc_ristretto255_SCALARSIZE = 32;
/**
 * Size of the scalar used in the curve operations.
 *
 * @type {number}
 */
Module.ecc_ristretto255_SCALARSIZE = ecc_ristretto255_SCALARSIZE;

const ecc_ristretto255_NONREDUCEDSCALARSIZE = 64;
/**
 * Size of a non reduced scalar.
 *
 * @type {number}
 */
Module.ecc_ristretto255_NONREDUCEDSCALARSIZE = ecc_ristretto255_NONREDUCEDSCALARSIZE;

/**
 * Checks that p is a valid ristretto255-encoded element. This operation
 * only checks that p is in canonical form.
 *
 * @param {Uint8Array} p potential point to test, size:ecc_ristretto255_ELEMENTSIZE
 * @return {number} 1 on success, and 0 if the checks didn't pass.
 */
Module.ecc_ristretto255_is_valid_point = (
    p,
) => {
    const ptr_p = mput(p, ecc_ristretto255_ELEMENTSIZE);
    const fun_ret = _ecc_ristretto255_is_valid_point(
        ptr_p,
    );
    mfree(ptr_p, ecc_ristretto255_ELEMENTSIZE);
    return fun_ret;
}

/**
 * Adds the element represented by p to the element q and stores
 * the resulting element into r.
 *
 * @param {Uint8Array} r (output) the result, size:ecc_ristretto255_ELEMENTSIZE
 * @param {Uint8Array} p input point operand, size:ecc_ristretto255_ELEMENTSIZE
 * @param {Uint8Array} q input point operand, size:ecc_ristretto255_ELEMENTSIZE
 * @return {number} 0 on success, or -1 if p and/or q are not valid encoded elements
 */
Module.ecc_ristretto255_add = (
    r,
    p,
    q,
) => {
    const ptr_r = mput(r, ecc_ristretto255_ELEMENTSIZE);
    const ptr_p = mput(p, ecc_ristretto255_ELEMENTSIZE);
    const ptr_q = mput(q, ecc_ristretto255_ELEMENTSIZE);
    const fun_ret = _ecc_ristretto255_add(
        ptr_r,
        ptr_p,
        ptr_q,
    );
    mget(r, ptr_r, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_r, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_p, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_q, ecc_ristretto255_ELEMENTSIZE);
    return fun_ret;
}

/**
 * Subtracts the element represented by p to the element q and stores
 * the resulting element into r.
 *
 * @param {Uint8Array} r (output) the result, size:ecc_ristretto255_ELEMENTSIZE
 * @param {Uint8Array} p input point operand, size:ecc_ristretto255_ELEMENTSIZE
 * @param {Uint8Array} q input point operand, size:ecc_ristretto255_ELEMENTSIZE
 * @return {number} 0 on success, or -1 if p and/or q are not valid encoded elements
 */
Module.ecc_ristretto255_sub = (
    r,
    p,
    q,
) => {
    const ptr_r = mput(r, ecc_ristretto255_ELEMENTSIZE);
    const ptr_p = mput(p, ecc_ristretto255_ELEMENTSIZE);
    const ptr_q = mput(q, ecc_ristretto255_ELEMENTSIZE);
    const fun_ret = _ecc_ristretto255_sub(
        ptr_r,
        ptr_p,
        ptr_q,
    );
    mget(r, ptr_r, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_r, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_p, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_q, ecc_ristretto255_ELEMENTSIZE);
    return fun_ret;
}

/**
 *
 *
 * @param {Uint8Array} g (output) size:ecc_ristretto255_ELEMENTSIZE
 */
Module.ecc_ristretto255_generator = (
    g,
) => {
    const ptr_g = mput(g, ecc_ristretto255_ELEMENTSIZE);
    _ecc_ristretto255_generator(
        ptr_g,
    );
    mget(g, ptr_g, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_g, ecc_ristretto255_ELEMENTSIZE);
}

/**
 * Maps a 64 bytes vector r (usually the output of a hash function) to
 * a group element, and stores its representation into p.
 *
 * @param {Uint8Array} p (output) group element, size:ecc_ristretto255_ELEMENTSIZE
 * @param {Uint8Array} r bytes vector hash, size:ecc_ristretto255_HASHSIZE
 */
Module.ecc_ristretto255_from_hash = (
    p,
    r,
) => {
    const ptr_p = mput(p, ecc_ristretto255_ELEMENTSIZE);
    const ptr_r = mput(r, ecc_ristretto255_HASHSIZE);
    _ecc_ristretto255_from_hash(
        ptr_p,
        ptr_r,
    );
    mget(p, ptr_p, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_p, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_r, ecc_ristretto255_HASHSIZE);
}

/**
 * Fills p with the representation of a random group element.
 *
 * @param {Uint8Array} p (output) random group element, size:ecc_ristretto255_ELEMENTSIZE
 */
Module.ecc_ristretto255_random = (
    p,
) => {
    const ptr_p = mput(p, ecc_ristretto255_ELEMENTSIZE);
    _ecc_ristretto255_random(
        ptr_p,
    );
    mget(p, ptr_p, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_p, ecc_ristretto255_ELEMENTSIZE);
}

/**
 * Fills r with a bytes representation of the scalar in
 * the ]0..L[ interval where L is the order of the
 * group (2^252 + 27742317777372353535851937790883648493).
 *
 * @param {Uint8Array} r (output) random scalar, size:ecc_ristretto255_SCALARSIZE
 */
Module.ecc_ristretto255_scalar_random = (
    r,
) => {
    const ptr_r = mput(r, ecc_ristretto255_SCALARSIZE);
    _ecc_ristretto255_scalar_random(
        ptr_r,
    );
    mget(r, ptr_r, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_r, ecc_ristretto255_SCALARSIZE);
}

/**
 * Computes the multiplicative inverse of s over L, and puts it into recip.
 *
 * @param {Uint8Array} recip (output) the result, size:ecc_ristretto255_SCALARSIZE
 * @param {Uint8Array} s an scalar, size:ecc_ristretto255_SCALARSIZE
 * @return {number} 0 on success, or -1 if s is zero
 */
Module.ecc_ristretto255_scalar_invert = (
    recip,
    s,
) => {
    const ptr_recip = mput(recip, ecc_ristretto255_SCALARSIZE);
    const ptr_s = mput(s, ecc_ristretto255_SCALARSIZE);
    const fun_ret = _ecc_ristretto255_scalar_invert(
        ptr_recip,
        ptr_s,
    );
    mget(recip, ptr_recip, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_recip, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_s, ecc_ristretto255_SCALARSIZE);
    return fun_ret;
}

/**
 * Returns neg so that s + neg = 0 (mod L).
 *
 * @param {Uint8Array} neg (output) the result, size:ecc_ristretto255_SCALARSIZE
 * @param {Uint8Array} s an scalar, size:ecc_ristretto255_SCALARSIZE
 */
Module.ecc_ristretto255_scalar_negate = (
    neg,
    s,
) => {
    const ptr_neg = mput(neg, ecc_ristretto255_SCALARSIZE);
    const ptr_s = mput(s, ecc_ristretto255_SCALARSIZE);
    _ecc_ristretto255_scalar_negate(
        ptr_neg,
        ptr_s,
    );
    mget(neg, ptr_neg, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_neg, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_s, ecc_ristretto255_SCALARSIZE);
}

/**
 * Returns comp so that s + comp = 1 (mod L).
 *
 * @param {Uint8Array} comp (output) the result, size:ecc_ristretto255_SCALARSIZE
 * @param {Uint8Array} s an scalar, size:ecc_ristretto255_SCALARSIZE
 */
Module.ecc_ristretto255_scalar_complement = (
    comp,
    s,
) => {
    const ptr_comp = mput(comp, ecc_ristretto255_SCALARSIZE);
    const ptr_s = mput(s, ecc_ristretto255_SCALARSIZE);
    _ecc_ristretto255_scalar_complement(
        ptr_comp,
        ptr_s,
    );
    mget(comp, ptr_comp, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_comp, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_s, ecc_ristretto255_SCALARSIZE);
}

/**
 * Stores x + y (mod L) into z.
 *
 * @param {Uint8Array} z (output) the result, size:ecc_ristretto255_SCALARSIZE
 * @param {Uint8Array} x input scalar operand, size:ecc_ristretto255_SCALARSIZE
 * @param {Uint8Array} y input scalar operand, size:ecc_ristretto255_SCALARSIZE
 */
Module.ecc_ristretto255_scalar_add = (
    z,
    x,
    y,
) => {
    const ptr_z = mput(z, ecc_ristretto255_SCALARSIZE);
    const ptr_x = mput(x, ecc_ristretto255_SCALARSIZE);
    const ptr_y = mput(y, ecc_ristretto255_SCALARSIZE);
    _ecc_ristretto255_scalar_add(
        ptr_z,
        ptr_x,
        ptr_y,
    );
    mget(z, ptr_z, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_z, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_x, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_y, ecc_ristretto255_SCALARSIZE);
}

/**
 * Stores x - y (mod L) into z.
 *
 * @param {Uint8Array} z (output) the result, size:ecc_ristretto255_SCALARSIZE
 * @param {Uint8Array} x input scalar operand, size:ecc_ristretto255_SCALARSIZE
 * @param {Uint8Array} y input scalar operand, size:ecc_ristretto255_SCALARSIZE
 */
Module.ecc_ristretto255_scalar_sub = (
    z,
    x,
    y,
) => {
    const ptr_z = mput(z, ecc_ristretto255_SCALARSIZE);
    const ptr_x = mput(x, ecc_ristretto255_SCALARSIZE);
    const ptr_y = mput(y, ecc_ristretto255_SCALARSIZE);
    _ecc_ristretto255_scalar_sub(
        ptr_z,
        ptr_x,
        ptr_y,
    );
    mget(z, ptr_z, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_z, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_x, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_y, ecc_ristretto255_SCALARSIZE);
}

/**
 * Stores x * y (mod L) into z.
 *
 * @param {Uint8Array} z (output) the result, size:ecc_ristretto255_SCALARSIZE
 * @param {Uint8Array} x input scalar operand, size:ecc_ristretto255_SCALARSIZE
 * @param {Uint8Array} y input scalar operand, size:ecc_ristretto255_SCALARSIZE
 */
Module.ecc_ristretto255_scalar_mul = (
    z,
    x,
    y,
) => {
    const ptr_z = mput(z, ecc_ristretto255_SCALARSIZE);
    const ptr_x = mput(x, ecc_ristretto255_SCALARSIZE);
    const ptr_y = mput(y, ecc_ristretto255_SCALARSIZE);
    _ecc_ristretto255_scalar_mul(
        ptr_z,
        ptr_x,
        ptr_y,
    );
    mget(z, ptr_z, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_z, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_x, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_y, ecc_ristretto255_SCALARSIZE);
}

/**
 * Reduces s to s mod L and puts the bytes integer into r where
 * L = 2^252 + 27742317777372353535851937790883648493 is the order
 * of the group.
 *
 * The interval `s` is sampled from should be at least 317 bits to
 * ensure almost uniformity of `r` over `L`.
 *
 * @param {Uint8Array} r (output) the reduced scalar, size:ecc_ristretto255_SCALARSIZE
 * @param {Uint8Array} s the integer to reduce, size:ecc_ristretto255_NONREDUCEDSCALARSIZE
 */
Module.ecc_ristretto255_scalar_reduce = (
    r,
    s,
) => {
    const ptr_r = mput(r, ecc_ristretto255_SCALARSIZE);
    const ptr_s = mput(s, ecc_ristretto255_NONREDUCEDSCALARSIZE);
    _ecc_ristretto255_scalar_reduce(
        ptr_r,
        ptr_s,
    );
    mget(r, ptr_r, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_r, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_s, ecc_ristretto255_NONREDUCEDSCALARSIZE);
}

/**
 * Multiplies an element represented by p by a valid scalar n
 * and puts the resulting element into q.
 *
 * @param {Uint8Array} q (output) the result, size:ecc_ristretto255_ELEMENTSIZE
 * @param {Uint8Array} n the valid input scalar, size:ecc_ristretto255_SCALARSIZE
 * @param {Uint8Array} p the point on the curve, size:ecc_ristretto255_ELEMENTSIZE
 * @return {number} 0 on success, or -1 if q is the identity element.
 */
Module.ecc_ristretto255_scalarmult = (
    q,
    n,
    p,
) => {
    const ptr_q = mput(q, ecc_ristretto255_ELEMENTSIZE);
    const ptr_n = mput(n, ecc_ristretto255_SCALARSIZE);
    const ptr_p = mput(p, ecc_ristretto255_ELEMENTSIZE);
    const fun_ret = _ecc_ristretto255_scalarmult(
        ptr_q,
        ptr_n,
        ptr_p,
    );
    mget(q, ptr_q, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_q, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_n, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_p, ecc_ristretto255_ELEMENTSIZE);
    return fun_ret;
}

/**
 * Multiplies the generator by a valid scalar n and puts the resulting
 * element into q.
 *
 * @param {Uint8Array} q (output) the result, size:ecc_ristretto255_ELEMENTSIZE
 * @param {Uint8Array} n the valid input scalar, size:ecc_ristretto255_SCALARSIZE
 * @return {number} -1 if n is 0, and 0 otherwise.
 */
Module.ecc_ristretto255_scalarmult_base = (
    q,
    n,
) => {
    const ptr_q = mput(q, ecc_ristretto255_ELEMENTSIZE);
    const ptr_n = mput(n, ecc_ristretto255_SCALARSIZE);
    const fun_ret = _ecc_ristretto255_scalarmult_base(
        ptr_q,
        ptr_n,
    );
    mget(q, ptr_q, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_q, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_n, ecc_ristretto255_SCALARSIZE);
    return fun_ret;
}

// bls12_381

const ecc_bls12_381_G1SIZE = 48;
/**
 * Size of a an element in G1.
 *
 * @type {number}
 */
Module.ecc_bls12_381_G1SIZE = ecc_bls12_381_G1SIZE;

const ecc_bls12_381_G2SIZE = 96;
/**
 * Size of an element in G2.
 *
 * @type {number}
 */
Module.ecc_bls12_381_G2SIZE = ecc_bls12_381_G2SIZE;

const ecc_bls12_381_SCALARSIZE = 32;
/**
 * Size of the scalar used in the curve operations.
 *
 * @type {number}
 */
Module.ecc_bls12_381_SCALARSIZE = ecc_bls12_381_SCALARSIZE;

const ecc_bls12_381_FPSIZE = 48;
/**
 * Size of an element in Fp.
 *
 * @type {number}
 */
Module.ecc_bls12_381_FPSIZE = ecc_bls12_381_FPSIZE;

const ecc_bls12_381_FP12SIZE = 576;
/**
 * Size of an element in Fp12.
 *
 * @type {number}
 */
Module.ecc_bls12_381_FP12SIZE = ecc_bls12_381_FP12SIZE;

/**
 * Computes a random element of BLS12-381 Fp.
 *
 * @param {Uint8Array} ret (output) the result, size:ecc_bls12_381_FPSIZE
 */
Module.ecc_bls12_381_fp_random = (
    ret,
) => {
    const ptr_ret = mput(ret, ecc_bls12_381_FPSIZE);
    _ecc_bls12_381_fp_random(
        ptr_ret,
    );
    mget(ret, ptr_ret, ecc_bls12_381_FPSIZE);
    mfree(ptr_ret, ecc_bls12_381_FPSIZE);
}

/**
 * Get the identity element of BLS12-381 Fp12.
 *
 * @param {Uint8Array} ret (output) the result, size:ecc_bls12_381_FP12SIZE
 */
Module.ecc_bls12_381_fp12_one = (
    ret,
) => {
    const ptr_ret = mput(ret, ecc_bls12_381_FP12SIZE);
    _ecc_bls12_381_fp12_one(
        ptr_ret,
    );
    mget(ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
}

/**
 * Determine if an element is the identity in BLS12-381 Fp12.
 *
 * @param {Uint8Array} a the input, size:ecc_bls12_381_FP12SIZE
 * @return {number} 1 if the element a is the identity in BLS12-381 Fp12.
 */
Module.ecc_bls12_381_fp12_is_one = (
    a,
) => {
    const ptr_a = mput(a, ecc_bls12_381_FP12SIZE);
    const fun_ret = _ecc_bls12_381_fp12_is_one(
        ptr_a,
    );
    mfree(ptr_a, ecc_bls12_381_FP12SIZE);
    return fun_ret;
}

/**
 * Computes the inverse of an element in BLS12-381 Fp12.
 *
 * @param {Uint8Array} ret (output) the result, size:ecc_bls12_381_FP12SIZE
 * @param {Uint8Array} a the input, size:ecc_bls12_381_FP12SIZE
 */
Module.ecc_bls12_381_fp12_inverse = (
    ret,
    a,
) => {
    const ptr_ret = mput(ret, ecc_bls12_381_FP12SIZE);
    const ptr_a = mput(a, ecc_bls12_381_FP12SIZE);
    _ecc_bls12_381_fp12_inverse(
        ptr_ret,
        ptr_a,
    );
    mget(ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_a, ecc_bls12_381_FP12SIZE);
}

/**
 * Computes the square of an element in BLS12-381 Fp12.
 *
 * @param {Uint8Array} ret (output) the result, size:ecc_bls12_381_FP12SIZE
 * @param {Uint8Array} a the input, size:ecc_bls12_381_FP12SIZE
 */
Module.ecc_bls12_381_fp12_sqr = (
    ret,
    a,
) => {
    const ptr_ret = mput(ret, ecc_bls12_381_FP12SIZE);
    const ptr_a = mput(a, ecc_bls12_381_FP12SIZE);
    _ecc_bls12_381_fp12_sqr(
        ptr_ret,
        ptr_a,
    );
    mget(ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_a, ecc_bls12_381_FP12SIZE);
}

/**
 * Perform a * b in Fp12.
 *
 * @param {Uint8Array} ret (output) the result, size:ecc_bls12_381_FP12SIZE
 * @param {Uint8Array} a input group element, size:ecc_bls12_381_FP12SIZE
 * @param {Uint8Array} b input group element, size:ecc_bls12_381_FP12SIZE
 */
Module.ecc_bls12_381_fp12_mul = (
    ret,
    a,
    b,
) => {
    const ptr_ret = mput(ret, ecc_bls12_381_FP12SIZE);
    const ptr_a = mput(a, ecc_bls12_381_FP12SIZE);
    const ptr_b = mput(b, ecc_bls12_381_FP12SIZE);
    _ecc_bls12_381_fp12_mul(
        ptr_ret,
        ptr_a,
        ptr_b,
    );
    mget(ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_a, ecc_bls12_381_FP12SIZE);
    mfree(ptr_b, ecc_bls12_381_FP12SIZE);
}

/**
 * This is a naive implementation of an iterative exponentiation by squaring.
 *
 * NOTE: This method is not side-channel attack resistant on `n`, the algorithm
 * leaks information about it, don't use this if `n` is a secret.
 *
 * @param {Uint8Array} ret (output) the result, size:ecc_bls12_381_FP12SIZE
 * @param {Uint8Array} a the base, size:ecc_bls12_381_FP12SIZE
 * @param {number} n the exponent
 */
Module.ecc_bls12_381_fp12_pow = (
    ret,
    a,
    n,
) => {
    const ptr_ret = mput(ret, ecc_bls12_381_FP12SIZE);
    const ptr_a = mput(a, ecc_bls12_381_FP12SIZE);
    _ecc_bls12_381_fp12_pow(
        ptr_ret,
        ptr_a,
        n,
    );
    mget(ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_a, ecc_bls12_381_FP12SIZE);
}

/**
 * Computes a random element of BLS12-381 Fp12.
 *
 * @param {Uint8Array} ret (output) the result, size:ecc_bls12_381_FP12SIZE
 */
Module.ecc_bls12_381_fp12_random = (
    ret,
) => {
    const ptr_ret = mput(ret, ecc_bls12_381_FP12SIZE);
    _ecc_bls12_381_fp12_random(
        ptr_ret,
    );
    mget(ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
}

/**
 *
 *
 * @param {Uint8Array} r (output) size:ecc_bls12_381_G1SIZE
 * @param {Uint8Array} p size:ecc_bls12_381_G1SIZE
 * @param {Uint8Array} q size:ecc_bls12_381_G1SIZE
 */
Module.ecc_bls12_381_g1_add = (
    r,
    p,
    q,
) => {
    const ptr_r = mput(r, ecc_bls12_381_G1SIZE);
    const ptr_p = mput(p, ecc_bls12_381_G1SIZE);
    const ptr_q = mput(q, ecc_bls12_381_G1SIZE);
    _ecc_bls12_381_g1_add(
        ptr_r,
        ptr_p,
        ptr_q,
    );
    mget(r, ptr_r, ecc_bls12_381_G1SIZE);
    mfree(ptr_r, ecc_bls12_381_G1SIZE);
    mfree(ptr_p, ecc_bls12_381_G1SIZE);
    mfree(ptr_q, ecc_bls12_381_G1SIZE);
}

/**
 *
 *
 * @param {Uint8Array} neg (output) size:ecc_bls12_381_G1SIZE
 * @param {Uint8Array} p size:ecc_bls12_381_G1SIZE
 */
Module.ecc_bls12_381_g1_negate = (
    neg,
    p,
) => {
    const ptr_neg = mput(neg, ecc_bls12_381_G1SIZE);
    const ptr_p = mput(p, ecc_bls12_381_G1SIZE);
    _ecc_bls12_381_g1_negate(
        ptr_neg,
        ptr_p,
    );
    mget(neg, ptr_neg, ecc_bls12_381_G1SIZE);
    mfree(ptr_neg, ecc_bls12_381_G1SIZE);
    mfree(ptr_p, ecc_bls12_381_G1SIZE);
}

/**
 *
 *
 * @param {Uint8Array} g (output) size:ecc_bls12_381_G1SIZE
 */
Module.ecc_bls12_381_g1_generator = (
    g,
) => {
    const ptr_g = mput(g, ecc_bls12_381_G1SIZE);
    _ecc_bls12_381_g1_generator(
        ptr_g,
    );
    mget(g, ptr_g, ecc_bls12_381_G1SIZE);
    mfree(ptr_g, ecc_bls12_381_G1SIZE);
}

/**
 * Multiplies an element represented by p by a valid scalar n
 * and puts the resulting element into q.
 *
 * @param {Uint8Array} q (output) the result, size:ecc_bls12_381_G1SIZE
 * @param {Uint8Array} n the valid input scalar, size:ecc_bls12_381_SCALARSIZE
 * @param {Uint8Array} p the point on the curve, size:ecc_bls12_381_G1SIZE
 */
Module.ecc_bls12_381_g1_scalarmult = (
    q,
    n,
    p,
) => {
    const ptr_q = mput(q, ecc_bls12_381_G1SIZE);
    const ptr_n = mput(n, ecc_bls12_381_SCALARSIZE);
    const ptr_p = mput(p, ecc_bls12_381_G1SIZE);
    _ecc_bls12_381_g1_scalarmult(
        ptr_q,
        ptr_n,
        ptr_p,
    );
    mget(q, ptr_q, ecc_bls12_381_G1SIZE);
    mfree(ptr_q, ecc_bls12_381_G1SIZE);
    mfree(ptr_n, ecc_bls12_381_SCALARSIZE);
    mfree(ptr_p, ecc_bls12_381_G1SIZE);
}

/**
 * Multiplies the generator by a valid scalar n and puts the resulting
 * element into q.
 *
 * @param {Uint8Array} q (output) the result, size:ecc_bls12_381_G1SIZE
 * @param {Uint8Array} n the valid input scalar, size:ecc_bls12_381_SCALARSIZE
 */
Module.ecc_bls12_381_g1_scalarmult_base = (
    q,
    n,
) => {
    const ptr_q = mput(q, ecc_bls12_381_G1SIZE);
    const ptr_n = mput(n, ecc_bls12_381_SCALARSIZE);
    _ecc_bls12_381_g1_scalarmult_base(
        ptr_q,
        ptr_n,
    );
    mget(q, ptr_q, ecc_bls12_381_G1SIZE);
    mfree(ptr_q, ecc_bls12_381_G1SIZE);
    mfree(ptr_n, ecc_bls12_381_SCALARSIZE);
}

/**
 *
 *
 * @param {Uint8Array} r (output) size:ecc_bls12_381_G2SIZE
 * @param {Uint8Array} p size:ecc_bls12_381_G2SIZE
 * @param {Uint8Array} q size:ecc_bls12_381_G2SIZE
 */
Module.ecc_bls12_381_g2_add = (
    r,
    p,
    q,
) => {
    const ptr_r = mput(r, ecc_bls12_381_G2SIZE);
    const ptr_p = mput(p, ecc_bls12_381_G2SIZE);
    const ptr_q = mput(q, ecc_bls12_381_G2SIZE);
    _ecc_bls12_381_g2_add(
        ptr_r,
        ptr_p,
        ptr_q,
    );
    mget(r, ptr_r, ecc_bls12_381_G2SIZE);
    mfree(ptr_r, ecc_bls12_381_G2SIZE);
    mfree(ptr_p, ecc_bls12_381_G2SIZE);
    mfree(ptr_q, ecc_bls12_381_G2SIZE);
}

/**
 *
 *
 * @param {Uint8Array} neg (output) size:ecc_bls12_381_G2SIZE
 * @param {Uint8Array} p size:ecc_bls12_381_G2SIZE
 */
Module.ecc_bls12_381_g2_negate = (
    neg,
    p,
) => {
    const ptr_neg = mput(neg, ecc_bls12_381_G2SIZE);
    const ptr_p = mput(p, ecc_bls12_381_G2SIZE);
    _ecc_bls12_381_g2_negate(
        ptr_neg,
        ptr_p,
    );
    mget(neg, ptr_neg, ecc_bls12_381_G2SIZE);
    mfree(ptr_neg, ecc_bls12_381_G2SIZE);
    mfree(ptr_p, ecc_bls12_381_G2SIZE);
}

/**
 *
 *
 * @param {Uint8Array} g (output) size:ecc_bls12_381_G2SIZE
 */
Module.ecc_bls12_381_g2_generator = (
    g,
) => {
    const ptr_g = mput(g, ecc_bls12_381_G2SIZE);
    _ecc_bls12_381_g2_generator(
        ptr_g,
    );
    mget(g, ptr_g, ecc_bls12_381_G2SIZE);
    mfree(ptr_g, ecc_bls12_381_G2SIZE);
}

/**
 * Multiplies the generator by a valid scalar n and puts the resulting
 * element into q.
 *
 * @param {Uint8Array} q (output) the result, size:ecc_bls12_381_G2SIZE
 * @param {Uint8Array} n the valid input scalar, size:ecc_bls12_381_SCALARSIZE
 */
Module.ecc_bls12_381_g2_scalarmult_base = (
    q,
    n,
) => {
    const ptr_q = mput(q, ecc_bls12_381_G2SIZE);
    const ptr_n = mput(n, ecc_bls12_381_SCALARSIZE);
    _ecc_bls12_381_g2_scalarmult_base(
        ptr_q,
        ptr_n,
    );
    mget(q, ptr_q, ecc_bls12_381_G2SIZE);
    mfree(ptr_q, ecc_bls12_381_G2SIZE);
    mfree(ptr_n, ecc_bls12_381_SCALARSIZE);
}

/**
 * Fills r with a bytes representation of an scalar.
 *
 * @param {Uint8Array} r (output) random scalar, size:ecc_bls12_381_SCALARSIZE
 */
Module.ecc_bls12_381_scalar_random = (
    r,
) => {
    const ptr_r = mput(r, ecc_bls12_381_SCALARSIZE);
    _ecc_bls12_381_scalar_random(
        ptr_r,
    );
    mget(r, ptr_r, ecc_bls12_381_SCALARSIZE);
    mfree(ptr_r, ecc_bls12_381_SCALARSIZE);
}

/**
 * Evaluates a pairing of BLS12-381.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-09#section-2.2
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-09#section-2.4
 *
 * G1 is a subgroup of E(GF(p)) of order r.
 * G2 is a subgroup of E'(GF(p^2)) of order r.
 * GT is a subgroup of a multiplicative group (GF(p^12))^* of order r.
 *
 * @param {Uint8Array} ret (output) the result of the pairing evaluation in GT, size:ecc_bls12_381_FP12SIZE
 * @param {Uint8Array} p1_g1 point in G1, size:ecc_bls12_381_G1SIZE
 * @param {Uint8Array} p2_g2 point in G2, size:ecc_bls12_381_G2SIZE
 */
Module.ecc_bls12_381_pairing = (
    ret,
    p1_g1,
    p2_g2,
) => {
    const ptr_ret = mput(ret, ecc_bls12_381_FP12SIZE);
    const ptr_p1_g1 = mput(p1_g1, ecc_bls12_381_G1SIZE);
    const ptr_p2_g2 = mput(p2_g2, ecc_bls12_381_G2SIZE);
    _ecc_bls12_381_pairing(
        ptr_ret,
        ptr_p1_g1,
        ptr_p2_g2,
    );
    mget(ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_p1_g1, ecc_bls12_381_G1SIZE);
    mfree(ptr_p2_g2, ecc_bls12_381_G2SIZE);
}

/**
 *
 *
 * @param {Uint8Array} ret (output) size:ecc_bls12_381_FP12SIZE
 * @param {Uint8Array} p1_g1 size:ecc_bls12_381_G1SIZE
 * @param {Uint8Array} p2_g2 size:ecc_bls12_381_G2SIZE
 */
Module.ecc_bls12_381_pairing_miller_loop = (
    ret,
    p1_g1,
    p2_g2,
) => {
    const ptr_ret = mput(ret, ecc_bls12_381_FP12SIZE);
    const ptr_p1_g1 = mput(p1_g1, ecc_bls12_381_G1SIZE);
    const ptr_p2_g2 = mput(p2_g2, ecc_bls12_381_G2SIZE);
    _ecc_bls12_381_pairing_miller_loop(
        ptr_ret,
        ptr_p1_g1,
        ptr_p2_g2,
    );
    mget(ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_p1_g1, ecc_bls12_381_G1SIZE);
    mfree(ptr_p2_g2, ecc_bls12_381_G2SIZE);
}

/**
 *
 *
 * @param {Uint8Array} ret (output) size:ecc_bls12_381_FP12SIZE
 * @param {Uint8Array} a size:ecc_bls12_381_FP12SIZE
 */
Module.ecc_bls12_381_pairing_final_exp = (
    ret,
    a,
) => {
    const ptr_ret = mput(ret, ecc_bls12_381_FP12SIZE);
    const ptr_a = mput(a, ecc_bls12_381_FP12SIZE);
    _ecc_bls12_381_pairing_final_exp(
        ptr_ret,
        ptr_a,
    );
    mget(ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_a, ecc_bls12_381_FP12SIZE);
}

/**
 * Perform the verification of a pairing match. Useful if the
 * inputs are raw output values from the miller loop.
 *
 * @param {Uint8Array} a the first argument to verify, size:ecc_bls12_381_FP12SIZE
 * @param {Uint8Array} b the second argument to verify, size:ecc_bls12_381_FP12SIZE
 * @return {number} 1 if it's a pairing match, else 0
 */
Module.ecc_bls12_381_pairing_final_verify = (
    a,
    b,
) => {
    const ptr_a = mput(a, ecc_bls12_381_FP12SIZE);
    const ptr_b = mput(b, ecc_bls12_381_FP12SIZE);
    const fun_ret = _ecc_bls12_381_pairing_final_verify(
        ptr_a,
        ptr_b,
    );
    mfree(ptr_a, ecc_bls12_381_FP12SIZE);
    mfree(ptr_b, ecc_bls12_381_FP12SIZE);
    return fun_ret;
}

// h2c

const ecc_h2c_expand_message_xmd_sha256_MAXSIZE = 8160;
/**
 *
 *
 * @type {number}
 */
Module.ecc_h2c_expand_message_xmd_sha256_MAXSIZE = ecc_h2c_expand_message_xmd_sha256_MAXSIZE;

const ecc_h2c_expand_message_xmd_sha256_DSTMAXSIZE = 255;
/**
 *
 *
 * @type {number}
 */
Module.ecc_h2c_expand_message_xmd_sha256_DSTMAXSIZE = ecc_h2c_expand_message_xmd_sha256_DSTMAXSIZE;

const ecc_h2c_expand_message_xmd_sha512_MAXSIZE = 16320;
/**
 *
 *
 * @type {number}
 */
Module.ecc_h2c_expand_message_xmd_sha512_MAXSIZE = ecc_h2c_expand_message_xmd_sha512_MAXSIZE;

const ecc_h2c_expand_message_xmd_sha512_DSTMAXSIZE = 255;
/**
 *
 *
 * @type {number}
 */
Module.ecc_h2c_expand_message_xmd_sha512_DSTMAXSIZE = ecc_h2c_expand_message_xmd_sha512_DSTMAXSIZE;

/**
 * Produces a uniformly random byte string using SHA-256.
 *
 * @param {Uint8Array} out (output) a byte string, should be at least of size `len`, size:len
 * @param {Uint8Array} msg a byte string, size:msg_len
 * @param {number} msg_len the length of `msg`
 * @param {Uint8Array} dst a byte string of at most 255 bytes, size:dst_len
 * @param {number} dst_len the length of `dst`, should be
 * <
 * = ecc_h2c_expand_message_xmd_sha256_DSTMAXSIZE
 * @param {number} len the length of the requested output in bytes, should be
 * <
 * = ecc_h2c_expand_message_xmd_sha256_MAXSIZE
 * @return {number} 0 on success or -1 if arguments are out of range
 */
Module.ecc_h2c_expand_message_xmd_sha256 = (
    out,
    msg,
    msg_len,
    dst,
    dst_len,
    len,
) => {
    const ptr_out = mput(out, len);
    const ptr_msg = mput(msg, msg_len);
    const ptr_dst = mput(dst, dst_len);
    const fun_ret = _ecc_h2c_expand_message_xmd_sha256(
        ptr_out,
        ptr_msg,
        msg_len,
        ptr_dst,
        dst_len,
        len,
    );
    mget(out, ptr_out, len);
    mfree(ptr_out, len);
    mfree(ptr_msg, msg_len);
    mfree(ptr_dst, dst_len);
    return fun_ret;
}

/**
 * Produces a uniformly random byte string using SHA-512.
 *
 * @param {Uint8Array} out (output) a byte string, should be at least of size `len`, size:len
 * @param {Uint8Array} msg a byte string, size:msg_len
 * @param {number} msg_len the length of `msg`
 * @param {Uint8Array} dst a byte string of at most 255 bytes, size:dst_len
 * @param {number} dst_len the length of `dst`, should be
 * <
 * = ecc_h2c_expand_message_xmd_sha512_DSTMAXSIZE
 * @param {number} len the length of the requested output in bytes, should be
 * <
 * = ecc_h2c_expand_message_xmd_sha512_MAXSIZE
 * @return {number} 0 on success or -1 if arguments are out of range
 */
Module.ecc_h2c_expand_message_xmd_sha512 = (
    out,
    msg,
    msg_len,
    dst,
    dst_len,
    len,
) => {
    const ptr_out = mput(out, len);
    const ptr_msg = mput(msg, msg_len);
    const ptr_dst = mput(dst, dst_len);
    const fun_ret = _ecc_h2c_expand_message_xmd_sha512(
        ptr_out,
        ptr_msg,
        msg_len,
        ptr_dst,
        dst_len,
        len,
    );
    mget(out, ptr_out, len);
    mfree(ptr_out, len);
    mfree(ptr_msg, msg_len);
    mfree(ptr_dst, dst_len);
    return fun_ret;
}

// voprf

const ecc_voprf_ristretto255_sha512_ELEMENTSIZE = 32;
/**
 * Size of a serialized group element, since this is the ristretto255
 * curve the size is 32 bytes.
 *
 * @type {number}
 */
Module.ecc_voprf_ristretto255_sha512_ELEMENTSIZE = ecc_voprf_ristretto255_sha512_ELEMENTSIZE;

const ecc_voprf_ristretto255_sha512_SCALARSIZE = 32;
/**
 * Size of a serialized scalar, since this is the ristretto255
 * curve the size is 32 bytes.
 *
 * @type {number}
 */
Module.ecc_voprf_ristretto255_sha512_SCALARSIZE = ecc_voprf_ristretto255_sha512_SCALARSIZE;

const ecc_voprf_ristretto255_sha512_PROOFSIZE = 64;
/**
 * Size of a proof. Proof is a tuple of two scalars.
 *
 * @type {number}
 */
Module.ecc_voprf_ristretto255_sha512_PROOFSIZE = ecc_voprf_ristretto255_sha512_PROOFSIZE;

const ecc_voprf_ristretto255_sha512_Nh = 64;
/**
 * Size of the protocol output in the `Finalize` operations, since
 * this is ristretto255 with SHA-512, the size is 64 bytes.
 *
 * @type {number}
 */
Module.ecc_voprf_ristretto255_sha512_Nh = ecc_voprf_ristretto255_sha512_Nh;

const ecc_voprf_ristretto255_sha512_MODE_OPRF = 0;
/**
 * A client and server interact to compute output = F(skS, input, info).
 *
 * @type {number}
 */
Module.ecc_voprf_ristretto255_sha512_MODE_OPRF = ecc_voprf_ristretto255_sha512_MODE_OPRF;

const ecc_voprf_ristretto255_sha512_MODE_VOPRF = 1;
/**
 * A client and server interact to compute output = F(skS, input, info) and
 * the client also receives proof that the server used skS in computing
 * the function.
 *
 * @type {number}
 */
Module.ecc_voprf_ristretto255_sha512_MODE_VOPRF = ecc_voprf_ristretto255_sha512_MODE_VOPRF;

const ecc_voprf_ristretto255_sha512_MODE_POPRF = 2;
/**
 * A client and server interact to compute output = F(skS, input, info).
 * Allows clients and servers to provide public input to the PRF computation.
 *
 * @type {number}
 */
Module.ecc_voprf_ristretto255_sha512_MODE_POPRF = ecc_voprf_ristretto255_sha512_MODE_POPRF;

const ecc_voprf_ristretto255_sha512_MAXINFOSIZE = 2000;
/**
 *
 *
 * @type {number}
 */
Module.ecc_voprf_ristretto255_sha512_MAXINFOSIZE = ecc_voprf_ristretto255_sha512_MAXINFOSIZE;

/**
 * Generates a proof using the specified scalar. Given elements A and B, two
 * non-empty lists of elements C and D of length m, and a scalar k; this
 * function produces a proof that k*A == B and k*C[i] == D[i] for each i in
 * [0, ..., m - 1]. The output is a value of type Proof, which is a tuple of two
 * scalar values.
 *
 * @param {Uint8Array} proof (output) size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @param {Uint8Array} k size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} A size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} B size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} C size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} D size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {number} m the size of the `C` and `D` arrays
 * @param {number} mode the protocol mode VOPRF or POPRF
 * @param {Uint8Array} r size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 */
Module.ecc_voprf_ristretto255_sha512_GenerateProofWithScalar = (
    proof,
    k,
    A,
    B,
    C,
    D,
    m,
    mode,
    r,
) => {
    const ptr_proof = mput(proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    const ptr_k = mput(k, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_A = mput(A, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_B = mput(B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_C = mput(C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_D = mput(D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_r = mput(r, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    _ecc_voprf_ristretto255_sha512_GenerateProofWithScalar(
        ptr_proof,
        ptr_k,
        ptr_A,
        ptr_B,
        ptr_C,
        ptr_D,
        m,
        mode,
        ptr_r,
    );
    mget(proof, ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_k, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_A, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_r, ecc_voprf_ristretto255_sha512_SCALARSIZE);
}

/**
 * Generates a proof. Given elements A and B, two
 * non-empty lists of elements C and D of length m, and a scalar k; this
 * function produces a proof that k*A == B and k*C[i] == D[i] for each i in
 * [0, ..., m - 1]. The output is a value of type Proof, which is a tuple of two
 * scalar values.
 *
 * @param {Uint8Array} proof (output) size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @param {Uint8Array} k size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} A size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} B size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} C size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} D size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {number} m the size of the `C` and `D` arrays
 * @param {number} mode the protocol mode VOPRF or POPRF
 */
Module.ecc_voprf_ristretto255_sha512_GenerateProof = (
    proof,
    k,
    A,
    B,
    C,
    D,
    m,
    mode,
) => {
    const ptr_proof = mput(proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    const ptr_k = mput(k, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_A = mput(A, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_B = mput(B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_C = mput(C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_D = mput(D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    _ecc_voprf_ristretto255_sha512_GenerateProof(
        ptr_proof,
        ptr_k,
        ptr_A,
        ptr_B,
        ptr_C,
        ptr_D,
        m,
        mode,
    );
    mget(proof, ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_k, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_A, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
}

/**
 * Helper function used in GenerateProof. It is an optimization of the
 * ComputeComposites function for servers since they have knowledge of the
 * private key.
 *
 * @param {Uint8Array} M (output) size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} Z (output) size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} k size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} B size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} C size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} D size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {number} m the size of the `C` and `D` arrays
 * @param {number} mode the protocol mode VOPRF or POPRF
 */
Module.ecc_voprf_ristretto255_sha512_ComputeCompositesFast = (
    M,
    Z,
    k,
    B,
    C,
    D,
    m,
    mode,
) => {
    const ptr_M = mput(M, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_Z = mput(Z, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_k = mput(k, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_B = mput(B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_C = mput(C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_D = mput(D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    _ecc_voprf_ristretto255_sha512_ComputeCompositesFast(
        ptr_M,
        ptr_Z,
        ptr_k,
        ptr_B,
        ptr_C,
        ptr_D,
        m,
        mode,
    );
    mget(M, ptr_M, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(Z, ptr_Z, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_M, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_Z, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_k, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
}

/**
 * This function takes elements A and B, two non-empty lists of elements C and D
 * of length m, and a Proof value output from GenerateProof. It outputs a single
 * boolean value indicating whether or not the proof is valid for the given DLEQ
 * inputs. Note this function can verify proofs on lists of inputs whenever the
 * proof was generated as a batched DLEQ proof with the same inputs.
 *
 * @param {Uint8Array} A size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} B size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} C size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} D size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {number} m the size of the `C` and `D` arrays
 * @param {number} mode the protocol mode VOPRF or POPRF
 * @param {Uint8Array} proof size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @return {number} on success verification returns 1, else 0.
 */
Module.ecc_voprf_ristretto255_sha512_VerifyProof = (
    A,
    B,
    C,
    D,
    m,
    mode,
    proof,
) => {
    const ptr_A = mput(A, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_B = mput(B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_C = mput(C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_D = mput(D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_proof = mput(proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    const fun_ret = _ecc_voprf_ristretto255_sha512_VerifyProof(
        ptr_A,
        ptr_B,
        ptr_C,
        ptr_D,
        m,
        mode,
        ptr_proof,
    );
    mfree(ptr_A, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    return fun_ret;
}

/**
 * Helper function used in `VerifyProof`.
 *
 * @param {Uint8Array} M (output) size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} Z (output) size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} B size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} C size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} D size:m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {number} m the size of the `C` and `D` arrays
 * @param {number} mode the protocol mode VOPRF or POPRF
 */
Module.ecc_voprf_ristretto255_sha512_ComputeComposites = (
    M,
    Z,
    B,
    C,
    D,
    m,
    mode,
) => {
    const ptr_M = mput(M, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_Z = mput(Z, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_B = mput(B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_C = mput(C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_D = mput(D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    _ecc_voprf_ristretto255_sha512_ComputeComposites(
        ptr_M,
        ptr_Z,
        ptr_B,
        ptr_C,
        ptr_D,
        m,
        mode,
    );
    mget(M, ptr_M, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(Z, ptr_Z, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_M, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_Z, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
}

/**
 * In the offline setup phase, the server key pair (skS, pkS) is generated using
 * this function, which produces a randomly generate private and public key pair.
 *
 * @param {Uint8Array} skS (output) size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} pkS (output) size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 */
Module.ecc_voprf_ristretto255_sha512_GenerateKeyPair = (
    skS,
    pkS,
) => {
    const ptr_skS = mput(skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_pkS = mput(pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    _ecc_voprf_ristretto255_sha512_GenerateKeyPair(
        ptr_skS,
        ptr_pkS,
    );
    mget(skS, ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mget(pkS, ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
}

/**
 * Deterministically generate a key. It accepts a randomly generated seed of
 * length Ns bytes and an optional (possibly empty) public info string.
 *
 * @param {Uint8Array} skS (output) size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} pkS (output) size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} seed size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} info size:infoLen
 * @param {number} infoLen the size of `info`, it should be
 * <
 * = ecc_voprf_ristretto255_sha512_MAXINFOSIZE
 * @param {number} mode the protocol mode VOPRF or POPRF
 * @return {number} 0 on success, or -1 if an error
 */
Module.ecc_voprf_ristretto255_sha512_DeriveKeyPair = (
    skS,
    pkS,
    seed,
    info,
    infoLen,
    mode,
) => {
    const ptr_skS = mput(skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_pkS = mput(pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_seed = mput(seed, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_info = mput(info, infoLen);
    const fun_ret = _ecc_voprf_ristretto255_sha512_DeriveKeyPair(
        ptr_skS,
        ptr_pkS,
        ptr_seed,
        ptr_info,
        infoLen,
        mode,
    );
    mget(skS, ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mget(pkS, ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_seed, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_info, infoLen);
    return fun_ret;
}

/**
 * Same as calling `ecc_voprf_ristretto255_sha512_Blind` with an
 * specified scalar blind.
 *
 * @param {Uint8Array} blindedElement (output) blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} input message to blind, size:inputLen
 * @param {number} inputLen length of `input`
 * @param {Uint8Array} blind scalar to use in the blind operation, size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {number} mode oprf mode
 * @return {number} 0 on success, or -1 if an error
 */
Module.ecc_voprf_ristretto255_sha512_BlindWithScalar = (
    blindedElement,
    input,
    inputLen,
    blind,
    mode,
) => {
    const ptr_blindedElement = mput(blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_input = mput(input, inputLen);
    const ptr_blind = mput(blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const fun_ret = _ecc_voprf_ristretto255_sha512_BlindWithScalar(
        ptr_blindedElement,
        ptr_input,
        inputLen,
        ptr_blind,
        mode,
    );
    mget(blindedElement, ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    return fun_ret;
}

/**
 * The OPRF protocol begins with the client blinding its input. Note that this
 * function can fail for certain inputs that map to the group identity element.
 *
 * @param {Uint8Array} blind (output) scalar used in the blind operation, size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} blindedElement (output) blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} input message to blind, size:inputLen
 * @param {number} inputLen length of `input`
 * @param {number} mode oprf mode
 * @return {number} 0 on success, or -1 if an error
 */
Module.ecc_voprf_ristretto255_sha512_Blind = (
    blind,
    blindedElement,
    input,
    inputLen,
    mode,
) => {
    const ptr_blind = mput(blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_blindedElement = mput(blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_input = mput(input, inputLen);
    const fun_ret = _ecc_voprf_ristretto255_sha512_Blind(
        ptr_blind,
        ptr_blindedElement,
        ptr_input,
        inputLen,
        mode,
    );
    mget(blind, ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mget(blindedElement, ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
    return fun_ret;
}

/**
 * Clients store blind locally, and send blindedElement to the server for
 * evaluation. Upon receipt, servers process blindedElement using this function.
 *
 * @param {Uint8Array} evaluatedElement (output) blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} skS scalar used in the blind operation, size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} blindedElement blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 */
Module.ecc_voprf_ristretto255_sha512_BlindEvaluate = (
    evaluatedElement,
    skS,
    blindedElement,
) => {
    const ptr_evaluatedElement = mput(evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_skS = mput(skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_blindedElement = mput(blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    _ecc_voprf_ristretto255_sha512_BlindEvaluate(
        ptr_evaluatedElement,
        ptr_skS,
        ptr_blindedElement,
    );
    mget(evaluatedElement, ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
}

/**
 * Servers send the output evaluatedElement to clients for processing. Recall
 * that servers may process multiple client inputs by applying the BlindEvaluate
 * function to each blindedElement received, and returning an array with the
 * corresponding evaluatedElement values. Upon receipt of evaluatedElement,
 * clients process it to complete the OPRF evaluation with this function.
 *
 * @param {Uint8Array} output (output) size:ecc_voprf_ristretto255_sha512_Nh
 * @param {Uint8Array} input the input message, size:inputLen
 * @param {number} inputLen the length of `input`
 * @param {Uint8Array} blind size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} evaluatedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 */
Module.ecc_voprf_ristretto255_sha512_Finalize = (
    output,
    input,
    inputLen,
    blind,
    evaluatedElement,
) => {
    const ptr_output = mput(output, ecc_voprf_ristretto255_sha512_Nh);
    const ptr_input = mput(input, inputLen);
    const ptr_blind = mput(blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_evaluatedElement = mput(evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    _ecc_voprf_ristretto255_sha512_Finalize(
        ptr_output,
        ptr_input,
        inputLen,
        ptr_blind,
        ptr_evaluatedElement,
    );
    mget(output, ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_input, inputLen);
    mfree(ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
}

/**
 * An entity which knows both the secret key and the input can compute the PRF
 * result using this function.
 *
 * @param {Uint8Array} output (output) size:ecc_voprf_ristretto255_sha512_Nh
 * @param {Uint8Array} skS size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} input the input message, size:inputLen
 * @param {number} inputLen the length of `input`
 * @param {number} mode oprf mode
 * @return {number} 0 on success, or -1 if an error
 */
Module.ecc_voprf_ristretto255_sha512_Evaluate = (
    output,
    skS,
    input,
    inputLen,
    mode,
) => {
    const ptr_output = mput(output, ecc_voprf_ristretto255_sha512_Nh);
    const ptr_skS = mput(skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_input = mput(input, inputLen);
    const fun_ret = _ecc_voprf_ristretto255_sha512_Evaluate(
        ptr_output,
        ptr_skS,
        ptr_input,
        inputLen,
        mode,
    );
    mget(output, ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_input, inputLen);
    return fun_ret;
}

/**
 * Same as calling ecc_voprf_ristretto255_sha512_VerifiableBlindEvaluate but
 * using an specified scalar `r`.
 *
 * @param {Uint8Array} evaluatedElement (output) size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} proof (output) size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @param {Uint8Array} skS size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} pkS size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} blindedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} r size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 */
Module.ecc_voprf_ristretto255_sha512_VerifiableBlindEvaluateWithScalar = (
    evaluatedElement,
    proof,
    skS,
    pkS,
    blindedElement,
    r,
) => {
    const ptr_evaluatedElement = mput(evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_proof = mput(proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    const ptr_skS = mput(skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_pkS = mput(pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_blindedElement = mput(blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_r = mput(r, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    _ecc_voprf_ristretto255_sha512_VerifiableBlindEvaluateWithScalar(
        ptr_evaluatedElement,
        ptr_proof,
        ptr_skS,
        ptr_pkS,
        ptr_blindedElement,
        ptr_r,
    );
    mget(evaluatedElement, ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(proof, ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_r, ecc_voprf_ristretto255_sha512_SCALARSIZE);
}

/**
 * The VOPRF protocol begins with the client blinding its input. Clients store
 * the output blind locally and send blindedElement to the server for
 * evaluation. Upon receipt, servers process blindedElement to compute an
 * evaluated element and DLEQ proof using this function.
 *
 * @param {Uint8Array} evaluatedElement (output) size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} proof (output) size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @param {Uint8Array} skS size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} pkS size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} blindedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 */
Module.ecc_voprf_ristretto255_sha512_VerifiableBlindEvaluate = (
    evaluatedElement,
    proof,
    skS,
    pkS,
    blindedElement,
) => {
    const ptr_evaluatedElement = mput(evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_proof = mput(proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    const ptr_skS = mput(skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_pkS = mput(pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_blindedElement = mput(blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    _ecc_voprf_ristretto255_sha512_VerifiableBlindEvaluate(
        ptr_evaluatedElement,
        ptr_proof,
        ptr_skS,
        ptr_pkS,
        ptr_blindedElement,
    );
    mget(evaluatedElement, ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(proof, ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
}

/**
 * The server sends both evaluatedElement and proof back to the client. Upon
 * receipt, the client processes both values to complete the VOPRF computation
 * using this function below.
 *
 * @param {Uint8Array} output (output) size:ecc_voprf_ristretto255_sha512_Nh
 * @param {Uint8Array} input the input message, size:inputLen
 * @param {number} inputLen the length of `input`
 * @param {Uint8Array} blind size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} evaluatedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} blindedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} pkS size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} proof size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @return {number} 0 on success, or -1 if an error
 */
Module.ecc_voprf_ristretto255_sha512_VerifiableFinalize = (
    output,
    input,
    inputLen,
    blind,
    evaluatedElement,
    blindedElement,
    pkS,
    proof,
) => {
    const ptr_output = mput(output, ecc_voprf_ristretto255_sha512_Nh);
    const ptr_input = mput(input, inputLen);
    const ptr_blind = mput(blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_evaluatedElement = mput(evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_blindedElement = mput(blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_pkS = mput(pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_proof = mput(proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    const fun_ret = _ecc_voprf_ristretto255_sha512_VerifiableFinalize(
        ptr_output,
        ptr_input,
        inputLen,
        ptr_blind,
        ptr_evaluatedElement,
        ptr_blindedElement,
        ptr_pkS,
        ptr_proof,
    );
    mget(output, ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_input, inputLen);
    mfree(ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    return fun_ret;
}

/**
 * Same as calling ecc_voprf_ristretto255_sha512_PartiallyBlind with an
 * specified blind scalar.
 *
 * @param {Uint8Array} blindedElement (output) blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} tweakedKey (output) blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} input message to blind, size:inputLen
 * @param {number} inputLen length of `input`
 * @param {Uint8Array} info message to blind, size:infoLen
 * @param {number} infoLen length of `info`, it should be
 * <
 * = ecc_voprf_ristretto255_sha512_MAXINFOSIZE
 * @param {Uint8Array} pkS size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} blind size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @return {number} 0 on success, or -1 if an error
 */
Module.ecc_voprf_ristretto255_sha512_PartiallyBlindWithScalar = (
    blindedElement,
    tweakedKey,
    input,
    inputLen,
    info,
    infoLen,
    pkS,
    blind,
) => {
    const ptr_blindedElement = mput(blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_tweakedKey = mput(tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_input = mput(input, inputLen);
    const ptr_info = mput(info, infoLen);
    const ptr_pkS = mput(pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_blind = mput(blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const fun_ret = _ecc_voprf_ristretto255_sha512_PartiallyBlindWithScalar(
        ptr_blindedElement,
        ptr_tweakedKey,
        ptr_input,
        inputLen,
        ptr_info,
        infoLen,
        ptr_pkS,
        ptr_blind,
    );
    mget(blindedElement, ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(tweakedKey, ptr_tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_info, infoLen);
    mfree(ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    return fun_ret;
}

/**
 * The POPRF protocol begins with the client blinding its input, using the
 * following modified Blind function. In this step, the client also binds a
 * public info value, which produces an additional tweakedKey to be used later
 * in the protocol. Note that this function can fail for certain private inputs
 * that map to the group identity element, as well as certain public inputs
 * that, if not detected at this point, will cause server evaluation to fail.
 *
 * @param {Uint8Array} blind (output) scalar used in the blind operation, size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} blindedElement (output) blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} tweakedKey (output) blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} input message to blind, size:inputLen
 * @param {number} inputLen length of `input`
 * @param {Uint8Array} info message to blind, size:infoLen
 * @param {number} infoLen length of `info`, it should be
 * <
 * = ecc_voprf_ristretto255_sha512_MAXINFOSIZE
 * @param {Uint8Array} pkS size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @return {number} 0 on success, or -1 if an error
 */
Module.ecc_voprf_ristretto255_sha512_PartiallyBlind = (
    blind,
    blindedElement,
    tweakedKey,
    input,
    inputLen,
    info,
    infoLen,
    pkS,
) => {
    const ptr_blind = mput(blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_blindedElement = mput(blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_tweakedKey = mput(tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_input = mput(input, inputLen);
    const ptr_info = mput(info, infoLen);
    const ptr_pkS = mput(pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const fun_ret = _ecc_voprf_ristretto255_sha512_PartiallyBlind(
        ptr_blind,
        ptr_blindedElement,
        ptr_tweakedKey,
        ptr_input,
        inputLen,
        ptr_info,
        infoLen,
        ptr_pkS,
    );
    mget(blind, ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mget(blindedElement, ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(tweakedKey, ptr_tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_info, infoLen);
    mfree(ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    return fun_ret;
}

/**
 * Same as calling ecc_voprf_ristretto255_sha512_PartiallyBlindEvaluate with an
 * specified scalar r.
 *
 * @param {Uint8Array} evaluatedElement (output) size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} proof (output) size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @param {Uint8Array} skS size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} blindedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} info message to blind, size:infoLen
 * @param {number} infoLen length of `info`, it should be
 * <
 * = ecc_voprf_ristretto255_sha512_MAXINFOSIZE
 * @param {Uint8Array} r size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @return {number} 0 on success, or -1 if an error
 */
Module.ecc_voprf_ristretto255_sha512_PartiallyBlindEvaluateWithScalar = (
    evaluatedElement,
    proof,
    skS,
    blindedElement,
    info,
    infoLen,
    r,
) => {
    const ptr_evaluatedElement = mput(evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_proof = mput(proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    const ptr_skS = mput(skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_blindedElement = mput(blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_info = mput(info, infoLen);
    const ptr_r = mput(r, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const fun_ret = _ecc_voprf_ristretto255_sha512_PartiallyBlindEvaluateWithScalar(
        ptr_evaluatedElement,
        ptr_proof,
        ptr_skS,
        ptr_blindedElement,
        ptr_info,
        infoLen,
        ptr_r,
    );
    mget(evaluatedElement, ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(proof, ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_info, infoLen);
    mfree(ptr_r, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    return fun_ret;
}

/**
 * Clients store the outputs blind and tweakedKey locally and send
 * blindedElement to the server for evaluation. Upon receipt, servers process
 * blindedElement to compute an evaluated element and DLEQ proof using the
 * this function.
 *
 * @param {Uint8Array} evaluatedElement (output) size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} proof (output) size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @param {Uint8Array} skS size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} blindedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} info message to blind, size:infoLen
 * @param {number} infoLen length of `info`, it should be
 * <
 * = ecc_voprf_ristretto255_sha512_MAXINFOSIZE
 * @return {number} 0 on success, or -1 if an error
 */
Module.ecc_voprf_ristretto255_sha512_PartiallyBlindEvaluate = (
    evaluatedElement,
    proof,
    skS,
    blindedElement,
    info,
    infoLen,
) => {
    const ptr_evaluatedElement = mput(evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_proof = mput(proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    const ptr_skS = mput(skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_blindedElement = mput(blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_info = mput(info, infoLen);
    const fun_ret = _ecc_voprf_ristretto255_sha512_PartiallyBlindEvaluate(
        ptr_evaluatedElement,
        ptr_proof,
        ptr_skS,
        ptr_blindedElement,
        ptr_info,
        infoLen,
    );
    mget(evaluatedElement, ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(proof, ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_info, infoLen);
    return fun_ret;
}

/**
 * The server sends both evaluatedElement and proof back to the client. Upon
 * receipt, the client processes both values to complete the POPRF computation
 * using this function.
 *
 * @param {Uint8Array} output (output) size:ecc_voprf_ristretto255_sha512_Nh
 * @param {Uint8Array} input the input message, size:inputLen
 * @param {number} inputLen the length of `input`
 * @param {Uint8Array} blind size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} evaluatedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} blindedElement size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} proof size:ecc_voprf_ristretto255_sha512_PROOFSIZE
 * @param {Uint8Array} info message to blind, size:infoLen
 * @param {number} infoLen length of `info`, it should be
 * <
 * = ecc_voprf_ristretto255_sha512_MAXINFOSIZE
 * @param {Uint8Array} tweakedKey blinded element, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @return {number} 0 on success, or -1 if an error
 */
Module.ecc_voprf_ristretto255_sha512_PartiallyFinalize = (
    output,
    input,
    inputLen,
    blind,
    evaluatedElement,
    blindedElement,
    proof,
    info,
    infoLen,
    tweakedKey,
) => {
    const ptr_output = mput(output, ecc_voprf_ristretto255_sha512_Nh);
    const ptr_input = mput(input, inputLen);
    const ptr_blind = mput(blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_evaluatedElement = mput(evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_blindedElement = mput(blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_proof = mput(proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    const ptr_info = mput(info, infoLen);
    const ptr_tweakedKey = mput(tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const fun_ret = _ecc_voprf_ristretto255_sha512_PartiallyFinalize(
        ptr_output,
        ptr_input,
        inputLen,
        ptr_blind,
        ptr_evaluatedElement,
        ptr_blindedElement,
        ptr_proof,
        ptr_info,
        infoLen,
        ptr_tweakedKey,
    );
    mget(output, ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_input, inputLen);
    mfree(ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_info, infoLen);
    mfree(ptr_tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    return fun_ret;
}

/**
 * An entity which knows both the secret key and the input can compute the PRF
 * result using this function.
 *
 * @param {Uint8Array} output (output) size:ecc_voprf_ristretto255_sha512_Nh
 * @param {Uint8Array} skS size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} input the input message, size:inputLen
 * @param {number} inputLen the length of `input`
 * @param {Uint8Array} info message to blind, size:infoLen
 * @param {number} infoLen length of `info`, it should be
 * <
 * = ecc_voprf_ristretto255_sha512_MAXINFOSIZE
 * @return {number} 0 on success, or -1 if an error
 */
Module.ecc_voprf_ristretto255_sha512_PartiallyEvaluate = (
    output,
    skS,
    input,
    inputLen,
    info,
    infoLen,
) => {
    const ptr_output = mput(output, ecc_voprf_ristretto255_sha512_Nh);
    const ptr_skS = mput(skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_input = mput(input, inputLen);
    const ptr_info = mput(info, infoLen);
    const fun_ret = _ecc_voprf_ristretto255_sha512_PartiallyEvaluate(
        ptr_output,
        ptr_skS,
        ptr_input,
        inputLen,
        ptr_info,
        infoLen,
    );
    mget(output, ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_info, infoLen);
    return fun_ret;
}

/**
 * Same as calling `ecc_voprf_ristretto255_sha512_HashToGroup` with an
 * specified DST string.
 *
 * @param {Uint8Array} out (output) element of the group, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} input input string to map, size:inputLen
 * @param {number} inputLen length of `input`
 * @param {Uint8Array} dst domain separation tag (DST), size:dstLen
 * @param {number} dstLen length of `dst`
 */
Module.ecc_voprf_ristretto255_sha512_HashToGroupWithDST = (
    out,
    input,
    inputLen,
    dst,
    dstLen,
) => {
    const ptr_out = mput(out, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_input = mput(input, inputLen);
    const ptr_dst = mput(dst, dstLen);
    _ecc_voprf_ristretto255_sha512_HashToGroupWithDST(
        ptr_out,
        ptr_input,
        inputLen,
        ptr_dst,
        dstLen,
    );
    mget(out, ptr_out, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_out, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_dst, dstLen);
}

/**
 * Deterministically maps an array of bytes "x" to an element of "G" in
 * the ristretto255 curve.
 *
 * @param {Uint8Array} out (output) element of the group, size:ecc_voprf_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} input input string to map, size:inputLen
 * @param {number} inputLen length of `input`
 * @param {number} mode mode to build the internal DST string (OPRF, VOPRF, POPRF)
 */
Module.ecc_voprf_ristretto255_sha512_HashToGroup = (
    out,
    input,
    inputLen,
    mode,
) => {
    const ptr_out = mput(out, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const ptr_input = mput(input, inputLen);
    _ecc_voprf_ristretto255_sha512_HashToGroup(
        ptr_out,
        ptr_input,
        inputLen,
        mode,
    );
    mget(out, ptr_out, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_out, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
}

/**
 * Same as calling ecc_voprf_ristretto255_sha512_HashToScalar with an specified
 * DST.
 *
 * @param {Uint8Array} out (output) size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} input size:inputLen
 * @param {number} inputLen the length of `input`
 * @param {Uint8Array} dst size:dstLen
 * @param {number} dstLen the length of `dst`
 */
Module.ecc_voprf_ristretto255_sha512_HashToScalarWithDST = (
    out,
    input,
    inputLen,
    dst,
    dstLen,
) => {
    const ptr_out = mput(out, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_input = mput(input, inputLen);
    const ptr_dst = mput(dst, dstLen);
    _ecc_voprf_ristretto255_sha512_HashToScalarWithDST(
        ptr_out,
        ptr_input,
        inputLen,
        ptr_dst,
        dstLen,
    );
    mget(out, ptr_out, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_out, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_dst, dstLen);
}

/**
 * Deterministically maps an array of bytes x to an element in GF(p) in
 * the ristretto255 curve.
 *
 * @param {Uint8Array} out (output) size:ecc_voprf_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} input size:inputLen
 * @param {number} inputLen the length of `input`
 * @param {number} mode oprf mode
 */
Module.ecc_voprf_ristretto255_sha512_HashToScalar = (
    out,
    input,
    inputLen,
    mode,
) => {
    const ptr_out = mput(out, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const ptr_input = mput(input, inputLen);
    _ecc_voprf_ristretto255_sha512_HashToScalar(
        ptr_out,
        ptr_input,
        inputLen,
        mode,
    );
    mget(out, ptr_out, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_out, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_input, inputLen);
}

// opaque

const ecc_opaque_ristretto255_sha512_Nn = 32;
/**
 * The size all random nonces used in this protocol.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_Nn = ecc_opaque_ristretto255_sha512_Nn;

const ecc_opaque_ristretto255_sha512_Nm = 64;
/**
 * The output size of the "MAC=HMAC-SHA-512" function in bytes.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_Nm = ecc_opaque_ristretto255_sha512_Nm;

const ecc_opaque_ristretto255_sha512_Nh = 64;
/**
 * The output size of the "Hash=SHA-512" function in bytes.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_Nh = ecc_opaque_ristretto255_sha512_Nh;

const ecc_opaque_ristretto255_sha512_Nx = 64;
/**
 * The size of pseudorandom keys.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_Nx = ecc_opaque_ristretto255_sha512_Nx;

const ecc_opaque_ristretto255_sha512_Npk = 32;
/**
 * The size of public keys used in the AKE.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_Npk = ecc_opaque_ristretto255_sha512_Npk;

const ecc_opaque_ristretto255_sha512_Nsk = 32;
/**
 * The size of private keys used in the AKE.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_Nsk = ecc_opaque_ristretto255_sha512_Nsk;

const ecc_opaque_ristretto255_sha512_Noe = 32;
/**
 * The size of a serialized OPRF group element.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_Noe = ecc_opaque_ristretto255_sha512_Noe;

const ecc_opaque_ristretto255_sha512_Ns = 32;
/**
 * The size of a serialized OPRF scalar.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_Ns = ecc_opaque_ristretto255_sha512_Ns;

const ecc_opaque_ristretto255_sha512_Nok = 32;
/**
 * The size of an OPRF private key.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_Nok = ecc_opaque_ristretto255_sha512_Nok;

const ecc_opaque_ristretto255_sha512_Ne = 96;
/**
 * <pre>
 * struct {
 *   uint8 nonce[Nn];
 *   uint8 auth_tag[Nm];
 * } Envelope;
 * </pre>
 *
 * nonce: A unique nonce of length Nn, used to protect this Envelope.
 * auth_tag: An authentication tag protecting the contents of the envelope, covering the envelope nonce and CleartextCredentials.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_Ne = ecc_opaque_ristretto255_sha512_Ne;

const ecc_opaque_ristretto255_sha512_PASSWORDMAXSIZE = 200;
/**
 * In order to avoid dynamic memory allocation, this limit is necessary.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_PASSWORDMAXSIZE = ecc_opaque_ristretto255_sha512_PASSWORDMAXSIZE;

const ecc_opaque_ristretto255_sha512_IDENTITYMAXSIZE = 200;
/**
 * In order to avoid dynamic memory allocation, this limit is necessary.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_IDENTITYMAXSIZE = ecc_opaque_ristretto255_sha512_IDENTITYMAXSIZE;

const ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE = 434;
/**
 *
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE = ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE;

const ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE = 32;
/**
 * <pre>
 * struct {
 *   uint8 blinded_message[Noe];
 * } RegistrationRequest;
 * </pre>
 *
 * blinded_message: A serialized OPRF group element.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE = ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE;

const ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE = 64;
/**
 * <pre>
 * typedef struct {
 *   uint8 evaluated_message[Noe];
 *   uint8 server_public_key[Npk];
 * } RegistrationResponse;
 * </pre>
 *
 * evaluated_message: A serialized OPRF group element.
 * server_public_key: The server's encoded public key that will be used for the online AKE stage.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE = ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE;

const ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE = 192;
/**
 * <pre>
 * struct {
 *   uint8 client_public_key[Npk];
 *   uint8 masking_key[Nh];
 *   Envelope envelope;
 * } RegistrationRecord;
 * </pre>
 *
 * client_public_key: The client's encoded public key, corresponding to the private key client_private_key.
 * masking_key: An encryption key used by the server to preserve confidentiality of the envelope during login to defend against client enumeration attacks.
 * envelope: The client's Envelope structure.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE = ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE;

const ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE = 32;
/**
 *
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE = ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE;

const ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE = 192;
/**
 *
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE = ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE;

const ecc_opaque_ristretto255_sha512_KE1SIZE = 96;
/**
 * <pre>
 * struct {
 *   CredentialRequest credential_request;
 *   AuthRequest auth_request;
 * } KE1;
 * </pre>
 *
 * credential_request: A CredentialRequest structure.
 * auth_request: An AuthRequest structure.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_KE1SIZE = ecc_opaque_ristretto255_sha512_KE1SIZE;

const ecc_opaque_ristretto255_sha512_KE2SIZE = 320;
/**
 * <pre>
 * struct {
 *   CredentialResponse credential_response;
 *   AuthResponse auth_response;
 * } KE2;
 * </pre>
 *
 * credential_response: A CredentialResponse structure.
 * auth_response: An AuthResponse structure.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_KE2SIZE = ecc_opaque_ristretto255_sha512_KE2SIZE;

const ecc_opaque_ristretto255_sha512_KE3SIZE = 64;
/**
 * <pre>
 * struct {
 *   uint8 client_mac[Nm];
 * } KE3;
 * </pre>
 *
 * client_mac: An authentication tag computed over the handshake transcript of fixed size Nm, computed using Km2.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_KE3SIZE = ecc_opaque_ristretto255_sha512_KE3SIZE;

const ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE = 361;
/**
 * <pre>
 * struct {
 *   uint8 password[PASSWORDMAXSIZE];
 *   uint8 password_len;
 *   uint8 blind[Nok];
 *   ClientAkeState_t client_ake_state;
 * } ClientState;
 * </pre>
 *
 * password: The client's password.
 * blind: The random blinding inverter returned by Blind().
 * client_ake_state: a ClientAkeState structure.
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE = ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE;

const ecc_opaque_ristretto255_sha512_SERVERSTATESIZE = 128;
/**
 *
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_SERVERSTATESIZE = ecc_opaque_ristretto255_sha512_SERVERSTATESIZE;

const ecc_opaque_ristretto255_sha512_MHF_IDENTITY = 0;
/**
 * Use Identity for the Memory Hard Function (MHF).
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_MHF_IDENTITY = ecc_opaque_ristretto255_sha512_MHF_IDENTITY;

const ecc_opaque_ristretto255_sha512_MHF_SCRYPT = 1;
/**
 * Use Scrypt(32768,8,1) for the Memory Hard Function (MHF).
 *
 * @type {number}
 */
Module.ecc_opaque_ristretto255_sha512_MHF_SCRYPT = ecc_opaque_ristretto255_sha512_MHF_SCRYPT;

/**
 * Derive a private and public key pair deterministically from a seed.
 *
 * @param {Uint8Array} private_key (output) a private key, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param {Uint8Array} public_key (output) the associated public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} seed pseudo-random byte sequence used as a seed, size:ecc_opaque_ristretto255_sha512_Nn
 */
Module.ecc_opaque_ristretto255_sha512_DeriveKeyPair = (
    private_key,
    public_key,
    seed,
) => {
    const ptr_private_key = mput(private_key, ecc_opaque_ristretto255_sha512_Nsk);
    const ptr_public_key = mput(public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_seed = mput(seed, ecc_opaque_ristretto255_sha512_Nn);
    _ecc_opaque_ristretto255_sha512_DeriveKeyPair(
        ptr_private_key,
        ptr_public_key,
        ptr_seed,
    );
    mget(private_key, ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mget(public_key, ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_seed, ecc_opaque_ristretto255_sha512_Nn);
}

/**
 * Constructs a "CleartextCredentials" structure given application
 * credential information.
 *
 * @param {Uint8Array} cleartext_credentials (output) a CleartextCredentials structure, size:ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE
 * @param {Uint8Array} server_public_key the encoded server public key for the AKE protocol, size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} client_public_key the encoded client public key for the AKE protocol, size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} server_identity the optional encoded server identity, size:server_identity_len
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} client_identity the optional encoded client identity, size:client_identity_len
 * @param {number} client_identity_len the length of `client_identity`
 */
Module.ecc_opaque_ristretto255_sha512_CreateCleartextCredentials = (
    cleartext_credentials,
    server_public_key,
    client_public_key,
    server_identity,
    server_identity_len,
    client_identity,
    client_identity_len,
) => {
    const ptr_cleartext_credentials = mput(cleartext_credentials, ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE);
    const ptr_server_public_key = mput(server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_client_public_key = mput(client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_server_identity = mput(server_identity, server_identity_len);
    const ptr_client_identity = mput(client_identity, client_identity_len);
    _ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
        ptr_cleartext_credentials,
        ptr_server_public_key,
        ptr_client_public_key,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len,
    );
    mget(cleartext_credentials, ptr_cleartext_credentials, ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE);
    mfree(ptr_cleartext_credentials, ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
}

/**
 * Same as calling `ecc_opaque_ristretto255_sha512_EnvelopeStore` with an
 * specified `nonce`.
 *
 * @param {Uint8Array} envelope (output) size:ecc_opaque_ristretto255_sha512_Ne
 * @param {Uint8Array} client_public_key (output) size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} masking_key (output) size:ecc_opaque_ristretto255_sha512_Nh
 * @param {Uint8Array} export_key (output) size:ecc_opaque_ristretto255_sha512_Nh
 * @param {Uint8Array} randomized_pwd size:64
 * @param {Uint8Array} server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} server_identity size:server_identity_len
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} client_identity size:client_identity_len
 * @param {number} client_identity_len the length of `client_identity`
 * @param {Uint8Array} nonce size:ecc_opaque_ristretto255_sha512_Nn
 */
Module.ecc_opaque_ristretto255_sha512_EnvelopeStoreWithNonce = (
    envelope,
    client_public_key,
    masking_key,
    export_key,
    randomized_pwd,
    server_public_key,
    server_identity,
    server_identity_len,
    client_identity,
    client_identity_len,
    nonce,
) => {
    const ptr_envelope = mput(envelope, ecc_opaque_ristretto255_sha512_Ne);
    const ptr_client_public_key = mput(client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_masking_key = mput(masking_key, ecc_opaque_ristretto255_sha512_Nh);
    const ptr_export_key = mput(export_key, ecc_opaque_ristretto255_sha512_Nh);
    const ptr_randomized_pwd = mput(randomized_pwd, 64);
    const ptr_server_public_key = mput(server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_server_identity = mput(server_identity, server_identity_len);
    const ptr_client_identity = mput(client_identity, client_identity_len);
    const ptr_nonce = mput(nonce, ecc_opaque_ristretto255_sha512_Nn);
    _ecc_opaque_ristretto255_sha512_EnvelopeStoreWithNonce(
        ptr_envelope,
        ptr_client_public_key,
        ptr_masking_key,
        ptr_export_key,
        ptr_randomized_pwd,
        ptr_server_public_key,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len,
        ptr_nonce,
    );
    mget(envelope, ptr_envelope, ecc_opaque_ristretto255_sha512_Ne);
    mget(client_public_key, ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mget(masking_key, ptr_masking_key, ecc_opaque_ristretto255_sha512_Nh);
    mget(export_key, ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_envelope, ecc_opaque_ristretto255_sha512_Ne);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_masking_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_randomized_pwd, 64);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_nonce, ecc_opaque_ristretto255_sha512_Nn);
}

/**
 * Creates an "Envelope" at registration.
 *
 * In order to work with stack allocated memory (i.e. fixed and not dynamic
 * allocation), it's necessary to add the restriction on length of the
 * identities to less than 200 bytes.
 *
 * @param {Uint8Array} envelope (output) size:ecc_opaque_ristretto255_sha512_Ne
 * @param {Uint8Array} client_public_key (output) size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} masking_key (output) size:ecc_opaque_ristretto255_sha512_Nh
 * @param {Uint8Array} export_key (output) size:ecc_opaque_ristretto255_sha512_Nh
 * @param {Uint8Array} randomized_pwd size:64
 * @param {Uint8Array} server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} server_identity size:server_identity_len
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} client_identity size:client_identity_len
 * @param {number} client_identity_len the length of `client_identity`
 */
Module.ecc_opaque_ristretto255_sha512_EnvelopeStore = (
    envelope,
    client_public_key,
    masking_key,
    export_key,
    randomized_pwd,
    server_public_key,
    server_identity,
    server_identity_len,
    client_identity,
    client_identity_len,
) => {
    const ptr_envelope = mput(envelope, ecc_opaque_ristretto255_sha512_Ne);
    const ptr_client_public_key = mput(client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_masking_key = mput(masking_key, ecc_opaque_ristretto255_sha512_Nh);
    const ptr_export_key = mput(export_key, ecc_opaque_ristretto255_sha512_Nh);
    const ptr_randomized_pwd = mput(randomized_pwd, 64);
    const ptr_server_public_key = mput(server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_server_identity = mput(server_identity, server_identity_len);
    const ptr_client_identity = mput(client_identity, client_identity_len);
    _ecc_opaque_ristretto255_sha512_EnvelopeStore(
        ptr_envelope,
        ptr_client_public_key,
        ptr_masking_key,
        ptr_export_key,
        ptr_randomized_pwd,
        ptr_server_public_key,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len,
    );
    mget(envelope, ptr_envelope, ecc_opaque_ristretto255_sha512_Ne);
    mget(client_public_key, ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mget(masking_key, ptr_masking_key, ecc_opaque_ristretto255_sha512_Nh);
    mget(export_key, ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_envelope, ecc_opaque_ristretto255_sha512_Ne);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_masking_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_randomized_pwd, 64);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
}

/**
 * This functions attempts to recover the credentials from the input. On
 * success returns 0, else -1.
 *
 * @param {Uint8Array} client_private_key (output) size:ecc_opaque_ristretto255_sha512_Nsk
 * @param {Uint8Array} export_key (output) size:ecc_opaque_ristretto255_sha512_Nh
 * @param {Uint8Array} randomized_pwd size:64
 * @param {Uint8Array} server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} envelope_raw size:ecc_opaque_ristretto255_sha512_Ne
 * @param {Uint8Array} server_identity size:server_identity_len
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} client_identity size:client_identity_len
 * @param {number} client_identity_len the length of `client_identity`
 * @return {number} on success returns 0, else -1.
 */
Module.ecc_opaque_ristretto255_sha512_EnvelopeRecover = (
    client_private_key,
    export_key,
    randomized_pwd,
    server_public_key,
    envelope_raw,
    server_identity,
    server_identity_len,
    client_identity,
    client_identity_len,
) => {
    const ptr_client_private_key = mput(client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    const ptr_export_key = mput(export_key, ecc_opaque_ristretto255_sha512_Nh);
    const ptr_randomized_pwd = mput(randomized_pwd, 64);
    const ptr_server_public_key = mput(server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_envelope_raw = mput(envelope_raw, ecc_opaque_ristretto255_sha512_Ne);
    const ptr_server_identity = mput(server_identity, server_identity_len);
    const ptr_client_identity = mput(client_identity, client_identity_len);
    const fun_ret = _ecc_opaque_ristretto255_sha512_EnvelopeRecover(
        ptr_client_private_key,
        ptr_export_key,
        ptr_randomized_pwd,
        ptr_server_public_key,
        ptr_envelope_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len,
    );
    mget(client_private_key, ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mget(export_key, ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_randomized_pwd, 64);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_envelope_raw, ecc_opaque_ristretto255_sha512_Ne);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
    return fun_ret;
}

/**
 * Recover the public key related to the input "private_key".
 *
 * @param {Uint8Array} public_key (output) size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} private_key size:ecc_opaque_ristretto255_sha512_Nsk
 */
Module.ecc_opaque_ristretto255_sha512_RecoverPublicKey = (
    public_key,
    private_key,
) => {
    const ptr_public_key = mput(public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_private_key = mput(private_key, ecc_opaque_ristretto255_sha512_Nsk);
    _ecc_opaque_ristretto255_sha512_RecoverPublicKey(
        ptr_public_key,
        ptr_private_key,
    );
    mget(public_key, ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
}

/**
 * Returns a randomly generated private and public key pair.
 *
 * This is implemented by generating a random "seed", then
 * calling internally DeriveAuthKeyPair.
 *
 * @param {Uint8Array} private_key (output) a private key, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param {Uint8Array} public_key (output) the associated public key, size:ecc_opaque_ristretto255_sha512_Npk
 */
Module.ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair = (
    private_key,
    public_key,
) => {
    const ptr_private_key = mput(private_key, ecc_opaque_ristretto255_sha512_Nsk);
    const ptr_public_key = mput(public_key, ecc_opaque_ristretto255_sha512_Npk);
    _ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(
        ptr_private_key,
        ptr_public_key,
    );
    mget(private_key, ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mget(public_key, ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
}

/**
 * Derive a private and public authentication key pair deterministically
 * from the input "seed".
 *
 * @param {Uint8Array} private_key (output) a private key, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param {Uint8Array} public_key (output) the associated public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} seed pseudo-random byte sequence used as a seed, size:ecc_opaque_ristretto255_sha512_Nn
 */
Module.ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair = (
    private_key,
    public_key,
    seed,
) => {
    const ptr_private_key = mput(private_key, ecc_opaque_ristretto255_sha512_Nsk);
    const ptr_public_key = mput(public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_seed = mput(seed, ecc_opaque_ristretto255_sha512_Nn);
    _ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
        ptr_private_key,
        ptr_public_key,
        ptr_seed,
    );
    mget(private_key, ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mget(public_key, ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_seed, ecc_opaque_ristretto255_sha512_Nn);
}

/**
 * Same as calling CreateRegistrationRequest with a specified blind.
 *
 * @param {Uint8Array} request (output) a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
 * @param {Uint8Array} password an opaque byte string containing the client's password, size:password_len
 * @param {number} password_len the length of `password`
 * @param {Uint8Array} blind the OPRF scalar value to use, size:ecc_opaque_ristretto255_sha512_Ns
 */
Module.ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind = (
    request,
    password,
    password_len,
    blind,
) => {
    const ptr_request = mput(request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    const ptr_password = mput(password, password_len);
    const ptr_blind = mput(blind, ecc_opaque_ristretto255_sha512_Ns);
    _ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
        ptr_request,
        ptr_password,
        password_len,
        ptr_blind,
    );
    mget(request, ptr_request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mfree(ptr_request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Ns);
}

/**
 * To begin the registration flow, the client executes this function.
 *
 * @param {Uint8Array} request (output) a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
 * @param {Uint8Array} blind (output) an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Ns
 * @param {Uint8Array} password an opaque byte string containing the client's password, size:password_len
 * @param {number} password_len the length of `password`
 */
Module.ecc_opaque_ristretto255_sha512_CreateRegistrationRequest = (
    request,
    blind,
    password,
    password_len,
) => {
    const ptr_request = mput(request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    const ptr_blind = mput(blind, ecc_opaque_ristretto255_sha512_Ns);
    const ptr_password = mput(password, password_len);
    _ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
        ptr_request,
        ptr_blind,
        ptr_password,
        password_len,
    );
    mget(request, ptr_request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mget(blind, ptr_blind, ecc_opaque_ristretto255_sha512_Ns);
    mfree(ptr_request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Ns);
    mfree(ptr_password, password_len);
}

/**
 * To process the client's registration request, the server executes
 * this function.
 *
 * @param {Uint8Array} response (output) a RegistrationResponse structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
 * @param {Uint8Array} request a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
 * @param {Uint8Array} server_public_key the server's public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} credential_identifier an identifier that uniquely represents the credential, size:credential_identifier_len
 * @param {number} credential_identifier_len the length of `credential_identifier`
 * @param {Uint8Array} oprf_seed the seed of Nh bytes used by the server to generate an oprf_key, size:ecc_opaque_ristretto255_sha512_Nh
 */
Module.ecc_opaque_ristretto255_sha512_CreateRegistrationResponse = (
    response,
    request,
    server_public_key,
    credential_identifier,
    credential_identifier_len,
    oprf_seed,
) => {
    const ptr_response = mput(response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    const ptr_request = mput(request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    const ptr_server_public_key = mput(server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_credential_identifier = mput(credential_identifier, credential_identifier_len);
    const ptr_oprf_seed = mput(oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    _ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
        ptr_response,
        ptr_request,
        ptr_server_public_key,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed,
    );
    mget(response, ptr_response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mfree(ptr_response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mfree(ptr_request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_credential_identifier, credential_identifier_len);
    mfree(ptr_oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
}

/**
 * Same as calling `ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequest` with an
 * specified `nonce`.
 *
 * @param {Uint8Array} record (output) a RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE
 * @param {Uint8Array} export_key (output) an additional client key, size:ecc_opaque_ristretto255_sha512_Nh
 * @param {Uint8Array} password an opaque byte string containing the client's password, size:password_len
 * @param {number} password_len the length of `password`
 * @param {Uint8Array} blind an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Ns
 * @param {Uint8Array} response a RegistrationResponse structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
 * @param {Uint8Array} server_identity the optional encoded server identity, size:server_identity_len
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} client_identity the optional encoded client identity, size:client_identity_len
 * @param {number} client_identity_len the length of `client_identity`
 * @param {number} mhf the memory hard function to use
 * @param {Uint8Array} nonce size:ecc_opaque_ristretto255_sha512_Nn
 */
Module.ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequestWithNonce = (
    record,
    export_key,
    password,
    password_len,
    blind,
    response,
    server_identity,
    server_identity_len,
    client_identity,
    client_identity_len,
    mhf,
    nonce,
) => {
    const ptr_record = mput(record, ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    const ptr_export_key = mput(export_key, ecc_opaque_ristretto255_sha512_Nh);
    const ptr_password = mput(password, password_len);
    const ptr_blind = mput(blind, ecc_opaque_ristretto255_sha512_Ns);
    const ptr_response = mput(response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    const ptr_server_identity = mput(server_identity, server_identity_len);
    const ptr_client_identity = mput(client_identity, client_identity_len);
    const ptr_nonce = mput(nonce, ecc_opaque_ristretto255_sha512_Nn);
    _ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequestWithNonce(
        ptr_record,
        ptr_export_key,
        ptr_password,
        password_len,
        ptr_blind,
        ptr_response,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len,
        mhf,
        ptr_nonce,
    );
    mget(record, ptr_record, ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    mget(export_key, ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_record, ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    mfree(ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Ns);
    mfree(ptr_response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_nonce, ecc_opaque_ristretto255_sha512_Nn);
}

/**
 * To create the user record used for subsequent authentication and complete the
 * registration flow, the client executes the following function.
 *
 * @param {Uint8Array} record (output) a RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE
 * @param {Uint8Array} export_key (output) an additional client key, size:ecc_opaque_ristretto255_sha512_Nh
 * @param {Uint8Array} password an opaque byte string containing the client's password, size:password_len
 * @param {number} password_len the length of `password`
 * @param {Uint8Array} blind an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Ns
 * @param {Uint8Array} response a RegistrationResponse structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
 * @param {Uint8Array} server_identity the optional encoded server identity, size:server_identity_len
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} client_identity the optional encoded client identity, size:client_identity_len
 * @param {number} client_identity_len the length of `client_identity`
 * @param {number} mhf the memory hard function to use
 */
Module.ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequest = (
    record,
    export_key,
    password,
    password_len,
    blind,
    response,
    server_identity,
    server_identity_len,
    client_identity,
    client_identity_len,
    mhf,
) => {
    const ptr_record = mput(record, ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    const ptr_export_key = mput(export_key, ecc_opaque_ristretto255_sha512_Nh);
    const ptr_password = mput(password, password_len);
    const ptr_blind = mput(blind, ecc_opaque_ristretto255_sha512_Ns);
    const ptr_response = mput(response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    const ptr_server_identity = mput(server_identity, server_identity_len);
    const ptr_client_identity = mput(client_identity, client_identity_len);
    _ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequest(
        ptr_record,
        ptr_export_key,
        ptr_password,
        password_len,
        ptr_blind,
        ptr_response,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len,
        mhf,
    );
    mget(record, ptr_record, ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    mget(export_key, ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_record, ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    mfree(ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Ns);
    mfree(ptr_response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
}

/**
 *
 *
 * @param {Uint8Array} request (output) a CredentialRequest structure, size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 * @param {Uint8Array} password an opaque byte string containing the client's password, size:password_len
 * @param {number} password_len the length of `password`
 * @param {Uint8Array} blind an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Ns
 */
Module.ecc_opaque_ristretto255_sha512_CreateCredentialRequestWithBlind = (
    request,
    password,
    password_len,
    blind,
) => {
    const ptr_request = mput(request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    const ptr_password = mput(password, password_len);
    const ptr_blind = mput(blind, ecc_opaque_ristretto255_sha512_Ns);
    _ecc_opaque_ristretto255_sha512_CreateCredentialRequestWithBlind(
        ptr_request,
        ptr_password,
        password_len,
        ptr_blind,
    );
    mget(request, ptr_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mfree(ptr_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Ns);
}

/**
 *
 *
 * @param {Uint8Array} request (output) a CredentialRequest structure, size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 * @param {Uint8Array} blind (output) an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Ns
 * @param {Uint8Array} password an opaque byte string containing the client's password, size:password_len
 * @param {number} password_len the length of `password`
 */
Module.ecc_opaque_ristretto255_sha512_CreateCredentialRequest = (
    request,
    blind,
    password,
    password_len,
) => {
    const ptr_request = mput(request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    const ptr_blind = mput(blind, ecc_opaque_ristretto255_sha512_Ns);
    const ptr_password = mput(password, password_len);
    _ecc_opaque_ristretto255_sha512_CreateCredentialRequest(
        ptr_request,
        ptr_blind,
        ptr_password,
        password_len,
    );
    mget(request, ptr_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mget(blind, ptr_blind, ecc_opaque_ristretto255_sha512_Ns);
    mfree(ptr_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Ns);
    mfree(ptr_password, password_len);
}

/**
 * In order to make this method not to use dynamic memory allocation, there is a
 * limit of credential_identifier_len
 * <
 * = 200.
 *
 * There are two scenarios to handle for the construction of a
 * CredentialResponse object: either the record for the client exists
 * (corresponding to a properly registered client), or it was never
 * created (corresponding to a client that has yet to register).
 *
 * In the case of a record that does not exist, the server SHOULD invoke
 * the CreateCredentialResponse function where the record argument is
 * configured so that:
 *
 * - record.masking_key is set to a random byte string of length Nh, and
 * - record.envelope is set to the byte string consisting only of
 * zeros, of length Ne
 *
 * @param {Uint8Array} response_raw (output) size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
 * @param {Uint8Array} request_raw size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 * @param {Uint8Array} server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} record_raw size:ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE
 * @param {Uint8Array} credential_identifier size:credential_identifier_len
 * @param {number} credential_identifier_len the length of `credential_identifier`
 * @param {Uint8Array} oprf_seed size:ecc_opaque_ristretto255_sha512_Nh
 * @param {Uint8Array} masking_nonce size:ecc_opaque_ristretto255_sha512_Nn
 */
Module.ecc_opaque_ristretto255_sha512_CreateCredentialResponseWithMasking = (
    response_raw,
    request_raw,
    server_public_key,
    record_raw,
    credential_identifier,
    credential_identifier_len,
    oprf_seed,
    masking_nonce,
) => {
    const ptr_response_raw = mput(response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    const ptr_request_raw = mput(request_raw, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    const ptr_server_public_key = mput(server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_record_raw = mput(record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    const ptr_credential_identifier = mput(credential_identifier, credential_identifier_len);
    const ptr_oprf_seed = mput(oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    const ptr_masking_nonce = mput(masking_nonce, ecc_opaque_ristretto255_sha512_Nn);
    _ecc_opaque_ristretto255_sha512_CreateCredentialResponseWithMasking(
        ptr_response_raw,
        ptr_request_raw,
        ptr_server_public_key,
        ptr_record_raw,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed,
        ptr_masking_nonce,
    );
    mget(response_raw, ptr_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_request_raw, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    mfree(ptr_credential_identifier, credential_identifier_len);
    mfree(ptr_oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_masking_nonce, ecc_opaque_ristretto255_sha512_Nn);
}

/**
 * In order to make this method not to use dynamic memory allocation, there is a
 * limit of credential_identifier_len
 * <
 * = 200.
 *
 * There are two scenarios to handle for the construction of a
 * CredentialResponse object: either the record for the client exists
 * (corresponding to a properly registered client), or it was never
 * created (corresponding to a client that has yet to register).
 *
 * In the case of a record that does not exist, the server SHOULD invoke
 * the CreateCredentialResponse function where the record argument is
 * configured so that:
 *
 * - record.masking_key is set to a random byte string of length Nh, and
 * - record.envelope is set to the byte string consisting only of
 * zeros, of length Ne
 *
 * @param {Uint8Array} response_raw (output) size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
 * @param {Uint8Array} request_raw size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 * @param {Uint8Array} server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} record_raw size:ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE
 * @param {Uint8Array} credential_identifier size:credential_identifier_len
 * @param {number} credential_identifier_len the length of `credential_identifier`
 * @param {Uint8Array} oprf_seed size:ecc_opaque_ristretto255_sha512_Nh
 */
Module.ecc_opaque_ristretto255_sha512_CreateCredentialResponse = (
    response_raw,
    request_raw,
    server_public_key,
    record_raw,
    credential_identifier,
    credential_identifier_len,
    oprf_seed,
) => {
    const ptr_response_raw = mput(response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    const ptr_request_raw = mput(request_raw, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    const ptr_server_public_key = mput(server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_record_raw = mput(record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    const ptr_credential_identifier = mput(credential_identifier, credential_identifier_len);
    const ptr_oprf_seed = mput(oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    _ecc_opaque_ristretto255_sha512_CreateCredentialResponse(
        ptr_response_raw,
        ptr_request_raw,
        ptr_server_public_key,
        ptr_record_raw,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed,
    );
    mget(response_raw, ptr_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_request_raw, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    mfree(ptr_credential_identifier, credential_identifier_len);
    mfree(ptr_oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
}

/**
 *
 *
 * @param {Uint8Array} client_private_key (output) size:ecc_opaque_ristretto255_sha512_Nsk
 * @param {Uint8Array} server_public_key (output) size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} export_key (output) size:ecc_opaque_ristretto255_sha512_Nh
 * @param {Uint8Array} password size:password_len
 * @param {number} password_len the length of `password`
 * @param {Uint8Array} blind size:ecc_opaque_ristretto255_sha512_Noe
 * @param {Uint8Array} response size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
 * @param {Uint8Array} server_identity size:server_identity_len
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} client_identity size:client_identity_len
 * @param {number} client_identity_len the length of `client_identity`
 * @param {number} mhf the memory hard function to use
 * @return {number} on success returns 0, else -1.
 */
Module.ecc_opaque_ristretto255_sha512_RecoverCredentials = (
    client_private_key,
    server_public_key,
    export_key,
    password,
    password_len,
    blind,
    response,
    server_identity,
    server_identity_len,
    client_identity,
    client_identity_len,
    mhf,
) => {
    const ptr_client_private_key = mput(client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    const ptr_server_public_key = mput(server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_export_key = mput(export_key, ecc_opaque_ristretto255_sha512_Nh);
    const ptr_password = mput(password, password_len);
    const ptr_blind = mput(blind, ecc_opaque_ristretto255_sha512_Noe);
    const ptr_response = mput(response, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    const ptr_server_identity = mput(server_identity, server_identity_len);
    const ptr_client_identity = mput(client_identity, client_identity_len);
    const fun_ret = _ecc_opaque_ristretto255_sha512_RecoverCredentials(
        ptr_client_private_key,
        ptr_server_public_key,
        ptr_export_key,
        ptr_password,
        password_len,
        ptr_blind,
        ptr_response,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len,
        mhf,
    );
    mget(client_private_key, ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mget(server_public_key, ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mget(export_key, ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_response, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
    return fun_ret;
}

/**
 *
 *
 * @param {Uint8Array} out (output) size:length
 * @param {Uint8Array} secret size:64
 * @param {Uint8Array} label size:label_len
 * @param {number} label_len the length of `label`
 * @param {Uint8Array} context size:context_len
 * @param {number} context_len the length of `context`
 * @param {number} length the length of the output
 */
Module.ecc_opaque_ristretto255_sha512_3DH_Expand_Label = (
    out,
    secret,
    label,
    label_len,
    context,
    context_len,
    length,
) => {
    const ptr_out = mput(out, length);
    const ptr_secret = mput(secret, 64);
    const ptr_label = mput(label, label_len);
    const ptr_context = mput(context, context_len);
    _ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
        ptr_out,
        ptr_secret,
        ptr_label,
        label_len,
        ptr_context,
        context_len,
        length,
    );
    mget(out, ptr_out, length);
    mfree(ptr_out, length);
    mfree(ptr_secret, 64);
    mfree(ptr_label, label_len);
    mfree(ptr_context, context_len);
}

/**
 *
 *
 * @param {Uint8Array} out (output) size:ecc_opaque_ristretto255_sha512_Nx
 * @param {Uint8Array} secret size:64
 * @param {Uint8Array} label size:label_len
 * @param {number} label_len the length of `label`
 * @param {Uint8Array} transcript_hash size:transcript_hash_len
 * @param {number} transcript_hash_len the length of `transcript_hash`
 */
Module.ecc_opaque_ristretto255_sha512_3DH_Derive_Secret = (
    out,
    secret,
    label,
    label_len,
    transcript_hash,
    transcript_hash_len,
) => {
    const ptr_out = mput(out, ecc_opaque_ristretto255_sha512_Nx);
    const ptr_secret = mput(secret, 64);
    const ptr_label = mput(label, label_len);
    const ptr_transcript_hash = mput(transcript_hash, transcript_hash_len);
    _ecc_opaque_ristretto255_sha512_3DH_Derive_Secret(
        ptr_out,
        ptr_secret,
        ptr_label,
        label_len,
        ptr_transcript_hash,
        transcript_hash_len,
    );
    mget(out, ptr_out, ecc_opaque_ristretto255_sha512_Nx);
    mfree(ptr_out, ecc_opaque_ristretto255_sha512_Nx);
    mfree(ptr_secret, 64);
    mfree(ptr_label, label_len);
    mfree(ptr_transcript_hash, transcript_hash_len);
}

/**
 * The OPAQUE-3DH key schedule requires a preamble.
 *
 * OPAQUE-3DH can optionally include shared "context" information in the
 * transcript, such as configuration parameters or application-specific
 * info, e.g. "appXYZ-v1.2.3".
 *
 * @param {Uint8Array} preamble (output) the protocol transcript with identities and messages, size:preamble_len
 * @param {number} preamble_len the length of `preamble`
 * @param {Uint8Array} context optional shared context information, size:context_len
 * @param {number} context_len the length of `context`
 * @param {Uint8Array} client_identity the optional encoded client identity, size:client_identity_len
 * @param {number} client_identity_len the length of `client_identity`
 * @param {Uint8Array} client_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} ke1 a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param {Uint8Array} server_identity the optional encoded server identity, size:server_identity_len
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} ke2 a ke2 structure as defined in KE2, size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @return {number} the protocol transcript with identities and messages
 */
Module.ecc_opaque_ristretto255_sha512_3DH_Preamble = (
    preamble,
    preamble_len,
    context,
    context_len,
    client_identity,
    client_identity_len,
    client_public_key,
    ke1,
    server_identity,
    server_identity_len,
    server_public_key,
    ke2,
) => {
    const ptr_preamble = mput(preamble, preamble_len);
    const ptr_context = mput(context, context_len);
    const ptr_client_identity = mput(client_identity, client_identity_len);
    const ptr_client_public_key = mput(client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_ke1 = mput(ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    const ptr_server_identity = mput(server_identity, server_identity_len);
    const ptr_server_public_key = mput(server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_ke2 = mput(ke2, ecc_opaque_ristretto255_sha512_KE2SIZE);
    const fun_ret = _ecc_opaque_ristretto255_sha512_3DH_Preamble(
        ptr_preamble,
        preamble_len,
        ptr_context,
        context_len,
        ptr_client_identity,
        client_identity_len,
        ptr_client_public_key,
        ptr_ke1,
        ptr_server_identity,
        server_identity_len,
        ptr_server_public_key,
        ptr_ke2,
    );
    mget(preamble, ptr_preamble, preamble_len);
    mfree(ptr_preamble, preamble_len);
    mfree(ptr_context, context_len);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_ke2, ecc_opaque_ristretto255_sha512_KE2SIZE);
    return fun_ret;
}

/**
 * Computes the OPAQUE-3DH shared secret derived during the key
 * exchange protocol.
 *
 * @param {Uint8Array} ikm (output) size:96
 * @param {Uint8Array} sk1 size:32
 * @param {Uint8Array} pk1 size:32
 * @param {Uint8Array} sk2 size:32
 * @param {Uint8Array} pk2 size:32
 * @param {Uint8Array} sk3 size:32
 * @param {Uint8Array} pk3 size:32
 */
Module.ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM = (
    ikm,
    sk1,
    pk1,
    sk2,
    pk2,
    sk3,
    pk3,
) => {
    const ptr_ikm = mput(ikm, 96);
    const ptr_sk1 = mput(sk1, 32);
    const ptr_pk1 = mput(pk1, 32);
    const ptr_sk2 = mput(sk2, 32);
    const ptr_pk2 = mput(pk2, 32);
    const ptr_sk3 = mput(sk3, 32);
    const ptr_pk3 = mput(pk3, 32);
    _ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM(
        ptr_ikm,
        ptr_sk1,
        ptr_pk1,
        ptr_sk2,
        ptr_pk2,
        ptr_sk3,
        ptr_pk3,
    );
    mget(ikm, ptr_ikm, 96);
    mfree(ptr_ikm, 96);
    mfree(ptr_sk1, 32);
    mfree(ptr_pk1, 32);
    mfree(ptr_sk2, 32);
    mfree(ptr_pk2, 32);
    mfree(ptr_sk3, 32);
    mfree(ptr_pk3, 32);
}

/**
 *
 *
 * @param {Uint8Array} km2 (output) size:64
 * @param {Uint8Array} km3 (output) size:64
 * @param {Uint8Array} session_key (output) size:64
 * @param {Uint8Array} ikm size:ikm_len
 * @param {number} ikm_len the length of `ikm`
 * @param {Uint8Array} preamble size:preamble_len
 * @param {number} preamble_len the length of `preamble`
 */
Module.ecc_opaque_ristretto255_sha512_3DH_DeriveKeys = (
    km2,
    km3,
    session_key,
    ikm,
    ikm_len,
    preamble,
    preamble_len,
) => {
    const ptr_km2 = mput(km2, 64);
    const ptr_km3 = mput(km3, 64);
    const ptr_session_key = mput(session_key, 64);
    const ptr_ikm = mput(ikm, ikm_len);
    const ptr_preamble = mput(preamble, preamble_len);
    _ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
        ptr_km2,
        ptr_km3,
        ptr_session_key,
        ptr_ikm,
        ikm_len,
        ptr_preamble,
        preamble_len,
    );
    mget(km2, ptr_km2, 64);
    mget(km3, ptr_km3, 64);
    mget(session_key, ptr_session_key, 64);
    mfree(ptr_km2, 64);
    mfree(ptr_km3, 64);
    mfree(ptr_session_key, 64);
    mfree(ptr_ikm, ikm_len);
    mfree(ptr_preamble, preamble_len);
}

/**
 *
 *
 * @param {Uint8Array} ke1 (output) a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param {Uint8Array} state (input, output) a ClientState structure, size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param {Uint8Array} password an opaque byte string containing the client's password, size:password_len
 * @param {number} password_len the length of `password`
 * @param {Uint8Array} blind size:ecc_opaque_ristretto255_sha512_Ns
 * @param {Uint8Array} client_nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param {Uint8Array} client_secret size:ecc_opaque_ristretto255_sha512_Nsk
 * @param {Uint8Array} client_keyshare size:ecc_opaque_ristretto255_sha512_Npk
 */
Module.ecc_opaque_ristretto255_sha512_ClientInitWithSecrets = (
    ke1,
    state,
    password,
    password_len,
    blind,
    client_nonce,
    client_secret,
    client_keyshare,
) => {
    const ptr_ke1 = mput(ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    const ptr_state = mput(state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    const ptr_password = mput(password, password_len);
    const ptr_blind = mput(blind, ecc_opaque_ristretto255_sha512_Ns);
    const ptr_client_nonce = mput(client_nonce, ecc_opaque_ristretto255_sha512_Nn);
    const ptr_client_secret = mput(client_secret, ecc_opaque_ristretto255_sha512_Nsk);
    const ptr_client_keyshare = mput(client_keyshare, ecc_opaque_ristretto255_sha512_Npk);
    _ecc_opaque_ristretto255_sha512_ClientInitWithSecrets(
        ptr_ke1,
        ptr_state,
        ptr_password,
        password_len,
        ptr_blind,
        ptr_client_nonce,
        ptr_client_secret,
        ptr_client_keyshare,
    );
    mget(ke1, ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mget(state, ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Ns);
    mfree(ptr_client_nonce, ecc_opaque_ristretto255_sha512_Nn);
    mfree(ptr_client_secret, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_client_keyshare, ecc_opaque_ristretto255_sha512_Npk);
}

/**
 *
 *
 * @param {Uint8Array} ke1 (output) a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param {Uint8Array} state (input, output) a ClientState structure, size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param {Uint8Array} password an opaque byte string containing the client's password, size:password_len
 * @param {number} password_len the length of `password`
 */
Module.ecc_opaque_ristretto255_sha512_ClientInit = (
    ke1,
    state,
    password,
    password_len,
) => {
    const ptr_ke1 = mput(ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    const ptr_state = mput(state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    const ptr_password = mput(password, password_len);
    _ecc_opaque_ristretto255_sha512_ClientInit(
        ptr_ke1,
        ptr_state,
        ptr_password,
        password_len,
    );
    mget(ke1, ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mget(state, ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_password, password_len);
}

/**
 *
 *
 * @param {Uint8Array} ke3_raw (output) a KE3 message structure, size:ecc_opaque_ristretto255_sha512_KE3SIZE
 * @param {Uint8Array} session_key (output) the session's shared secret, size:64
 * @param {Uint8Array} export_key (output) an additional client key, size:64
 * @param {Uint8Array} state (input, output) a ClientState structure, size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param {Uint8Array} client_identity the optional encoded client identity, which is set
 * to client_public_key if not specified, size:client_identity_len
 * @param {number} client_identity_len the length of `client_identity`
 * @param {Uint8Array} server_identity the optional encoded server identity, which is set
 * to server_public_key if not specified, size:server_identity_len
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} ke2 a KE2 message structure, size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param {number} mhf the memory hard function to use
 * @param {Uint8Array} context the application specific context, size:context_len
 * @param {number} context_len the length of `context`
 * @return {number} 0 if is able to recover credentials and authenticate with the server, else -1
 */
Module.ecc_opaque_ristretto255_sha512_ClientFinish = (
    ke3_raw,
    session_key,
    export_key,
    state,
    client_identity,
    client_identity_len,
    server_identity,
    server_identity_len,
    ke2,
    mhf,
    context,
    context_len,
) => {
    const ptr_ke3_raw = mput(ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    const ptr_session_key = mput(session_key, 64);
    const ptr_export_key = mput(export_key, 64);
    const ptr_state = mput(state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    const ptr_client_identity = mput(client_identity, client_identity_len);
    const ptr_server_identity = mput(server_identity, server_identity_len);
    const ptr_ke2 = mput(ke2, ecc_opaque_ristretto255_sha512_KE2SIZE);
    const ptr_context = mput(context, context_len);
    const fun_ret = _ecc_opaque_ristretto255_sha512_ClientFinish(
        ptr_ke3_raw,
        ptr_session_key,
        ptr_export_key,
        ptr_state,
        ptr_client_identity,
        client_identity_len,
        ptr_server_identity,
        server_identity_len,
        ptr_ke2,
        mhf,
        ptr_context,
        context_len,
    );
    mget(ke3_raw, ptr_ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    mget(session_key, ptr_session_key, 64);
    mget(export_key, ptr_export_key, 64);
    mget(state, ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    mfree(ptr_session_key, 64);
    mfree(ptr_export_key, 64);
    mfree(ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_ke2, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mfree(ptr_context, context_len);
    return fun_ret;
}

/**
 *
 *
 * @param {Uint8Array} ke1 (output) size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param {Uint8Array} state (input, output) size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param {Uint8Array} credential_request size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 * @param {Uint8Array} client_nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param {Uint8Array} client_secret size:ecc_opaque_ristretto255_sha512_Nsk
 * @param {Uint8Array} client_keyshare size:ecc_opaque_ristretto255_sha512_Npk
 */
Module.ecc_opaque_ristretto255_sha512_3DH_StartWithSecrets = (
    ke1,
    state,
    credential_request,
    client_nonce,
    client_secret,
    client_keyshare,
) => {
    const ptr_ke1 = mput(ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    const ptr_state = mput(state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    const ptr_credential_request = mput(credential_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    const ptr_client_nonce = mput(client_nonce, ecc_opaque_ristretto255_sha512_Nn);
    const ptr_client_secret = mput(client_secret, ecc_opaque_ristretto255_sha512_Nsk);
    const ptr_client_keyshare = mput(client_keyshare, ecc_opaque_ristretto255_sha512_Npk);
    _ecc_opaque_ristretto255_sha512_3DH_StartWithSecrets(
        ptr_ke1,
        ptr_state,
        ptr_credential_request,
        ptr_client_nonce,
        ptr_client_secret,
        ptr_client_keyshare,
    );
    mget(ke1, ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mget(state, ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_credential_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mfree(ptr_client_nonce, ecc_opaque_ristretto255_sha512_Nn);
    mfree(ptr_client_secret, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_client_keyshare, ecc_opaque_ristretto255_sha512_Npk);
}

/**
 *
 *
 * @param {Uint8Array} ke1 (output) size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param {Uint8Array} state (input, output) size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param {Uint8Array} credential_request size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 */
Module.ecc_opaque_ristretto255_sha512_3DH_Start = (
    ke1,
    state,
    credential_request,
) => {
    const ptr_ke1 = mput(ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    const ptr_state = mput(state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    const ptr_credential_request = mput(credential_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    _ecc_opaque_ristretto255_sha512_3DH_Start(
        ptr_ke1,
        ptr_state,
        ptr_credential_request,
    );
    mget(ke1, ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mget(state, ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_credential_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
}

/**
 *
 *
 * @param {Uint8Array} ke3_raw (output) size:ecc_opaque_ristretto255_sha512_KE3SIZE
 * @param {Uint8Array} session_key (output) size:64
 * @param {Uint8Array} state_raw (input, output) size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param {Uint8Array} client_identity size:client_identity_len
 * @param {number} client_identity_len the length of `client_identity`
 * @param {Uint8Array} client_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param {Uint8Array} server_identity size:server_identity_len
 * @param {number} server_identity_len the lenght of `server_identity`
 * @param {Uint8Array} server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} ke2_raw size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param {Uint8Array} context the application specific context, size:context_len
 * @param {number} context_len the length of `context`
 * @return {number} 0 if success, else -1
 */
Module.ecc_opaque_ristretto255_sha512_3DH_ClientFinalize = (
    ke3_raw,
    session_key,
    state_raw,
    client_identity,
    client_identity_len,
    client_private_key,
    server_identity,
    server_identity_len,
    server_public_key,
    ke2_raw,
    context,
    context_len,
) => {
    const ptr_ke3_raw = mput(ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    const ptr_session_key = mput(session_key, 64);
    const ptr_state_raw = mput(state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    const ptr_client_identity = mput(client_identity, client_identity_len);
    const ptr_client_private_key = mput(client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    const ptr_server_identity = mput(server_identity, server_identity_len);
    const ptr_server_public_key = mput(server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_ke2_raw = mput(ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    const ptr_context = mput(context, context_len);
    const fun_ret = _ecc_opaque_ristretto255_sha512_3DH_ClientFinalize(
        ptr_ke3_raw,
        ptr_session_key,
        ptr_state_raw,
        ptr_client_identity,
        client_identity_len,
        ptr_client_private_key,
        ptr_server_identity,
        server_identity_len,
        ptr_server_public_key,
        ptr_ke2_raw,
        ptr_context,
        context_len,
    );
    mget(ke3_raw, ptr_ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    mget(session_key, ptr_session_key, 64);
    mget(state_raw, ptr_state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    mfree(ptr_session_key, 64);
    mfree(ptr_state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mfree(ptr_context, context_len);
    return fun_ret;
}

/**
 *
 *
 * @param {Uint8Array} ke2_raw (output) a KE2 structure, size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param {Uint8Array} state_raw (input, output) a ServerState structure, size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
 * @param {Uint8Array} server_identity the optional encoded server identity, which is set to
 * server_public_key if null, size:server_identity_len
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} server_private_key the server's private key, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param {Uint8Array} server_public_key the server's public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} record_raw the client's RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE
 * @param {Uint8Array} credential_identifier an identifier that uniquely represents the credential
 * being registered, size:credential_identifier_len
 * @param {number} credential_identifier_len the length of `credential_identifier`
 * @param {Uint8Array} oprf_seed the server-side seed of Nh bytes used to generate an oprf_key, size:ecc_opaque_ristretto255_sha512_Nh
 * @param {Uint8Array} ke1_raw a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param {Uint8Array} client_identity the optional encoded server identity, which is set to
 * client_public_key if null, size:client_identity_len
 * @param {number} client_identity_len the length of `client_identity`
 * @param {Uint8Array} context the application specific context, size:context_len
 * @param {number} context_len the length of `context`
 * @param {Uint8Array} masking_nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param {Uint8Array} server_nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param {Uint8Array} server_secret size:ecc_opaque_ristretto255_sha512_Nsk
 * @param {Uint8Array} server_keyshare size:ecc_opaque_ristretto255_sha512_Npk
 */
Module.ecc_opaque_ristretto255_sha512_ServerInitWithSecrets = (
    ke2_raw,
    state_raw,
    server_identity,
    server_identity_len,
    server_private_key,
    server_public_key,
    record_raw,
    credential_identifier,
    credential_identifier_len,
    oprf_seed,
    ke1_raw,
    client_identity,
    client_identity_len,
    context,
    context_len,
    masking_nonce,
    server_nonce,
    server_secret,
    server_keyshare,
) => {
    const ptr_ke2_raw = mput(ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    const ptr_state_raw = mput(state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    const ptr_server_identity = mput(server_identity, server_identity_len);
    const ptr_server_private_key = mput(server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    const ptr_server_public_key = mput(server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_record_raw = mput(record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    const ptr_credential_identifier = mput(credential_identifier, credential_identifier_len);
    const ptr_oprf_seed = mput(oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    const ptr_ke1_raw = mput(ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    const ptr_client_identity = mput(client_identity, client_identity_len);
    const ptr_context = mput(context, context_len);
    const ptr_masking_nonce = mput(masking_nonce, ecc_opaque_ristretto255_sha512_Nn);
    const ptr_server_nonce = mput(server_nonce, ecc_opaque_ristretto255_sha512_Nn);
    const ptr_server_secret = mput(server_secret, ecc_opaque_ristretto255_sha512_Nsk);
    const ptr_server_keyshare = mput(server_keyshare, ecc_opaque_ristretto255_sha512_Npk);
    _ecc_opaque_ristretto255_sha512_ServerInitWithSecrets(
        ptr_ke2_raw,
        ptr_state_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_server_private_key,
        ptr_server_public_key,
        ptr_record_raw,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed,
        ptr_ke1_raw,
        ptr_client_identity,
        client_identity_len,
        ptr_context,
        context_len,
        ptr_masking_nonce,
        ptr_server_nonce,
        ptr_server_secret,
        ptr_server_keyshare,
    );
    mget(ke2_raw, ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mget(state_raw, ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mfree(ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    mfree(ptr_credential_identifier, credential_identifier_len);
    mfree(ptr_oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_context, context_len);
    mfree(ptr_masking_nonce, ecc_opaque_ristretto255_sha512_Nn);
    mfree(ptr_server_nonce, ecc_opaque_ristretto255_sha512_Nn);
    mfree(ptr_server_secret, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_keyshare, ecc_opaque_ristretto255_sha512_Npk);
}

/**
 *
 *
 * @param {Uint8Array} ke2_raw (output) a KE2 structure, size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param {Uint8Array} state_raw (input, output) a ServerState structure, size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
 * @param {Uint8Array} server_identity the optional encoded server identity, which is set to
 * server_public_key if null, size:server_identity_len
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} server_private_key the server's private key, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param {Uint8Array} server_public_key the server's public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} record_raw the client's RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE
 * @param {Uint8Array} credential_identifier an identifier that uniquely represents the credential
 * being registered, size:credential_identifier_len
 * @param {number} credential_identifier_len the length of `credential_identifier`
 * @param {Uint8Array} oprf_seed the server-side seed of Nh bytes used to generate an oprf_key, size:ecc_opaque_ristretto255_sha512_Nh
 * @param {Uint8Array} ke1_raw a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param {Uint8Array} client_identity the optional encoded server identity, which is set to
 * client_public_key if null, size:client_identity_len
 * @param {number} client_identity_len the length of `client_identity`
 * @param {Uint8Array} context the application specific context, size:context_len
 * @param {number} context_len the length of `context`
 */
Module.ecc_opaque_ristretto255_sha512_ServerInit = (
    ke2_raw,
    state_raw,
    server_identity,
    server_identity_len,
    server_private_key,
    server_public_key,
    record_raw,
    credential_identifier,
    credential_identifier_len,
    oprf_seed,
    ke1_raw,
    client_identity,
    client_identity_len,
    context,
    context_len,
) => {
    const ptr_ke2_raw = mput(ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    const ptr_state_raw = mput(state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    const ptr_server_identity = mput(server_identity, server_identity_len);
    const ptr_server_private_key = mput(server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    const ptr_server_public_key = mput(server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_record_raw = mput(record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    const ptr_credential_identifier = mput(credential_identifier, credential_identifier_len);
    const ptr_oprf_seed = mput(oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    const ptr_ke1_raw = mput(ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    const ptr_client_identity = mput(client_identity, client_identity_len);
    const ptr_context = mput(context, context_len);
    _ecc_opaque_ristretto255_sha512_ServerInit(
        ptr_ke2_raw,
        ptr_state_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_server_private_key,
        ptr_server_public_key,
        ptr_record_raw,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed,
        ptr_ke1_raw,
        ptr_client_identity,
        client_identity_len,
        ptr_context,
        context_len,
    );
    mget(ke2_raw, ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mget(state_raw, ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mfree(ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    mfree(ptr_credential_identifier, credential_identifier_len);
    mfree(ptr_oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_context, context_len);
}

/**
 *
 *
 * @param {Uint8Array} session_key (output) the shared session secret if and only if KE3 is valid, size:64
 * @param {Uint8Array} state (input, output) a ServerState structure, size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
 * @param {Uint8Array} ke3 a KE3 structure, size:ecc_opaque_ristretto255_sha512_KE3SIZE
 * @return {number} 0 if the user was authenticated, else -1
 */
Module.ecc_opaque_ristretto255_sha512_ServerFinish = (
    session_key,
    state,
    ke3,
) => {
    const ptr_session_key = mput(session_key, 64);
    const ptr_state = mput(state, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    const ptr_ke3 = mput(ke3, ecc_opaque_ristretto255_sha512_KE3SIZE);
    const fun_ret = _ecc_opaque_ristretto255_sha512_ServerFinish(
        ptr_session_key,
        ptr_state,
        ptr_ke3,
    );
    mget(session_key, ptr_session_key, 64);
    mget(state, ptr_state, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_session_key, 64);
    mfree(ptr_state, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_ke3, ecc_opaque_ristretto255_sha512_KE3SIZE);
    return fun_ret;
}

/**
 *
 *
 * @param {Uint8Array} ke2_raw (output) size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param {Uint8Array} state_raw (input, output) size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
 * @param {Uint8Array} server_identity size:server_identity_len
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} server_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param {Uint8Array} server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} client_identity size:client_identity_len
 * @param {number} client_identity_len the length of `client_identity`
 * @param {Uint8Array} client_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} ke1_raw size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param {Uint8Array} credential_response_raw size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
 * @param {Uint8Array} context size:context_len
 * @param {number} context_len the length of `context`
 * @param {Uint8Array} server_nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param {Uint8Array} server_secret size:ecc_opaque_ristretto255_sha512_Nsk
 * @param {Uint8Array} server_keyshare size:ecc_opaque_ristretto255_sha512_Npk
 */
Module.ecc_opaque_ristretto255_sha512_3DH_ResponseWithSecrets = (
    ke2_raw,
    state_raw,
    server_identity,
    server_identity_len,
    server_private_key,
    server_public_key,
    client_identity,
    client_identity_len,
    client_public_key,
    ke1_raw,
    credential_response_raw,
    context,
    context_len,
    server_nonce,
    server_secret,
    server_keyshare,
) => {
    const ptr_ke2_raw = mput(ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    const ptr_state_raw = mput(state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    const ptr_server_identity = mput(server_identity, server_identity_len);
    const ptr_server_private_key = mput(server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    const ptr_server_public_key = mput(server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_client_identity = mput(client_identity, client_identity_len);
    const ptr_client_public_key = mput(client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_ke1_raw = mput(ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    const ptr_credential_response_raw = mput(credential_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    const ptr_context = mput(context, context_len);
    const ptr_server_nonce = mput(server_nonce, ecc_opaque_ristretto255_sha512_Nn);
    const ptr_server_secret = mput(server_secret, ecc_opaque_ristretto255_sha512_Nsk);
    const ptr_server_keyshare = mput(server_keyshare, ecc_opaque_ristretto255_sha512_Npk);
    _ecc_opaque_ristretto255_sha512_3DH_ResponseWithSecrets(
        ptr_ke2_raw,
        ptr_state_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_server_private_key,
        ptr_server_public_key,
        ptr_client_identity,
        client_identity_len,
        ptr_client_public_key,
        ptr_ke1_raw,
        ptr_credential_response_raw,
        ptr_context,
        context_len,
        ptr_server_nonce,
        ptr_server_secret,
        ptr_server_keyshare,
    );
    mget(ke2_raw, ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mget(state_raw, ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mfree(ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_credential_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_context, context_len);
    mfree(ptr_server_nonce, ecc_opaque_ristretto255_sha512_Nn);
    mfree(ptr_server_secret, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_keyshare, ecc_opaque_ristretto255_sha512_Npk);
}

/**
 *
 *
 * @param {Uint8Array} ke2_raw (output) size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param {Uint8Array} state_raw (input, output) size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
 * @param {Uint8Array} server_identity size:server_identity_len
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} server_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param {Uint8Array} server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} client_identity size:client_identity_len
 * @param {number} client_identity_len the length of `client_identity`
 * @param {Uint8Array} client_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param {Uint8Array} ke1_raw size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param {Uint8Array} credential_response_raw size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
 * @param {Uint8Array} context size:context_len
 * @param {number} context_len the length of `context`
 */
Module.ecc_opaque_ristretto255_sha512_3DH_Response = (
    ke2_raw,
    state_raw,
    server_identity,
    server_identity_len,
    server_private_key,
    server_public_key,
    client_identity,
    client_identity_len,
    client_public_key,
    ke1_raw,
    credential_response_raw,
    context,
    context_len,
) => {
    const ptr_ke2_raw = mput(ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    const ptr_state_raw = mput(state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    const ptr_server_identity = mput(server_identity, server_identity_len);
    const ptr_server_private_key = mput(server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    const ptr_server_public_key = mput(server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_client_identity = mput(client_identity, client_identity_len);
    const ptr_client_public_key = mput(client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    const ptr_ke1_raw = mput(ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    const ptr_credential_response_raw = mput(credential_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    const ptr_context = mput(context, context_len);
    _ecc_opaque_ristretto255_sha512_3DH_Response(
        ptr_ke2_raw,
        ptr_state_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_server_private_key,
        ptr_server_public_key,
        ptr_client_identity,
        client_identity_len,
        ptr_client_public_key,
        ptr_ke1_raw,
        ptr_credential_response_raw,
        ptr_context,
        context_len,
    );
    mget(ke2_raw, ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mget(state_raw, ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mfree(ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_credential_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_context, context_len);
}

// sign

const ecc_sign_ed25519_SIGNATURESIZE = 64;
/**
 * Signature size.
 *
 * @type {number}
 */
Module.ecc_sign_ed25519_SIGNATURESIZE = ecc_sign_ed25519_SIGNATURESIZE;

const ecc_sign_ed25519_SEEDSIZE = 32;
/**
 * Seed size.
 *
 * @type {number}
 */
Module.ecc_sign_ed25519_SEEDSIZE = ecc_sign_ed25519_SEEDSIZE;

const ecc_sign_ed25519_PUBLICKEYSIZE = 32;
/**
 * Public key size.
 *
 * @type {number}
 */
Module.ecc_sign_ed25519_PUBLICKEYSIZE = ecc_sign_ed25519_PUBLICKEYSIZE;

const ecc_sign_ed25519_SECRETKEYSIZE = 64;
/**
 * Secret key size.
 *
 * @type {number}
 */
Module.ecc_sign_ed25519_SECRETKEYSIZE = ecc_sign_ed25519_SECRETKEYSIZE;

const ecc_sign_eth_bls_PRIVATEKEYSIZE = 32;
/**
 * Size of the signing private key (size of a scalar in BLS12-381).
 *
 * @type {number}
 */
Module.ecc_sign_eth_bls_PRIVATEKEYSIZE = ecc_sign_eth_bls_PRIVATEKEYSIZE;

const ecc_sign_eth_bls_PUBLICKEYSIZE = 48;
/**
 * Size of the signing public key (size of a compressed G1 element in BLS12-381).
 *
 * @type {number}
 */
Module.ecc_sign_eth_bls_PUBLICKEYSIZE = ecc_sign_eth_bls_PUBLICKEYSIZE;

const ecc_sign_eth_bls_SIGNATURESIZE = 96;
/**
 * Signature size (size of a compressed G2 element in BLS12-381).
 *
 * @type {number}
 */
Module.ecc_sign_eth_bls_SIGNATURESIZE = ecc_sign_eth_bls_SIGNATURESIZE;

/**
 * Signs the `message` whose length is `message_len` in bytes, using the
 * secret key `sk`, and puts the signature into `signature`.
 *
 * @param {Uint8Array} signature (output) the signature, size:ecc_sign_ed25519_SIGNATURESIZE
 * @param {Uint8Array} message input message, size:message_len
 * @param {number} message_len the length of `message`
 * @param {Uint8Array} sk the secret key, size:ecc_sign_ed25519_SECRETKEYSIZE
 */
Module.ecc_sign_ed25519_Sign = (
    signature,
    message,
    message_len,
    sk,
) => {
    const ptr_signature = mput(signature, ecc_sign_ed25519_SIGNATURESIZE);
    const ptr_message = mput(message, message_len);
    const ptr_sk = mput(sk, ecc_sign_ed25519_SECRETKEYSIZE);
    _ecc_sign_ed25519_Sign(
        ptr_signature,
        ptr_message,
        message_len,
        ptr_sk,
    );
    mget(signature, ptr_signature, ecc_sign_ed25519_SIGNATURESIZE);
    mfree(ptr_signature, ecc_sign_ed25519_SIGNATURESIZE);
    mfree(ptr_message, message_len);
    mfree(ptr_sk, ecc_sign_ed25519_SECRETKEYSIZE);
}

/**
 * Verifies that `signature` is a valid signature for the `message` whose length
 * is `message_len` in bytes, using the signer's public key `pk`.
 *
 * @param {Uint8Array} signature the signature, size:ecc_sign_ed25519_SIGNATURESIZE
 * @param {Uint8Array} message input message, size:message_len
 * @param {number} message_len the length of `message`
 * @param {Uint8Array} pk the public key, size:ecc_sign_ed25519_PUBLICKEYSIZE
 * @return {number} -1 if the signature fails verification, or 0 on success
 */
Module.ecc_sign_ed25519_Verify = (
    signature,
    message,
    message_len,
    pk,
) => {
    const ptr_signature = mput(signature, ecc_sign_ed25519_SIGNATURESIZE);
    const ptr_message = mput(message, message_len);
    const ptr_pk = mput(pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    const fun_ret = _ecc_sign_ed25519_Verify(
        ptr_signature,
        ptr_message,
        message_len,
        ptr_pk,
    );
    mfree(ptr_signature, ecc_sign_ed25519_SIGNATURESIZE);
    mfree(ptr_message, message_len);
    mfree(ptr_pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    return fun_ret;
}

/**
 * Generates a random key pair of public and private keys.
 *
 * @param {Uint8Array} pk (output) public key, size:ecc_sign_ed25519_PUBLICKEYSIZE
 * @param {Uint8Array} sk (output) private key, size:ecc_sign_ed25519_SECRETKEYSIZE
 */
Module.ecc_sign_ed25519_KeyPair = (
    pk,
    sk,
) => {
    const ptr_pk = mput(pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    const ptr_sk = mput(sk, ecc_sign_ed25519_SECRETKEYSIZE);
    _ecc_sign_ed25519_KeyPair(
        ptr_pk,
        ptr_sk,
    );
    mget(pk, ptr_pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    mget(sk, ptr_sk, ecc_sign_ed25519_SECRETKEYSIZE);
    mfree(ptr_pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_sign_ed25519_SECRETKEYSIZE);
}

/**
 * Generates a random key pair of public and private keys derived
 * from a `seed`.
 *
 * @param {Uint8Array} pk (output) public key, size:ecc_sign_ed25519_PUBLICKEYSIZE
 * @param {Uint8Array} sk (output) private key, size:ecc_sign_ed25519_SECRETKEYSIZE
 * @param {Uint8Array} seed seed to generate the keys, size:ecc_sign_ed25519_SEEDSIZE
 */
Module.ecc_sign_ed25519_SeedKeyPair = (
    pk,
    sk,
    seed,
) => {
    const ptr_pk = mput(pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    const ptr_sk = mput(sk, ecc_sign_ed25519_SECRETKEYSIZE);
    const ptr_seed = mput(seed, ecc_sign_ed25519_SEEDSIZE);
    _ecc_sign_ed25519_SeedKeyPair(
        ptr_pk,
        ptr_sk,
        ptr_seed,
    );
    mget(pk, ptr_pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    mget(sk, ptr_sk, ecc_sign_ed25519_SECRETKEYSIZE);
    mfree(ptr_pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_sign_ed25519_SECRETKEYSIZE);
    mfree(ptr_seed, ecc_sign_ed25519_SEEDSIZE);
}

/**
 * Extracts the seed from the secret key `sk` and copies it into `seed`.
 *
 * @param {Uint8Array} seed (output) the seed used to generate the secret key, size:ecc_sign_ed25519_SEEDSIZE
 * @param {Uint8Array} sk the secret key, size:ecc_sign_ed25519_SECRETKEYSIZE
 */
Module.ecc_sign_ed25519_SkToSeed = (
    seed,
    sk,
) => {
    const ptr_seed = mput(seed, ecc_sign_ed25519_SEEDSIZE);
    const ptr_sk = mput(sk, ecc_sign_ed25519_SECRETKEYSIZE);
    _ecc_sign_ed25519_SkToSeed(
        ptr_seed,
        ptr_sk,
    );
    mget(seed, ptr_seed, ecc_sign_ed25519_SEEDSIZE);
    mfree(ptr_seed, ecc_sign_ed25519_SEEDSIZE);
    mfree(ptr_sk, ecc_sign_ed25519_SECRETKEYSIZE);
}

/**
 * Extracts the public key from the secret key `sk` and copies it into `pk`.
 *
 * @param {Uint8Array} pk (output) the public key, size:ecc_sign_ed25519_PUBLICKEYSIZE
 * @param {Uint8Array} sk the secret key, size:ecc_sign_ed25519_SECRETKEYSIZE
 */
Module.ecc_sign_ed25519_SkToPk = (
    pk,
    sk,
) => {
    const ptr_pk = mput(pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    const ptr_sk = mput(sk, ecc_sign_ed25519_SECRETKEYSIZE);
    _ecc_sign_ed25519_SkToPk(
        ptr_pk,
        ptr_sk,
    );
    mget(pk, ptr_pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    mfree(ptr_pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_sign_ed25519_SECRETKEYSIZE);
}

/**
 * Generates a secret key `sk` deterministically from a secret
 * octet string `ikm`. The secret key is guaranteed to be nonzero.
 *
 * For security, `ikm` MUST be infeasible to guess, e.g., generated
 * by a trusted source of randomness and be at least 32 bytes long.
 *
 * @param {Uint8Array} sk (output) a secret key, size:ecc_sign_eth_bls_PRIVATEKEYSIZE
 * @param {Uint8Array} ikm a secret octet string, size:ikm_len
 * @param {number} ikm_len the length of `ikm`
 */
Module.ecc_sign_eth_bls_KeyGen = (
    sk,
    ikm,
    ikm_len,
) => {
    const ptr_sk = mput(sk, ecc_sign_eth_bls_PRIVATEKEYSIZE);
    const ptr_ikm = mput(ikm, ikm_len);
    _ecc_sign_eth_bls_KeyGen(
        ptr_sk,
        ptr_ikm,
        ikm_len,
    );
    mget(sk, ptr_sk, ecc_sign_eth_bls_PRIVATEKEYSIZE);
    mfree(ptr_sk, ecc_sign_eth_bls_PRIVATEKEYSIZE);
    mfree(ptr_ikm, ikm_len);
}

/**
 * Takes a secret key `sk` and outputs the corresponding public key `pk`.
 *
 * @param {Uint8Array} pk (output) a public key, size:ecc_sign_eth_bls_PUBLICKEYSIZE
 * @param {Uint8Array} sk the secret key, size:ecc_sign_eth_bls_PRIVATEKEYSIZE
 */
Module.ecc_sign_eth_bls_SkToPk = (
    pk,
    sk,
) => {
    const ptr_pk = mput(pk, ecc_sign_eth_bls_PUBLICKEYSIZE);
    const ptr_sk = mput(sk, ecc_sign_eth_bls_PRIVATEKEYSIZE);
    _ecc_sign_eth_bls_SkToPk(
        ptr_pk,
        ptr_sk,
    );
    mget(pk, ptr_pk, ecc_sign_eth_bls_PUBLICKEYSIZE);
    mfree(ptr_pk, ecc_sign_eth_bls_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_sign_eth_bls_PRIVATEKEYSIZE);
}

/**
 * Ensures that a public key is valid.  In particular, it ensures
 * that a public key represents a valid, non-identity point that
 * is in the correct subgroup.
 *
 * @param {Uint8Array} pk a public key in the format output by SkToPk, size:ecc_sign_eth_bls_PUBLICKEYSIZE
 * @return {number} 0 for valid or -1 for invalid
 */
Module.ecc_sign_eth_bls_KeyValidate = (
    pk,
) => {
    const ptr_pk = mput(pk, ecc_sign_eth_bls_PUBLICKEYSIZE);
    const fun_ret = _ecc_sign_eth_bls_KeyValidate(
        ptr_pk,
    );
    mfree(ptr_pk, ecc_sign_eth_bls_PUBLICKEYSIZE);
    return fun_ret;
}

/**
 * Computes a signature from sk, a secret key, and a message message
 * and put the result in sig.
 *
 * @param {Uint8Array} signature (output) the signature, size:ecc_sign_eth_bls_SIGNATURESIZE
 * @param {Uint8Array} sk the secret key, size:ecc_sign_eth_bls_PRIVATEKEYSIZE
 * @param {Uint8Array} message input message, size:message_len
 * @param {number} message_len the length of `message`
 */
Module.ecc_sign_eth_bls_Sign = (
    signature,
    sk,
    message,
    message_len,
) => {
    const ptr_signature = mput(signature, ecc_sign_eth_bls_SIGNATURESIZE);
    const ptr_sk = mput(sk, ecc_sign_eth_bls_PRIVATEKEYSIZE);
    const ptr_message = mput(message, message_len);
    _ecc_sign_eth_bls_Sign(
        ptr_signature,
        ptr_sk,
        ptr_message,
        message_len,
    );
    mget(signature, ptr_signature, ecc_sign_eth_bls_SIGNATURESIZE);
    mfree(ptr_signature, ecc_sign_eth_bls_SIGNATURESIZE);
    mfree(ptr_sk, ecc_sign_eth_bls_PRIVATEKEYSIZE);
    mfree(ptr_message, message_len);
}

/**
 * Checks that a signature is valid for the message under the public key pk.
 *
 * @param {Uint8Array} pk the public key, size:ecc_sign_eth_bls_PUBLICKEYSIZE
 * @param {Uint8Array} message input message, size:message_len
 * @param {number} message_len the length of `message`
 * @param {Uint8Array} signature the signature, size:ecc_sign_eth_bls_SIGNATURESIZE
 * @return {number} 0 if valid, -1 if invalid
 */
Module.ecc_sign_eth_bls_Verify = (
    pk,
    message,
    message_len,
    signature,
) => {
    const ptr_pk = mput(pk, ecc_sign_eth_bls_PUBLICKEYSIZE);
    const ptr_message = mput(message, message_len);
    const ptr_signature = mput(signature, ecc_sign_eth_bls_SIGNATURESIZE);
    const fun_ret = _ecc_sign_eth_bls_Verify(
        ptr_pk,
        ptr_message,
        message_len,
        ptr_signature,
    );
    mfree(ptr_pk, ecc_sign_eth_bls_PUBLICKEYSIZE);
    mfree(ptr_message, message_len);
    mfree(ptr_signature, ecc_sign_eth_bls_SIGNATURESIZE);
    return fun_ret;
}

/**
 * Aggregates multiple signatures into one.
 *
 * @param {Uint8Array} signature (output) the aggregated signature that combines all inputs, size:ecc_sign_eth_bls_SIGNATURESIZE
 * @param {Uint8Array} signatures array of individual signatures, size:n*ecc_sign_eth_bls_SIGNATURESIZE
 * @param {number} n amount of signatures in the array `signatures`
 * @return {number} 0 if valid, -1 if invalid
 */
Module.ecc_sign_eth_bls_Aggregate = (
    signature,
    signatures,
    n,
) => {
    const ptr_signature = mput(signature, ecc_sign_eth_bls_SIGNATURESIZE);
    const ptr_signatures = mput(signatures, n*ecc_sign_eth_bls_SIGNATURESIZE);
    const fun_ret = _ecc_sign_eth_bls_Aggregate(
        ptr_signature,
        ptr_signatures,
        n,
    );
    mget(signature, ptr_signature, ecc_sign_eth_bls_SIGNATURESIZE);
    mfree(ptr_signature, ecc_sign_eth_bls_SIGNATURESIZE);
    mfree(ptr_signatures, n*ecc_sign_eth_bls_SIGNATURESIZE);
    return fun_ret;
}

/**
 *
 *
 * @param {Uint8Array} pks size:n*ecc_sign_eth_bls_PUBLICKEYSIZE
 * @param {number} n the number of public keys in `pks`
 * @param {Uint8Array} message size:message_len
 * @param {number} message_len the length of `message`
 * @param {Uint8Array} signature size:ecc_sign_eth_bls_SIGNATURESIZE
 * @return {number} 0 if valid, -1 if invalid
 */
Module.ecc_sign_eth_bls_FastAggregateVerify = (
    pks,
    n,
    message,
    message_len,
    signature,
) => {
    const ptr_pks = mput(pks, n*ecc_sign_eth_bls_PUBLICKEYSIZE);
    const ptr_message = mput(message, message_len);
    const ptr_signature = mput(signature, ecc_sign_eth_bls_SIGNATURESIZE);
    const fun_ret = _ecc_sign_eth_bls_FastAggregateVerify(
        ptr_pks,
        n,
        ptr_message,
        message_len,
        ptr_signature,
    );
    mfree(ptr_pks, n*ecc_sign_eth_bls_PUBLICKEYSIZE);
    mfree(ptr_message, message_len);
    mfree(ptr_signature, ecc_sign_eth_bls_SIGNATURESIZE);
    return fun_ret;
}

/**
 * Checks an aggregated signature over several (PK, message) pairs. The
 * messages are concatenated and in PASCAL-encoded form [size, chars].
 *
 * In order to keep the API simple, the maximum length of a message is 255.
 *
 * @param {number} n number of pairs
 * @param {Uint8Array} pks size:n*ecc_sign_eth_bls_PUBLICKEYSIZE
 * @param {Uint8Array} messages size:messages_len
 * @param {number} messages_len total length of the buffer `messages`
 * @param {Uint8Array} signature size:ecc_sign_eth_bls_SIGNATURESIZE
 * @return {number} 0 if valid, -1 if invalid
 */
Module.ecc_sign_eth_bls_AggregateVerify = (
    n,
    pks,
    messages,
    messages_len,
    signature,
) => {
    const ptr_pks = mput(pks, n*ecc_sign_eth_bls_PUBLICKEYSIZE);
    const ptr_messages = mput(messages, messages_len);
    const ptr_signature = mput(signature, ecc_sign_eth_bls_SIGNATURESIZE);
    const fun_ret = _ecc_sign_eth_bls_AggregateVerify(
        n,
        ptr_pks,
        ptr_messages,
        messages_len,
        ptr_signature,
    );
    mfree(ptr_pks, n*ecc_sign_eth_bls_PUBLICKEYSIZE);
    mfree(ptr_messages, messages_len);
    mfree(ptr_signature, ecc_sign_eth_bls_SIGNATURESIZE);
    return fun_ret;
}

// frost

const ecc_frost_ristretto255_sha512_SCALARSIZE = 32;
/**
 * Size of a scalar, since this is using the ristretto255
 * curve the size is 32 bytes.
 *
 * @type {number}
 */
Module.ecc_frost_ristretto255_sha512_SCALARSIZE = ecc_frost_ristretto255_sha512_SCALARSIZE;

const ecc_frost_ristretto255_sha512_ELEMENTSIZE = 32;
/**
 * Size of an element, since this is using the ristretto255
 * curve the size is 32 bytes.
 *
 * @type {number}
 */
Module.ecc_frost_ristretto255_sha512_ELEMENTSIZE = ecc_frost_ristretto255_sha512_ELEMENTSIZE;

const ecc_frost_ristretto255_sha512_POINTSIZE = 64;
/**
 * Size of a scalar point for polynomial evaluation (x, y).
 *
 * @type {number}
 */
Module.ecc_frost_ristretto255_sha512_POINTSIZE = ecc_frost_ristretto255_sha512_POINTSIZE;

const ecc_frost_ristretto255_sha512_COMMITMENTSIZE = 96;
/**
 *
 *
 * @type {number}
 */
Module.ecc_frost_ristretto255_sha512_COMMITMENTSIZE = ecc_frost_ristretto255_sha512_COMMITMENTSIZE;

const ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE = 64;
/**
 *
 *
 * @type {number}
 */
Module.ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE = ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE;

const ecc_frost_ristretto255_sha512_SECRETKEYSIZE = 32;
/**
 * Size of a private key, since this is using the ristretto255
 * curve the size is 32 bytes, the size of an scalar.
 *
 * @type {number}
 */
Module.ecc_frost_ristretto255_sha512_SECRETKEYSIZE = ecc_frost_ristretto255_sha512_SECRETKEYSIZE;

const ecc_frost_ristretto255_sha512_PUBLICKEYSIZE = 32;
/**
 * Size of a public key, since this is using the ristretto255
 * curve the size is 32 bytes, the size of a group element.
 *
 * @type {number}
 */
Module.ecc_frost_ristretto255_sha512_PUBLICKEYSIZE = ecc_frost_ristretto255_sha512_PUBLICKEYSIZE;

const ecc_frost_ristretto255_sha512_SIGNATURESIZE = 64;
/**
 * Size of a schnorr signature, a pair of a scalar and an element.
 *
 * @type {number}
 */
Module.ecc_frost_ristretto255_sha512_SIGNATURESIZE = ecc_frost_ristretto255_sha512_SIGNATURESIZE;

const ecc_frost_ristretto255_sha512_NONCEPAIRSIZE = 64;
/**
 * Size of a nonce tuple.
 *
 * @type {number}
 */
Module.ecc_frost_ristretto255_sha512_NONCEPAIRSIZE = ecc_frost_ristretto255_sha512_NONCEPAIRSIZE;

const ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE = 64;
/**
 * Size of a nonce commitment tuple.
 *
 * @type {number}
 */
Module.ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE = ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE;

/**
 *
 *
 * @param {Uint8Array} nonce (output) size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} secret size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} random_bytes size:32
 */
Module.ecc_frost_ristretto255_sha512_nonce_generate_with_randomness = (
    nonce,
    secret,
    random_bytes,
) => {
    const ptr_nonce = mput(nonce, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_secret = mput(secret, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_random_bytes = mput(random_bytes, 32);
    _ecc_frost_ristretto255_sha512_nonce_generate_with_randomness(
        ptr_nonce,
        ptr_secret,
        ptr_random_bytes,
    );
    mget(nonce, ptr_nonce, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_nonce, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_secret, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_random_bytes, 32);
}

/**
 *
 *
 * @param {Uint8Array} nonce (output) size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} secret size:ecc_frost_ristretto255_sha512_SCALARSIZE
 */
Module.ecc_frost_ristretto255_sha512_nonce_generate = (
    nonce,
    secret,
) => {
    const ptr_nonce = mput(nonce, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_secret = mput(secret, ecc_frost_ristretto255_sha512_SCALARSIZE);
    _ecc_frost_ristretto255_sha512_nonce_generate(
        ptr_nonce,
        ptr_secret,
    );
    mget(nonce, ptr_nonce, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_nonce, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_secret, ecc_frost_ristretto255_sha512_SCALARSIZE);
}

/**
 * Lagrange coefficients are used in FROST to evaluate a polynomial f at f(0),
 * given a set of t other points, where f is represented as a set of coefficients.
 *
 * @param {Uint8Array} L_i (output) the i-th Lagrange coefficient, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} x_i an x-coordinate contained in L, a scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} L the set of x-coordinates, each a scalar, size:L_len*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {number} L_len the number of x-coordinates in `L`
 */
Module.ecc_frost_ristretto255_sha512_derive_interpolating_value = (
    L_i,
    x_i,
    L,
    L_len,
) => {
    const ptr_L_i = mput(L_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_x_i = mput(x_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_L = mput(L, L_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
    _ecc_frost_ristretto255_sha512_derive_interpolating_value(
        ptr_L_i,
        ptr_x_i,
        ptr_L,
        L_len,
    );
    mget(L_i, ptr_L_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_L_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_x_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_L, L_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
}

/**
 * This is an optimization that works like `ecc_frost_ristretto255_sha512_derive_interpolating_value`
 * but with a set of points (x, y).
 *
 * @param {Uint8Array} L_i (output) the i-th Lagrange coefficient, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} x_i an x-coordinate contained in L, a scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} L the set of (x, y)-points, size:L_len*ecc_frost_ristretto255_sha512_POINTSIZE
 * @param {number} L_len the number of (x, y)-points in `L`
 */
Module.ecc_frost_ristretto255_sha512_derive_interpolating_value_with_points = (
    L_i,
    x_i,
    L,
    L_len,
) => {
    const ptr_L_i = mput(L_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_x_i = mput(x_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_L = mput(L, L_len*ecc_frost_ristretto255_sha512_POINTSIZE);
    _ecc_frost_ristretto255_sha512_derive_interpolating_value_with_points(
        ptr_L_i,
        ptr_x_i,
        ptr_L,
        L_len,
    );
    mget(L_i, ptr_L_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_L_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_x_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_L, L_len*ecc_frost_ristretto255_sha512_POINTSIZE);
}

/**
 * Encodes a list of participant commitments into a bytestring for use in the
 * FROST protocol.
 *
 * @param {Uint8Array} out (output) size:commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE
 * @param {Uint8Array} commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE
 * @param {number} commitment_list_len the number of elements in `commitment_list`
 */
Module.ecc_frost_ristretto255_sha512_encode_group_commitment_list = (
    out,
    commitment_list,
    commitment_list_len,
) => {
    const ptr_out = mput(out, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    const ptr_commitment_list = mput(commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    _ecc_frost_ristretto255_sha512_encode_group_commitment_list(
        ptr_out,
        ptr_commitment_list,
        commitment_list_len,
    );
    mget(out, ptr_out, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    mfree(ptr_out, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    mfree(ptr_commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
}

/**
 * Extracts participant identifiers from a commitment list.
 *
 * @param {Uint8Array} identifiers (output) size:commitment_list_len*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE
 * @param {number} commitment_list_len the number of elements in `commitment_list`
 */
Module.ecc_frost_ristretto255_sha512_participants_from_commitment_list = (
    identifiers,
    commitment_list,
    commitment_list_len,
) => {
    const ptr_identifiers = mput(identifiers, commitment_list_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_commitment_list = mput(commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    _ecc_frost_ristretto255_sha512_participants_from_commitment_list(
        ptr_identifiers,
        ptr_commitment_list,
        commitment_list_len,
    );
    mget(identifiers, ptr_identifiers, commitment_list_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_identifiers, commitment_list_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
}

/**
 * Extracts a binding factor from a list of binding factors.
 *
 * @param {Uint8Array} binding_factor (output) size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} binding_factor_list a list of binding factors for each participant, MUST be sorted in ascending order by signer index, size:binding_factor_list_len*ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE
 * @param {number} binding_factor_list_len the number of elements in `binding_factor_list`
 * @param {Uint8Array} identifier participant identifier, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @return {number} 0 on success, or -1 if the designated participant is not known
 */
Module.ecc_frost_ristretto255_sha512_binding_factor_for_participant = (
    binding_factor,
    binding_factor_list,
    binding_factor_list_len,
    identifier,
) => {
    const ptr_binding_factor = mput(binding_factor, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_binding_factor_list = mput(binding_factor_list, binding_factor_list_len*ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE);
    const ptr_identifier = mput(identifier, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const fun_ret = _ecc_frost_ristretto255_sha512_binding_factor_for_participant(
        ptr_binding_factor,
        ptr_binding_factor_list,
        binding_factor_list_len,
        ptr_identifier,
    );
    mget(binding_factor, ptr_binding_factor, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_binding_factor, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_binding_factor_list, binding_factor_list_len*ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE);
    mfree(ptr_identifier, ecc_frost_ristretto255_sha512_SCALARSIZE);
    return fun_ret;
}

/**
 * Compute binding factors based on the participant commitment list and message
 * to be signed.
 *
 * @param {Uint8Array} binding_factor_list (output) list of binding factors (identifier, Scalar) tuples representing the binding factors, size:commitment_list_len*ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE
 * @param {Uint8Array} commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE
 * @param {number} commitment_list_len the number of elements in `commitment_list`
 * @param {Uint8Array} msg the message to be signed, size:msg_len
 * @param {number} msg_len the length of `msg`
 */
Module.ecc_frost_ristretto255_sha512_compute_binding_factors = (
    binding_factor_list,
    commitment_list,
    commitment_list_len,
    msg,
    msg_len,
) => {
    const ptr_binding_factor_list = mput(binding_factor_list, commitment_list_len*ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE);
    const ptr_commitment_list = mput(commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    const ptr_msg = mput(msg, msg_len);
    _ecc_frost_ristretto255_sha512_compute_binding_factors(
        ptr_binding_factor_list,
        ptr_commitment_list,
        commitment_list_len,
        ptr_msg,
        msg_len,
    );
    mget(binding_factor_list, ptr_binding_factor_list, commitment_list_len*ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE);
    mfree(ptr_binding_factor_list, commitment_list_len*ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE);
    mfree(ptr_commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    mfree(ptr_msg, msg_len);
}

/**
 * Create the group commitment from a commitment list.
 *
 * @param {Uint8Array} group_comm (output) size:ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE
 * @param {number} commitment_list_len the number of elements in `commitment_list`
 * @param {Uint8Array} binding_factor_list size:ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE
 * @param {number} binding_factor_list_len the number of elements in `binding_factor_list`
 */
Module.ecc_frost_ristretto255_sha512_compute_group_commitment = (
    group_comm,
    commitment_list,
    commitment_list_len,
    binding_factor_list,
    binding_factor_list_len,
) => {
    const ptr_group_comm = mput(group_comm, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    const ptr_commitment_list = mput(commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    const ptr_binding_factor_list = mput(binding_factor_list, ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE);
    _ecc_frost_ristretto255_sha512_compute_group_commitment(
        ptr_group_comm,
        ptr_commitment_list,
        commitment_list_len,
        ptr_binding_factor_list,
        binding_factor_list_len,
    );
    mget(group_comm, ptr_group_comm, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_group_comm, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    mfree(ptr_binding_factor_list, ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE);
}

/**
 * Create the per-message challenge.
 *
 * @param {Uint8Array} challenge (output) a challenge Scalar value, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} group_commitment an Element representing the group commitment, size:ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} group_public_key public key corresponding to the signer secret key share, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param {Uint8Array} msg the message to be signed (sent by the Coordinator), size:msg_len
 * @param {number} msg_len the length of `msg`
 */
Module.ecc_frost_ristretto255_sha512_compute_challenge = (
    challenge,
    group_commitment,
    group_public_key,
    msg,
    msg_len,
) => {
    const ptr_challenge = mput(challenge, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_group_commitment = mput(group_commitment, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    const ptr_group_public_key = mput(group_public_key, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    const ptr_msg = mput(msg, msg_len);
    _ecc_frost_ristretto255_sha512_compute_challenge(
        ptr_challenge,
        ptr_group_commitment,
        ptr_group_public_key,
        ptr_msg,
        msg_len,
    );
    mget(challenge, ptr_challenge, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_challenge, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_group_commitment, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_group_public_key, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    mfree(ptr_msg, msg_len);
}

/**
 *
 *
 * @param {Uint8Array} nonce (output) a nonce pair, size:ecc_frost_ristretto255_sha512_NONCEPAIRSIZE
 * @param {Uint8Array} comm (output) a nonce commitment pair, size:ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE
 * @param {Uint8Array} sk_i the secret key share, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} hiding_nonce_randomness size:32
 * @param {Uint8Array} binding_nonce_randomness size:32
 */
Module.ecc_frost_ristretto255_sha512_commit_with_randomness = (
    nonce,
    comm,
    sk_i,
    hiding_nonce_randomness,
    binding_nonce_randomness,
) => {
    const ptr_nonce = mput(nonce, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    const ptr_comm = mput(comm, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    const ptr_sk_i = mput(sk_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_hiding_nonce_randomness = mput(hiding_nonce_randomness, 32);
    const ptr_binding_nonce_randomness = mput(binding_nonce_randomness, 32);
    _ecc_frost_ristretto255_sha512_commit_with_randomness(
        ptr_nonce,
        ptr_comm,
        ptr_sk_i,
        ptr_hiding_nonce_randomness,
        ptr_binding_nonce_randomness,
    );
    mget(nonce, ptr_nonce, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    mget(comm, ptr_comm, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    mfree(ptr_nonce, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    mfree(ptr_comm, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    mfree(ptr_sk_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_hiding_nonce_randomness, 32);
    mfree(ptr_binding_nonce_randomness, 32);
}

/**
 *
 *
 * @param {Uint8Array} nonce (output) a nonce pair, size:ecc_frost_ristretto255_sha512_NONCEPAIRSIZE
 * @param {Uint8Array} comm (output) a nonce commitment pair, size:ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE
 * @param {Uint8Array} sk_i the secret key share, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 */
Module.ecc_frost_ristretto255_sha512_commit = (
    nonce,
    comm,
    sk_i,
) => {
    const ptr_nonce = mput(nonce, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    const ptr_comm = mput(comm, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    const ptr_sk_i = mput(sk_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    _ecc_frost_ristretto255_sha512_commit(
        ptr_nonce,
        ptr_comm,
        ptr_sk_i,
    );
    mget(nonce, ptr_nonce, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    mget(comm, ptr_comm, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    mfree(ptr_nonce, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    mfree(ptr_comm, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    mfree(ptr_sk_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
}

/**
 * To produce a signature share.
 *
 * @param {Uint8Array} sig_share (output) signature share, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} identifier identifier of the signer. Note identifier will never equal 0, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} sk_i signer secret key share, size:ecc_frost_ristretto255_sha512_SECRETKEYSIZE
 * @param {Uint8Array} group_public_key public key corresponding to the signer secret key share, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param {Uint8Array} nonce_i pair of scalar values generated in round one, size:ecc_frost_ristretto255_sha512_NONCEPAIRSIZE
 * @param {Uint8Array} msg the message to be signed (sent by the Coordinator), size:msg_len
 * @param {number} msg_len the length of `msg`
 * @param {Uint8Array} commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE
 * @param {number} commitment_list_len the number of elements in `commitment_list`
 */
Module.ecc_frost_ristretto255_sha512_sign = (
    sig_share,
    identifier,
    sk_i,
    group_public_key,
    nonce_i,
    msg,
    msg_len,
    commitment_list,
    commitment_list_len,
) => {
    const ptr_sig_share = mput(sig_share, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_identifier = mput(identifier, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_sk_i = mput(sk_i, ecc_frost_ristretto255_sha512_SECRETKEYSIZE);
    const ptr_group_public_key = mput(group_public_key, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    const ptr_nonce_i = mput(nonce_i, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    const ptr_msg = mput(msg, msg_len);
    const ptr_commitment_list = mput(commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    _ecc_frost_ristretto255_sha512_sign(
        ptr_sig_share,
        ptr_identifier,
        ptr_sk_i,
        ptr_group_public_key,
        ptr_nonce_i,
        ptr_msg,
        msg_len,
        ptr_commitment_list,
        commitment_list_len,
    );
    mget(sig_share, ptr_sig_share, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_sig_share, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_identifier, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_sk_i, ecc_frost_ristretto255_sha512_SECRETKEYSIZE);
    mfree(ptr_group_public_key, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    mfree(ptr_nonce_i, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    mfree(ptr_msg, msg_len);
    mfree(ptr_commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
}

/**
 * Performs the aggregate operation to obtain the resulting signature.
 *
 * @param {Uint8Array} signature (output) a Schnorr signature consisting of an Element and Scalar value, size:ecc_frost_ristretto255_sha512_SIGNATURESIZE
 * @param {Uint8Array} commitment_list the group commitment returned by compute_group_commitment, size:commitment_list_len*ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param {number} commitment_list_len the group commitment returned by compute_group_commitment, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param {Uint8Array} msg the message to be signed (sent by the Coordinator), size:msg_len
 * @param {number} msg_len the length of `msg`
 * @param {Uint8Array} sig_shares a set of signature shares z_i for each signer, size:sig_shares_len*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {number} sig_shares_len the number of elements in `sig_shares`, must satisfy THRESHOLD_LIMIT
 * <
 * = sig_shares_len
 * <
 * = MAX_SIGNERS
 */
Module.ecc_frost_ristretto255_sha512_aggregate = (
    signature,
    commitment_list,
    commitment_list_len,
    msg,
    msg_len,
    sig_shares,
    sig_shares_len,
) => {
    const ptr_signature = mput(signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    const ptr_commitment_list = mput(commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    const ptr_msg = mput(msg, msg_len);
    const ptr_sig_shares = mput(sig_shares, sig_shares_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
    _ecc_frost_ristretto255_sha512_aggregate(
        ptr_signature,
        ptr_commitment_list,
        commitment_list_len,
        ptr_msg,
        msg_len,
        ptr_sig_shares,
        sig_shares_len,
    );
    mget(signature, ptr_signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    mfree(ptr_signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    mfree(ptr_commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    mfree(ptr_msg, msg_len);
    mfree(ptr_sig_shares, sig_shares_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
}

/**
 * Check that the signature share is valid.
 *
 * @param {Uint8Array} identifier identifier of the signer. Note identifier will never equal 0, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} public_key_share_i the public key for the ith signer, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param {Uint8Array} comm_i pair of Element values (hiding_nonce_commitment, binding_nonce_commitment) generated in round one from the ith signer, size:ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE
 * @param {Uint8Array} sig_share_i a Scalar value indicating the signature share as produced in round two from the ith signer, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE
 * @param {number} commitment_list_len the number of elements in `commitment_list`
 * @param {Uint8Array} group_public_key the public key for the group, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param {Uint8Array} msg the message to be signed (sent by the Coordinator), size:msg_len
 * @param {number} msg_len the length of `msg`
 * @return {number} 1 if the signature share is valid, and 0 otherwise.
 */
Module.ecc_frost_ristretto255_sha512_verify_signature_share = (
    identifier,
    public_key_share_i,
    comm_i,
    sig_share_i,
    commitment_list,
    commitment_list_len,
    group_public_key,
    msg,
    msg_len,
) => {
    const ptr_identifier = mput(identifier, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_public_key_share_i = mput(public_key_share_i, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    const ptr_comm_i = mput(comm_i, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    const ptr_sig_share_i = mput(sig_share_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_commitment_list = mput(commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    const ptr_group_public_key = mput(group_public_key, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    const ptr_msg = mput(msg, msg_len);
    const fun_ret = _ecc_frost_ristretto255_sha512_verify_signature_share(
        ptr_identifier,
        ptr_public_key_share_i,
        ptr_comm_i,
        ptr_sig_share_i,
        ptr_commitment_list,
        commitment_list_len,
        ptr_group_public_key,
        ptr_msg,
        msg_len,
    );
    mfree(ptr_identifier, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_public_key_share_i, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    mfree(ptr_comm_i, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    mfree(ptr_sig_share_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    mfree(ptr_group_public_key, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    mfree(ptr_msg, msg_len);
    return fun_ret;
}

/**
 * Map arbitrary inputs to non-zero Scalar elements of the prime-order group scalar field.
 *
 * @param {Uint8Array} h1 (output) size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} m size:m_len
 * @param {number} m_len the length of `m`
 */
Module.ecc_frost_ristretto255_sha512_H1 = (
    h1,
    m,
    m_len,
) => {
    const ptr_h1 = mput(h1, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_m = mput(m, m_len);
    _ecc_frost_ristretto255_sha512_H1(
        ptr_h1,
        ptr_m,
        m_len,
    );
    mget(h1, ptr_h1, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_h1, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_m, m_len);
}

/**
 * Map arbitrary inputs to non-zero Scalar elements of the prime-order group scalar field.
 *
 * This is a variant of H2 that folds internally all inputs in the same
 * hash calculation.
 *
 * @param {Uint8Array} h1 (output) size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} m1 size:m1_len
 * @param {number} m1_len the length of `m1`
 * @param {Uint8Array} m2 size:m2_len
 * @param {number} m2_len the length of `m2`
 */
Module.ecc_frost_ristretto255_sha512_H1_2 = (
    h1,
    m1,
    m1_len,
    m2,
    m2_len,
) => {
    const ptr_h1 = mput(h1, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_m1 = mput(m1, m1_len);
    const ptr_m2 = mput(m2, m2_len);
    _ecc_frost_ristretto255_sha512_H1_2(
        ptr_h1,
        ptr_m1,
        m1_len,
        ptr_m2,
        m2_len,
    );
    mget(h1, ptr_h1, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_h1, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_m1, m1_len);
    mfree(ptr_m2, m2_len);
}

/**
 * Map arbitrary inputs to non-zero Scalar elements of the prime-order group scalar field.
 *
 * @param {Uint8Array} h2 (output) size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} m size:m_len
 * @param {number} m_len the length of `m`
 */
Module.ecc_frost_ristretto255_sha512_H2 = (
    h2,
    m,
    m_len,
) => {
    const ptr_h2 = mput(h2, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_m = mput(m, m_len);
    _ecc_frost_ristretto255_sha512_H2(
        ptr_h2,
        ptr_m,
        m_len,
    );
    mget(h2, ptr_h2, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_h2, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_m, m_len);
}

/**
 * Map arbitrary inputs to non-zero Scalar elements of the prime-order group scalar field.
 *
 * This is a variant of H2 that folds internally all inputs in the same
 * hash calculation.
 *
 * @param {Uint8Array} h2 (output) size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} m1 size:m1_len
 * @param {number} m1_len the length of `m1`
 * @param {Uint8Array} m2 size:m2_len
 * @param {number} m2_len the length of `m2`
 * @param {Uint8Array} m3 size:m3_len
 * @param {number} m3_len the length of `m3`
 */
Module.ecc_frost_ristretto255_sha512_H2_3 = (
    h2,
    m1,
    m1_len,
    m2,
    m2_len,
    m3,
    m3_len,
) => {
    const ptr_h2 = mput(h2, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_m1 = mput(m1, m1_len);
    const ptr_m2 = mput(m2, m2_len);
    const ptr_m3 = mput(m3, m3_len);
    _ecc_frost_ristretto255_sha512_H2_3(
        ptr_h2,
        ptr_m1,
        m1_len,
        ptr_m2,
        m2_len,
        ptr_m3,
        m3_len,
    );
    mget(h2, ptr_h2, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_h2, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_m1, m1_len);
    mfree(ptr_m2, m2_len);
    mfree(ptr_m3, m3_len);
}

/**
 * This is an alias for the ciphersuite hash function with
 * domain separation applied.
 *
 * @param {Uint8Array} h3 (output) size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} m size:m_len
 * @param {number} m_len the length of `m`
 */
Module.ecc_frost_ristretto255_sha512_H3 = (
    h3,
    m,
    m_len,
) => {
    const ptr_h3 = mput(h3, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_m = mput(m, m_len);
    _ecc_frost_ristretto255_sha512_H3(
        ptr_h3,
        ptr_m,
        m_len,
    );
    mget(h3, ptr_h3, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_h3, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_m, m_len);
}

/**
 * This is an alias for the ciphersuite hash function with
 * domain separation applied.
 *
 * This is a variant of H3 that folds internally all inputs in the same
 * hash calculation.
 *
 * @param {Uint8Array} h3 (output) size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} m1 size:m1_len
 * @param {number} m1_len the length of `m1`
 * @param {Uint8Array} m2 size:m2_len
 * @param {number} m2_len the length of `m2`
 */
Module.ecc_frost_ristretto255_sha512_H3_2 = (
    h3,
    m1,
    m1_len,
    m2,
    m2_len,
) => {
    const ptr_h3 = mput(h3, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_m1 = mput(m1, m1_len);
    const ptr_m2 = mput(m2, m2_len);
    _ecc_frost_ristretto255_sha512_H3_2(
        ptr_h3,
        ptr_m1,
        m1_len,
        ptr_m2,
        m2_len,
    );
    mget(h3, ptr_h3, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_h3, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_m1, m1_len);
    mfree(ptr_m2, m2_len);
}

/**
 * Implemented by computing H(contextString || "msg" || m).
 *
 * @param {Uint8Array} h4 (output) size:64
 * @param {Uint8Array} m size:m_len
 * @param {number} m_len the length of `m`
 */
Module.ecc_frost_ristretto255_sha512_H4 = (
    h4,
    m,
    m_len,
) => {
    const ptr_h4 = mput(h4, 64);
    const ptr_m = mput(m, m_len);
    _ecc_frost_ristretto255_sha512_H4(
        ptr_h4,
        ptr_m,
        m_len,
    );
    mget(h4, ptr_h4, 64);
    mfree(ptr_h4, 64);
    mfree(ptr_m, m_len);
}

/**
 * Implemented by computing H(contextString || "com" || m).
 *
 * @param {Uint8Array} h5 (output) size:64
 * @param {Uint8Array} m size:m_len
 * @param {number} m_len the length of `m`
 */
Module.ecc_frost_ristretto255_sha512_H5 = (
    h5,
    m,
    m_len,
) => {
    const ptr_h5 = mput(h5, 64);
    const ptr_m = mput(m, m_len);
    _ecc_frost_ristretto255_sha512_H5(
        ptr_h5,
        ptr_m,
        m_len,
    );
    mget(h5, ptr_h5, 64);
    mfree(ptr_h5, 64);
    mfree(ptr_m, m_len);
}

/**
 * Generate a single-party setting Schnorr signature.
 *
 * @param {Uint8Array} signature (output) signature, size:ecc_frost_ristretto255_sha512_SIGNATURESIZE
 * @param {Uint8Array} msg message to be signed, size:msg_len
 * @param {number} msg_len the length of `msg`
 * @param {Uint8Array} SK private key, a scalar, size:ecc_frost_ristretto255_sha512_SECRETKEYSIZE
 */
Module.ecc_frost_ristretto255_sha512_prime_order_sign = (
    signature,
    msg,
    msg_len,
    SK,
) => {
    const ptr_signature = mput(signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    const ptr_msg = mput(msg, msg_len);
    const ptr_SK = mput(SK, ecc_frost_ristretto255_sha512_SECRETKEYSIZE);
    _ecc_frost_ristretto255_sha512_prime_order_sign(
        ptr_signature,
        ptr_msg,
        msg_len,
        ptr_SK,
    );
    mget(signature, ptr_signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    mfree(ptr_signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    mfree(ptr_msg, msg_len);
    mfree(ptr_SK, ecc_frost_ristretto255_sha512_SECRETKEYSIZE);
}

/**
 * Verify a Schnorr signature.
 *
 * @param {Uint8Array} msg signed message, size:msg_len
 * @param {number} msg_len the length of `msg`
 * @param {Uint8Array} signature signature, size:ecc_frost_ristretto255_sha512_SIGNATURESIZE
 * @param {Uint8Array} PK public key, a group element, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @return {number} 1 if signature is valid, and 0 otherwise
 */
Module.ecc_frost_ristretto255_sha512_prime_order_verify = (
    msg,
    msg_len,
    signature,
    PK,
) => {
    const ptr_msg = mput(msg, msg_len);
    const ptr_signature = mput(signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    const ptr_PK = mput(PK, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    const fun_ret = _ecc_frost_ristretto255_sha512_prime_order_verify(
        ptr_msg,
        msg_len,
        ptr_signature,
        ptr_PK,
    );
    mfree(ptr_msg, msg_len);
    mfree(ptr_signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    mfree(ptr_PK, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    return fun_ret;
}

/**
 *
 *
 * @param {Uint8Array} participant_private_keys (output) MAX_PARTICIPANTS shares of the secret key s, each a tuple consisting of the participant identifier (a NonZeroScalar) and the key share (a Scalar), size:n*ecc_frost_ristretto255_sha512_POINTSIZE
 * @param {Uint8Array} group_public_key (output) public key corresponding to the group signing key, an Element, size:ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} vss_commitment (output) a vector commitment of Elements in G, to each of the coefficients in the polynomial defined by secret_key_shares and whose first element is G.ScalarBaseMult(s), size:t*ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} polynomial_coefficients (output) size:t*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} secret_key a group secret, a Scalar, that MUST be derived from at least Ns bytes of entropy, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {number} n the number of shares to generate
 * @param {number} t the threshold of the secret sharing scheme
 * @param {Uint8Array} coefficients size:(t-1)*ecc_frost_ristretto255_sha512_SCALARSIZE
 */
Module.ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_coefficients = (
    participant_private_keys,
    group_public_key,
    vss_commitment,
    polynomial_coefficients,
    secret_key,
    n,
    t,
    coefficients,
) => {
    const ptr_participant_private_keys = mput(participant_private_keys, n*ecc_frost_ristretto255_sha512_POINTSIZE);
    const ptr_group_public_key = mput(group_public_key, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    const ptr_vss_commitment = mput(vss_commitment, t*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    const ptr_polynomial_coefficients = mput(polynomial_coefficients, t*ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_secret_key = mput(secret_key, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_coefficients = mput(coefficients, (t-1)*ecc_frost_ristretto255_sha512_SCALARSIZE);
    _ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_coefficients(
        ptr_participant_private_keys,
        ptr_group_public_key,
        ptr_vss_commitment,
        ptr_polynomial_coefficients,
        ptr_secret_key,
        n,
        t,
        ptr_coefficients,
    );
    mget(participant_private_keys, ptr_participant_private_keys, n*ecc_frost_ristretto255_sha512_POINTSIZE);
    mget(group_public_key, ptr_group_public_key, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mget(vss_commitment, ptr_vss_commitment, t*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mget(polynomial_coefficients, ptr_polynomial_coefficients, t*ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_participant_private_keys, n*ecc_frost_ristretto255_sha512_POINTSIZE);
    mfree(ptr_group_public_key, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_vss_commitment, t*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_polynomial_coefficients, t*ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_secret_key, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_coefficients, (t-1)*ecc_frost_ristretto255_sha512_SCALARSIZE);
}

/**
 * Split a secret into shares.
 *
 * @param {Uint8Array} secret_key_shares (output) A list of n secret shares, each of which is an element of F, size:n*ecc_frost_ristretto255_sha512_POINTSIZE
 * @param {Uint8Array} polynomial_coefficients (output) a vector of t coefficients which uniquely determine a polynomial f, size:t*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} s secret value to be shared, a scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} coefficients an array of size t - 1 with randomly generated scalars, not including the 0th coefficient of the polynomial, size:(t-1)*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {number} n the number of shares to generate, an integer less than 2^16
 * @param {number} t the threshold of the secret sharing scheme, an integer greater than 0
 * @return {number} 0 if no errors, else -1
 */
Module.ecc_frost_ristretto255_sha512_secret_share_shard = (
    secret_key_shares,
    polynomial_coefficients,
    s,
    coefficients,
    n,
    t,
) => {
    const ptr_secret_key_shares = mput(secret_key_shares, n*ecc_frost_ristretto255_sha512_POINTSIZE);
    const ptr_polynomial_coefficients = mput(polynomial_coefficients, t*ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_s = mput(s, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_coefficients = mput(coefficients, (t-1)*ecc_frost_ristretto255_sha512_SCALARSIZE);
    const fun_ret = _ecc_frost_ristretto255_sha512_secret_share_shard(
        ptr_secret_key_shares,
        ptr_polynomial_coefficients,
        ptr_s,
        ptr_coefficients,
        n,
        t,
    );
    mget(secret_key_shares, ptr_secret_key_shares, n*ecc_frost_ristretto255_sha512_POINTSIZE);
    mget(polynomial_coefficients, ptr_polynomial_coefficients, t*ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_secret_key_shares, n*ecc_frost_ristretto255_sha512_POINTSIZE);
    mfree(ptr_polynomial_coefficients, t*ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_s, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_coefficients, (t-1)*ecc_frost_ristretto255_sha512_SCALARSIZE);
    return fun_ret;
}

/**
 * Combines a shares list of length MIN_PARTICIPANTS to recover the secret.
 *
 * @param {Uint8Array} s (output) the resulting secret s that was previously split into shares, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} shares a list of at minimum MIN_PARTICIPANTS secret shares, each a tuple (i, f(i)) where i and f(i) are Scalars, size:shares_len*ecc_frost_ristretto255_sha512_POINTSIZE
 * @param {number} shares_len the number of shares in `shares`
 * @return {number} 0 if no errors, else -1
 */
Module.ecc_frost_ristretto255_sha512_secret_share_combine = (
    s,
    shares,
    shares_len,
) => {
    const ptr_s = mput(s, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_shares = mput(shares, shares_len*ecc_frost_ristretto255_sha512_POINTSIZE);
    const fun_ret = _ecc_frost_ristretto255_sha512_secret_share_combine(
        ptr_s,
        ptr_shares,
        shares_len,
    );
    mget(s, ptr_s, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_s, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_shares, shares_len*ecc_frost_ristretto255_sha512_POINTSIZE);
    return fun_ret;
}

/**
 * Evaluate a polynomial f at a particular input x, i.e., y = f(x)
 * using Horner's method.
 *
 * @param {Uint8Array} value (output) scalar result of the polynomial evaluated at input x, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} x input at which to evaluate the polynomial, a scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} coeffs the polynomial coefficients, a list of scalars, size:coeffs_len*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {number} coeffs_len the number of coefficients in `coeffs`
 */
Module.ecc_frost_ristretto255_sha512_polynomial_evaluate = (
    value,
    x,
    coeffs,
    coeffs_len,
) => {
    const ptr_value = mput(value, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_x = mput(x, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_coeffs = mput(coeffs, coeffs_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
    _ecc_frost_ristretto255_sha512_polynomial_evaluate(
        ptr_value,
        ptr_x,
        ptr_coeffs,
        coeffs_len,
    );
    mget(value, ptr_value, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_value, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_x, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_coeffs, coeffs_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
}

/**
 * Recover the constant term of an interpolating polynomial defined by a set
 * of points.
 *
 * @param {Uint8Array} f_zero (output) the constant term of f, i.e., f(0), a scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {Uint8Array} points a set of t points with distinct x coordinates on a polynomial f, each a tuple of two Scalar values representing the x and y coordinates, size:points_len*ecc_frost_ristretto255_sha512_POINTSIZE
 * @param {number} points_len the number of elements in `points`
 */
Module.ecc_frost_ristretto255_sha512_polynomial_interpolate_constant = (
    f_zero,
    points,
    points_len,
) => {
    const ptr_f_zero = mput(f_zero, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const ptr_points = mput(points, points_len*ecc_frost_ristretto255_sha512_POINTSIZE);
    _ecc_frost_ristretto255_sha512_polynomial_interpolate_constant(
        ptr_f_zero,
        ptr_points,
        points_len,
    );
    mget(f_zero, ptr_f_zero, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_f_zero, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_points, points_len*ecc_frost_ristretto255_sha512_POINTSIZE);
}

/**
 * Compute the commitment using a polynomial f of degree at most MIN_PARTICIPANTS-1.
 *
 * @param {Uint8Array} vss_commitment (output) a vector commitment to each of the coefficients in coeffs, where each item of the vector commitment is an Element, size:coeffs_len*ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} coeffs a vector of the MIN_PARTICIPANTS coefficients which uniquely determine a polynomial f, size:coeffs_len*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param {number} coeffs_len the length of `coeffs`
 */
Module.ecc_frost_ristretto255_sha512_vss_commit = (
    vss_commitment,
    coeffs,
    coeffs_len,
) => {
    const ptr_vss_commitment = mput(vss_commitment, coeffs_len*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    const ptr_coeffs = mput(coeffs, coeffs_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
    _ecc_frost_ristretto255_sha512_vss_commit(
        ptr_vss_commitment,
        ptr_coeffs,
        coeffs_len,
    );
    mget(vss_commitment, ptr_vss_commitment, coeffs_len*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_vss_commitment, coeffs_len*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_coeffs, coeffs_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
}

/**
 * For verification of a participant's share.
 *
 * @param {Uint8Array} share_i a tuple of the form (i, sk_i), size:ecc_frost_ristretto255_sha512_POINTSIZE
 * @param {Uint8Array} vss_commitment a vector commitment to each of the coefficients in coeffs, where each item of the vector commitment is an Element, size:t*ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param {number} t the threshold of the secret sharing scheme
 * @return {number} 1 if sk_i is valid, and 0 otherwise.
 */
Module.ecc_frost_ristretto255_sha512_vss_verify = (
    share_i,
    vss_commitment,
    t,
) => {
    const ptr_share_i = mput(share_i, ecc_frost_ristretto255_sha512_POINTSIZE);
    const ptr_vss_commitment = mput(vss_commitment, t*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    const fun_ret = _ecc_frost_ristretto255_sha512_vss_verify(
        ptr_share_i,
        ptr_vss_commitment,
        t,
    );
    mfree(ptr_share_i, ecc_frost_ristretto255_sha512_POINTSIZE);
    mfree(ptr_vss_commitment, t*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    return fun_ret;
}

/**
 * Derive group info.
 *
 * @param {Uint8Array} PK (output) the public key representing the group, an Element, size:ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param {Uint8Array} participant_public_keys (output) a list of MAX_PARTICIPANTS public keys PK_i for i=1,...,MAX_PARTICIPANTS, where each PK_i is the public key, an Element, for participant i., size:n*ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param {number} n the number of shares to generate
 * @param {number} t the threshold of the secret sharing scheme
 * @param {Uint8Array} vss_commitment a VSS commitment to a secret polynomial f, a vector commitment to each of the coefficients in coeffs, where each element of the vector commitment is an Element, size:t*ecc_frost_ristretto255_sha512_ELEMENTSIZE
 */
Module.ecc_frost_ristretto255_sha512_derive_group_info = (
    PK,
    participant_public_keys,
    n,
    t,
    vss_commitment,
) => {
    const ptr_PK = mput(PK, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    const ptr_participant_public_keys = mput(participant_public_keys, n*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    const ptr_vss_commitment = mput(vss_commitment, t*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    _ecc_frost_ristretto255_sha512_derive_group_info(
        ptr_PK,
        ptr_participant_public_keys,
        n,
        t,
        ptr_vss_commitment,
    );
    mget(PK, ptr_PK, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mget(participant_public_keys, ptr_participant_public_keys, n*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_PK, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_participant_public_keys, n*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_vss_commitment, t*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
}

// pre

const ecc_pre_schema1_MESSAGESIZE = 576;
/**
 * Size of the PRE-SCHEMA1 plaintext and ciphertext messages (size of a Fp12 element in BLS12-381).
 *
 * @type {number}
 */
Module.ecc_pre_schema1_MESSAGESIZE = ecc_pre_schema1_MESSAGESIZE;

const ecc_pre_schema1_SEEDSIZE = 32;
/**
 * Size of the PRE-SCHEMA1 seed used in all operations.
 *
 * @type {number}
 */
Module.ecc_pre_schema1_SEEDSIZE = ecc_pre_schema1_SEEDSIZE;

const ecc_pre_schema1_PUBLICKEYSIZE = 48;
/**
 * Size of the PRE-SCHEMA1 public key (size of a G1 element in BLS12-381).
 *
 * @type {number}
 */
Module.ecc_pre_schema1_PUBLICKEYSIZE = ecc_pre_schema1_PUBLICKEYSIZE;

const ecc_pre_schema1_PRIVATEKEYSIZE = 32;
/**
 * Size of the PRE-SCHEMA1 private key (size of a scalar in BLS12-381).
 *
 * @type {number}
 */
Module.ecc_pre_schema1_PRIVATEKEYSIZE = ecc_pre_schema1_PRIVATEKEYSIZE;

const ecc_pre_schema1_SIGNINGPUBLICKEYSIZE = 32;
/**
 * Size of the PRE-SCHEMA1 signing public key (ed25519 signing public key size).
 *
 * @type {number}
 */
Module.ecc_pre_schema1_SIGNINGPUBLICKEYSIZE = ecc_pre_schema1_SIGNINGPUBLICKEYSIZE;

const ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE = 64;
/**
 * Size of the PRE-SCHEMA1 signing private key (ed25519 signing secret key size).
 *
 * @type {number}
 */
Module.ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE = ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE;

const ecc_pre_schema1_SIGNATURESIZE = 64;
/**
 * Size of the PRE-SCHEMA1 signature (ed25519 signature size).
 *
 * @type {number}
 */
Module.ecc_pre_schema1_SIGNATURESIZE = ecc_pre_schema1_SIGNATURESIZE;

const ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE = 752;
/**
 * Size of the whole ciphertext structure, that is the result of the simple Encrypt operation.
 *
 * @type {number}
 */
Module.ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE = ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE;

const ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE = 2096;
/**
 * Size of the whole ciphertext structure, that is the result of the one-hop ReEncrypt operation.
 *
 * @type {number}
 */
Module.ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE = ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE;

const ecc_pre_schema1_REKEYSIZE = 816;
/**
 * Size of the whole re-encryption key structure.
 *
 * @type {number}
 */
Module.ecc_pre_schema1_REKEYSIZE = ecc_pre_schema1_REKEYSIZE;

/**
 * Generates a random message suitable to use in the protocol.
 *
 * The output can be used in other key derivation algorithms for other
 * symmetric encryption protocols.
 *
 * @param {Uint8Array} m (output) a random plaintext message, size:ecc_pre_schema1_MESSAGESIZE
 */
Module.ecc_pre_schema1_MessageGen = (
    m,
) => {
    const ptr_m = mput(m, ecc_pre_schema1_MESSAGESIZE);
    _ecc_pre_schema1_MessageGen(
        ptr_m,
    );
    mget(m, ptr_m, ecc_pre_schema1_MESSAGESIZE);
    mfree(ptr_m, ecc_pre_schema1_MESSAGESIZE);
}

/**
 * Derive a public/private key pair deterministically
 * from the input "seed".
 *
 * @param {Uint8Array} pk (output) public key, size:ecc_pre_schema1_PUBLICKEYSIZE
 * @param {Uint8Array} sk (output) private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
 * @param {Uint8Array} seed input seed to generate the key pair, size:ecc_pre_schema1_SEEDSIZE
 */
Module.ecc_pre_schema1_DeriveKey = (
    pk,
    sk,
    seed,
) => {
    const ptr_pk = mput(pk, ecc_pre_schema1_PUBLICKEYSIZE);
    const ptr_sk = mput(sk, ecc_pre_schema1_PRIVATEKEYSIZE);
    const ptr_seed = mput(seed, ecc_pre_schema1_SEEDSIZE);
    _ecc_pre_schema1_DeriveKey(
        ptr_pk,
        ptr_sk,
        ptr_seed,
    );
    mget(pk, ptr_pk, ecc_pre_schema1_PUBLICKEYSIZE);
    mget(sk, ptr_sk, ecc_pre_schema1_PRIVATEKEYSIZE);
    mfree(ptr_pk, ecc_pre_schema1_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_pre_schema1_PRIVATEKEYSIZE);
    mfree(ptr_seed, ecc_pre_schema1_SEEDSIZE);
}

/**
 * Generate a public/private key pair.
 *
 * @param {Uint8Array} pk (output) public key, size:ecc_pre_schema1_PUBLICKEYSIZE
 * @param {Uint8Array} sk (output) private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
 */
Module.ecc_pre_schema1_KeyGen = (
    pk,
    sk,
) => {
    const ptr_pk = mput(pk, ecc_pre_schema1_PUBLICKEYSIZE);
    const ptr_sk = mput(sk, ecc_pre_schema1_PRIVATEKEYSIZE);
    _ecc_pre_schema1_KeyGen(
        ptr_pk,
        ptr_sk,
    );
    mget(pk, ptr_pk, ecc_pre_schema1_PUBLICKEYSIZE);
    mget(sk, ptr_sk, ecc_pre_schema1_PRIVATEKEYSIZE);
    mfree(ptr_pk, ecc_pre_schema1_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_pre_schema1_PRIVATEKEYSIZE);
}

/**
 * Derive a signing public/private key pair deterministically
 * from the input "seed".
 *
 * @param {Uint8Array} spk (output) signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @param {Uint8Array} ssk (output) signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
 * @param {Uint8Array} seed input seed to generate the key pair, size:ecc_pre_schema1_SEEDSIZE
 */
Module.ecc_pre_schema1_DeriveSigningKey = (
    spk,
    ssk,
    seed,
) => {
    const ptr_spk = mput(spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    const ptr_ssk = mput(ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    const ptr_seed = mput(seed, ecc_pre_schema1_SEEDSIZE);
    _ecc_pre_schema1_DeriveSigningKey(
        ptr_spk,
        ptr_ssk,
        ptr_seed,
    );
    mget(spk, ptr_spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mget(ssk, ptr_ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    mfree(ptr_spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mfree(ptr_ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    mfree(ptr_seed, ecc_pre_schema1_SEEDSIZE);
}

/**
 * Generate a signing public/private key pair.
 *
 * @param {Uint8Array} spk (output) signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @param {Uint8Array} ssk (output) signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
 */
Module.ecc_pre_schema1_SigningKeyGen = (
    spk,
    ssk,
) => {
    const ptr_spk = mput(spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    const ptr_ssk = mput(ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    _ecc_pre_schema1_SigningKeyGen(
        ptr_spk,
        ptr_ssk,
    );
    mget(spk, ptr_spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mget(ssk, ptr_ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    mfree(ptr_spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mfree(ptr_ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
}

/**
 * Encrypt a message `m` to delegatee j, given j’s public key (pk_j) and the
 * sender i’s signing key pair (spk_i, ssk_i). Produces a ciphertext C_j.
 *
 * This is also called encryption of level 1, since it's used to encrypt to
 * itself (i.e j == i), in order to have later the ciphertext re-encrypted
 * by the proxy with the re-encryption key (level 2).
 *
 * @param {Uint8Array} C_j_raw (output) a CiphertextLevel1_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE
 * @param {Uint8Array} m the plaintext message, size:ecc_pre_schema1_MESSAGESIZE
 * @param {Uint8Array} pk_j delegatee's public key, size:ecc_pre_schema1_PUBLICKEYSIZE
 * @param {Uint8Array} spk_i sender signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @param {Uint8Array} ssk_i sender signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
 * @param {Uint8Array} seed seed used to generate the internal ephemeral key, size:ecc_pre_schema1_SEEDSIZE
 */
Module.ecc_pre_schema1_EncryptWithSeed = (
    C_j_raw,
    m,
    pk_j,
    spk_i,
    ssk_i,
    seed,
) => {
    const ptr_C_j_raw = mput(C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    const ptr_m = mput(m, ecc_pre_schema1_MESSAGESIZE);
    const ptr_pk_j = mput(pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    const ptr_spk_i = mput(spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    const ptr_ssk_i = mput(ssk_i, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    const ptr_seed = mput(seed, ecc_pre_schema1_SEEDSIZE);
    _ecc_pre_schema1_EncryptWithSeed(
        ptr_C_j_raw,
        ptr_m,
        ptr_pk_j,
        ptr_spk_i,
        ptr_ssk_i,
        ptr_seed,
    );
    mget(C_j_raw, ptr_C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    mfree(ptr_C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    mfree(ptr_m, ecc_pre_schema1_MESSAGESIZE);
    mfree(ptr_pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    mfree(ptr_spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mfree(ptr_ssk_i, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    mfree(ptr_seed, ecc_pre_schema1_SEEDSIZE);
}

/**
 * Encrypt a message `m` to delegatee j, given j’s public key (pk_j) and the
 * sender i’s signing key pair (spk_i, ssk_i). Produces a ciphertext C_j.
 *
 * This is also called encryption of level 1, since it's used to encrypt to
 * itself (i.e j == i), in order to have later the ciphertext re-encrypted
 * by the proxy with the re-encryption key (level 2).
 *
 * @param {Uint8Array} C_j_raw (output) a CiphertextLevel1_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE
 * @param {Uint8Array} m the plaintext message, size:ecc_pre_schema1_MESSAGESIZE
 * @param {Uint8Array} pk_j delegatee's public key, size:ecc_pre_schema1_PUBLICKEYSIZE
 * @param {Uint8Array} spk_i sender signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @param {Uint8Array} ssk_i sender signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
 */
Module.ecc_pre_schema1_Encrypt = (
    C_j_raw,
    m,
    pk_j,
    spk_i,
    ssk_i,
) => {
    const ptr_C_j_raw = mput(C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    const ptr_m = mput(m, ecc_pre_schema1_MESSAGESIZE);
    const ptr_pk_j = mput(pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    const ptr_spk_i = mput(spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    const ptr_ssk_i = mput(ssk_i, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    _ecc_pre_schema1_Encrypt(
        ptr_C_j_raw,
        ptr_m,
        ptr_pk_j,
        ptr_spk_i,
        ptr_ssk_i,
    );
    mget(C_j_raw, ptr_C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    mfree(ptr_C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    mfree(ptr_m, ecc_pre_schema1_MESSAGESIZE);
    mfree(ptr_pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    mfree(ptr_spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mfree(ptr_ssk_i, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
}

/**
 * Generate a re-encryption key from user i (the delegator) to user j (the delegatee).
 *
 * Requires the delegator’s private key (sk_i), the delegatee’s public key (pk_j), and
 * the delegator’s signing key pair (spk_i, ssk_i).
 *
 * @param {Uint8Array} tk_i_j_raw (output) a ReKey_t structure, size:ecc_pre_schema1_REKEYSIZE
 * @param {Uint8Array} sk_i delegator’s private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
 * @param {Uint8Array} pk_j delegatee’s public key, size:ecc_pre_schema1_PUBLICKEYSIZE
 * @param {Uint8Array} spk_i delegator’s signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @param {Uint8Array} ssk_i delegator’s signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
 */
Module.ecc_pre_schema1_ReKeyGen = (
    tk_i_j_raw,
    sk_i,
    pk_j,
    spk_i,
    ssk_i,
) => {
    const ptr_tk_i_j_raw = mput(tk_i_j_raw, ecc_pre_schema1_REKEYSIZE);
    const ptr_sk_i = mput(sk_i, ecc_pre_schema1_PRIVATEKEYSIZE);
    const ptr_pk_j = mput(pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    const ptr_spk_i = mput(spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    const ptr_ssk_i = mput(ssk_i, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    _ecc_pre_schema1_ReKeyGen(
        ptr_tk_i_j_raw,
        ptr_sk_i,
        ptr_pk_j,
        ptr_spk_i,
        ptr_ssk_i,
    );
    mget(tk_i_j_raw, ptr_tk_i_j_raw, ecc_pre_schema1_REKEYSIZE);
    mfree(ptr_tk_i_j_raw, ecc_pre_schema1_REKEYSIZE);
    mfree(ptr_sk_i, ecc_pre_schema1_PRIVATEKEYSIZE);
    mfree(ptr_pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    mfree(ptr_spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mfree(ptr_ssk_i, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
}

/**
 * Re-encrypt a ciphertext encrypted to i (C_i) into a ciphertext encrypted
 * to j (C_j), given a re-encryption key (tk_i_j) and the proxy’s signing key
 * pair (spk, ssk).
 *
 * This operation is performed by the proxy and is also called encryption of
 * level 2, since it takes a ciphertext from a level 1 and re-encrypt it.
 *
 * It also validate the signature on the encrypted ciphertext and re-encryption key.
 *
 * @param {Uint8Array} C_j_raw (output) a CiphertextLevel2_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE
 * @param {Uint8Array} C_i_raw a CiphertextLevel1_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE
 * @param {Uint8Array} tk_i_j_raw a ReKey_t structure, size:ecc_pre_schema1_REKEYSIZE
 * @param {Uint8Array} spk_i delegator’s signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @param {Uint8Array} pk_j delegatee’s public key, size:ecc_pre_schema1_PUBLICKEYSIZE
 * @param {Uint8Array} spk proxy’s signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @param {Uint8Array} ssk proxy’s signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
 * @return {number} 0 if all the signatures are valid, -1 if there is an error
 */
Module.ecc_pre_schema1_ReEncrypt = (
    C_j_raw,
    C_i_raw,
    tk_i_j_raw,
    spk_i,
    pk_j,
    spk,
    ssk,
) => {
    const ptr_C_j_raw = mput(C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE);
    const ptr_C_i_raw = mput(C_i_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    const ptr_tk_i_j_raw = mput(tk_i_j_raw, ecc_pre_schema1_REKEYSIZE);
    const ptr_spk_i = mput(spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    const ptr_pk_j = mput(pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    const ptr_spk = mput(spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    const ptr_ssk = mput(ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    const fun_ret = _ecc_pre_schema1_ReEncrypt(
        ptr_C_j_raw,
        ptr_C_i_raw,
        ptr_tk_i_j_raw,
        ptr_spk_i,
        ptr_pk_j,
        ptr_spk,
        ptr_ssk,
    );
    mget(C_j_raw, ptr_C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE);
    mfree(ptr_C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE);
    mfree(ptr_C_i_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    mfree(ptr_tk_i_j_raw, ecc_pre_schema1_REKEYSIZE);
    mfree(ptr_spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mfree(ptr_pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    mfree(ptr_spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mfree(ptr_ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    return fun_ret;
}

/**
 * Decrypt a signed ciphertext (C_i) given the private key of the recipient
 * i (sk_i). Returns the original message that was encrypted, m.
 *
 * This operations is usually performed by the delegator, since it encrypted
 * the message just to be stored and later be re-encrypted by the proxy.
 *
 * It also validate the signature on the encrypted ciphertext.
 *
 * @param {Uint8Array} m (output) the original plaintext message, size:ecc_pre_schema1_MESSAGESIZE
 * @param {Uint8Array} C_i_raw a CiphertextLevel1_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE
 * @param {Uint8Array} sk_i recipient private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
 * @param {Uint8Array} spk_i recipient signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @return {number} 0 if all the signatures are valid, -1 if there is an error
 */
Module.ecc_pre_schema1_DecryptLevel1 = (
    m,
    C_i_raw,
    sk_i,
    spk_i,
) => {
    const ptr_m = mput(m, ecc_pre_schema1_MESSAGESIZE);
    const ptr_C_i_raw = mput(C_i_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    const ptr_sk_i = mput(sk_i, ecc_pre_schema1_PRIVATEKEYSIZE);
    const ptr_spk_i = mput(spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    const fun_ret = _ecc_pre_schema1_DecryptLevel1(
        ptr_m,
        ptr_C_i_raw,
        ptr_sk_i,
        ptr_spk_i,
    );
    mget(m, ptr_m, ecc_pre_schema1_MESSAGESIZE);
    mfree(ptr_m, ecc_pre_schema1_MESSAGESIZE);
    mfree(ptr_C_i_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    mfree(ptr_sk_i, ecc_pre_schema1_PRIVATEKEYSIZE);
    mfree(ptr_spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    return fun_ret;
}

/**
 * Decrypt a signed ciphertext (C_j) given the private key of the recipient
 * j (sk_j). Returns the original message that was encrypted, m.
 *
 * This operations is usually performed by the delegatee, since it is the proxy
 * that re-encrypt the message and send the ciphertext to the final recipient.
 *
 * It also validate the signature on the encrypted ciphertext.
 *
 * @param {Uint8Array} m (output) the original plaintext message, size:ecc_pre_schema1_MESSAGESIZE
 * @param {Uint8Array} C_j_raw a CiphertextLevel2_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE
 * @param {Uint8Array} sk_j recipient private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
 * @param {Uint8Array} spk proxy’s signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @return {number} 0 if all the signatures are valid, -1 if there is an error
 */
Module.ecc_pre_schema1_DecryptLevel2 = (
    m,
    C_j_raw,
    sk_j,
    spk,
) => {
    const ptr_m = mput(m, ecc_pre_schema1_MESSAGESIZE);
    const ptr_C_j_raw = mput(C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE);
    const ptr_sk_j = mput(sk_j, ecc_pre_schema1_PRIVATEKEYSIZE);
    const ptr_spk = mput(spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    const fun_ret = _ecc_pre_schema1_DecryptLevel2(
        ptr_m,
        ptr_C_j_raw,
        ptr_sk_j,
        ptr_spk,
    );
    mget(m, ptr_m, ecc_pre_schema1_MESSAGESIZE);
    mfree(ptr_m, ecc_pre_schema1_MESSAGESIZE);
    mfree(ptr_C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE);
    mfree(ptr_sk_j, ecc_pre_schema1_PRIVATEKEYSIZE);
    mfree(ptr_spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    return fun_ret;
}
