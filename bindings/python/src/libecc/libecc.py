#
# Copyright (c) 2021-2022, Alden Torres
#
# Licensed under the terms of the MIT license.
# Copy of the license at https://opensource.org/licenses/MIT
#

from ._libecc_cffi import ffi, lib

# util


def ecc_randombytes(
    buf: bytearray,
    n: int
) -> None:
    """
    Fills `n` bytes at `buf` with an unpredictable sequence of bytes.
    
    buf -- (output) the byte array to fill, size:n
    n -- the number of bytes to fill
    """
    ptr_buf = ffi.from_buffer(buf)
    lib.ecc_randombytes(
        ptr_buf,
        n
    )
    return None


def ecc_concat2(
    out: bytearray,
    a1: bytes,
    a1_len: int,
    a2: bytes,
    a2_len: int
) -> None:
    """
    Concatenates two byte arrays. Same as a || b.
    
    a || b: denotes the concatenation of byte strings a and b. For
    example, "ABC" || "DEF" == "ABCDEF".
    
    out -- (output) result of the concatenation, size:a1_len+a2_len
    a1 -- first byte array, size:a1_len
    a1_len -- the length of `a1`
    a2 -- second byte array, size:a2_len
    a2_len -- the length of `a2`
    """
    ptr_out = ffi.from_buffer(out)
    ptr_a1 = ffi.from_buffer(a1)
    ptr_a2 = ffi.from_buffer(a2)
    lib.ecc_concat2(
        ptr_out,
        ptr_a1,
        a1_len,
        ptr_a2,
        a2_len
    )
    return None


def ecc_concat3(
    out: bytearray,
    a1: bytes,
    a1_len: int,
    a2: bytes,
    a2_len: int,
    a3: bytes,
    a3_len: int
) -> None:
    """
    Same as calling ecc_concat2 but with three byte arrays.
    
    out -- (output) result of the concatenation, size:a1_len+a2_len+a3_len
    a1 -- first byte array, size:a1_len
    a1_len -- the length of `a1`
    a2 -- second byte array, size:a2_len
    a2_len -- the length of `a2`
    a3 -- third byte array, size:a3_len
    a3_len -- the length of `a3`
    """
    ptr_out = ffi.from_buffer(out)
    ptr_a1 = ffi.from_buffer(a1)
    ptr_a2 = ffi.from_buffer(a2)
    ptr_a3 = ffi.from_buffer(a3)
    lib.ecc_concat3(
        ptr_out,
        ptr_a1,
        a1_len,
        ptr_a2,
        a2_len,
        ptr_a3,
        a3_len
    )
    return None


def ecc_concat4(
    out: bytearray,
    a1: bytes,
    a1_len: int,
    a2: bytes,
    a2_len: int,
    a3: bytes,
    a3_len: int,
    a4: bytes,
    a4_len: int
) -> None:
    """
    Same as calling ecc_concat2 but with four byte arrays.
    
    out -- (output) result of the concatenation, size:a1_len+a2_len+a3_len+a4_len
    a1 -- first byte array, size:a1_len
    a1_len -- the length of `a1`
    a2 -- second byte array, size:a2_len
    a2_len -- the length of `a2`
    a3 -- third byte array, size:a3_len
    a3_len -- the length of `a4`
    a4 -- fourth byte array, size:a4_len
    a4_len -- the length of `a4`
    """
    ptr_out = ffi.from_buffer(out)
    ptr_a1 = ffi.from_buffer(a1)
    ptr_a2 = ffi.from_buffer(a2)
    ptr_a3 = ffi.from_buffer(a3)
    ptr_a4 = ffi.from_buffer(a4)
    lib.ecc_concat4(
        ptr_out,
        ptr_a1,
        a1_len,
        ptr_a2,
        a2_len,
        ptr_a3,
        a3_len,
        ptr_a4,
        a4_len
    )
    return None


def ecc_strxor(
    out: bytearray,
    a: bytes,
    b: bytes,
    len: int
) -> None:
    """
    For byte strings a and b, ecc_strxor(a, b) returns the bitwise XOR of
    the two byte strings. For example, ecc_strxor("abc", "XYZ") == "9;9" (the
    strings in this example are ASCII literals, but ecc_strxor is defined for
    arbitrary byte strings).
    
    out -- (output) result of the operation, size:len
    a -- first byte array, size:len
    b -- second byte array, size:len
    len -- length of both `a` and `b`
    """
    ptr_out = ffi.from_buffer(out)
    ptr_a = ffi.from_buffer(a)
    ptr_b = ffi.from_buffer(b)
    lib.ecc_strxor(
        ptr_out,
        ptr_a,
        ptr_b,
        len
    )
    return None


def ecc_I2OSP(
    out: bytearray,
    x: int,
    xLen: int
) -> None:
    """
    I2OSP converts a non-negative integer to an octet string of a
    specified length.
    
    See https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
    
    out -- (output) corresponding octet string of length xLen, size:xLen
    x -- non-negative integer to be converted
    xLen -- intended length of the resulting octet string
    """
    ptr_out = ffi.from_buffer(out)
    lib.ecc_I2OSP(
        ptr_out,
        x,
        xLen
    )
    return None


def ecc_compare(
    a: bytes,
    b: bytes,
    len: int
) -> int:
    """
    Takes two pointers to unsigned numbers encoded in little-endian
    format and returns:
    
    -1 if a is less than b
    0 if a is equals to b
    1 if a is greater than b
    
    The comparison is done in constant time
    
    a -- first unsigned integer argument, size:len
    b -- second unsigned integer argument, size:len
    len -- the length of both `a` and `b`
    return the result of the comparison
    """
    ptr_a = ffi.from_buffer(a)
    ptr_b = ffi.from_buffer(b)
    fun_ret = lib.ecc_compare(
        ptr_a,
        ptr_b,
        len
    )
    return fun_ret


def ecc_is_zero(
    n: bytes,
    len: int
) -> int:
    """
    Takes a byte array and test if it contains only zeros. It runs
    in constant time.
    
    n -- the byte array, size:len
    len -- the length of `n`
    return 0 if non-zero bits are found
    """
    ptr_n = ffi.from_buffer(n)
    fun_ret = lib.ecc_is_zero(
        ptr_n,
        len
    )
    return fun_ret


# hash

ecc_hash_sha256_HASHSIZE = 32
"""
The size of a SHA-256 digest.
"""

ecc_hash_sha512_HASHSIZE = 64
"""
The size of a SHA-512 digest.
"""

def ecc_hash_sha256(
    digest: bytearray,
    input: bytes,
    input_len: int
) -> None:
    """
    Computes the SHA-256 of a given input.
    
    See https://en.wikipedia.org/wiki/SHA-2
    
    digest -- (output) the SHA-256 of the input, size:ecc_hash_sha256_HASHSIZE
    input -- the input message, size:input_len
    input_len -- the length of `input`
    """
    ptr_digest = ffi.from_buffer(digest)
    ptr_input = ffi.from_buffer(input)
    lib.ecc_hash_sha256(
        ptr_digest,
        ptr_input,
        input_len
    )
    return None


def ecc_hash_sha512(
    digest: bytearray,
    input: bytes,
    input_len: int
) -> None:
    """
    Computes the SHA-512 of a given input.
    
    See https://en.wikipedia.org/wiki/SHA-2
    
    digest -- (output) the SHA-512 of the input, size:ecc_hash_sha512_HASHSIZE
    input -- the input message, size:input_len
    input_len -- the length of `input`
    """
    ptr_digest = ffi.from_buffer(digest)
    ptr_input = ffi.from_buffer(input)
    lib.ecc_hash_sha512(
        ptr_digest,
        ptr_input,
        input_len
    )
    return None


# mac

ecc_mac_hmac_sha256_HASHSIZE = 32
"""
Size of the HMAC-SHA-256 digest.
"""

ecc_mac_hmac_sha256_KEYSIZE = 32
"""
Size of a HMAC-SHA-256 key.
"""

ecc_mac_hmac_sha512_HASHSIZE = 64
"""
Size of the HMAC-SHA-512 digest.
"""

ecc_mac_hmac_sha512_KEYSIZE = 64
"""
Size of a HMAC-SHA-512 key.
"""

def ecc_mac_hmac_sha256(
    digest: bytearray,
    text: bytes,
    text_len: int,
    key: bytes
) -> None:
    """
    Computes the HMAC-SHA-256 of the input stream.
    
    See https://datatracker.ietf.org/doc/html/rfc2104
    See https://datatracker.ietf.org/doc/html/rfc4868
    
    digest -- (output) the HMAC-SHA-256 of the input, size:ecc_mac_hmac_sha256_HASHSIZE
    text -- the input message, size:text_len
    text_len -- the length of `input`
    key -- authentication key, size:ecc_mac_hmac_sha256_KEYSIZE
    """
    ptr_digest = ffi.from_buffer(digest)
    ptr_text = ffi.from_buffer(text)
    ptr_key = ffi.from_buffer(key)
    lib.ecc_mac_hmac_sha256(
        ptr_digest,
        ptr_text,
        text_len,
        ptr_key
    )
    return None


def ecc_mac_hmac_sha512(
    digest: bytearray,
    text: bytes,
    text_len: int,
    key: bytes
) -> None:
    """
    Computes the HMAC-SHA-512 of the input stream.
    
    See https://datatracker.ietf.org/doc/html/rfc2104
    See https://datatracker.ietf.org/doc/html/rfc4868
    
    digest -- (output) the HMAC-SHA-512 of the input, size:ecc_mac_hmac_sha512_HASHSIZE
    text -- the input message, size:text_len
    text_len -- the length of `input`
    key -- authentication key, size:ecc_mac_hmac_sha512_KEYSIZE
    """
    ptr_digest = ffi.from_buffer(digest)
    ptr_text = ffi.from_buffer(text)
    ptr_key = ffi.from_buffer(key)
    lib.ecc_mac_hmac_sha512(
        ptr_digest,
        ptr_text,
        text_len,
        ptr_key
    )
    return None


# kdf

ecc_kdf_hkdf_sha256_KEYSIZE = 32
"""
Key size for HKDF-SHA-256.
"""

ecc_kdf_hkdf_sha512_KEYSIZE = 64
"""
Key size for HKDF-SHA-512.
"""

def ecc_kdf_hkdf_sha256_extract(
    prk: bytearray,
    salt: bytes,
    salt_len: int,
    ikm: bytes,
    ikm_len: int
) -> None:
    """
    Computes the HKDF-SHA-256 extract of the input using a key material.
    
    See https://datatracker.ietf.org/doc/html/rfc5869
    
    prk -- (output) a pseudorandom key, size:ecc_kdf_hkdf_sha256_KEYSIZE
    salt -- optional salt value (a non-secret random value), size:salt_len
    salt_len -- the length of `salt`
    ikm -- input keying material, size:ikm_len
    ikm_len -- the length of `ikm`
    """
    ptr_prk = ffi.from_buffer(prk)
    ptr_salt = ffi.from_buffer(salt)
    ptr_ikm = ffi.from_buffer(ikm)
    lib.ecc_kdf_hkdf_sha256_extract(
        ptr_prk,
        ptr_salt,
        salt_len,
        ptr_ikm,
        ikm_len
    )
    return None


def ecc_kdf_hkdf_sha256_expand(
    okm: bytearray,
    prk: bytes,
    info: bytes,
    info_len: int,
    len: int
) -> None:
    """
    Computes the HKDF-SHA-256 expand of the input using a key.
    
    See https://datatracker.ietf.org/doc/html/rfc5869
    
    okm -- (output) output keying material of length `len`, size:len
    prk -- a pseudorandom key, size:ecc_kdf_hkdf_sha256_KEYSIZE
    info -- optional context and application specific information, size:info_len
    info_len -- length of `info`
    len -- length of output keying material in octets, max allowed value is 8160
    """
    ptr_okm = ffi.from_buffer(okm)
    ptr_prk = ffi.from_buffer(prk)
    ptr_info = ffi.from_buffer(info)
    lib.ecc_kdf_hkdf_sha256_expand(
        ptr_okm,
        ptr_prk,
        ptr_info,
        info_len,
        len
    )
    return None


def ecc_kdf_hkdf_sha512_extract(
    prk: bytearray,
    salt: bytes,
    salt_len: int,
    ikm: bytes,
    ikm_len: int
) -> None:
    """
    Computes the HKDF-SHA-512 extract of the input using a key material.
    
    See https://datatracker.ietf.org/doc/html/rfc5869
    
    prk -- (output) a pseudorandom key, size:ecc_kdf_hkdf_sha512_KEYSIZE
    salt -- optional salt value (a non-secret random value), size:salt_len
    salt_len -- the length of `salt`
    ikm -- input keying material, size:ikm_len
    ikm_len -- the length of `ikm`
    """
    ptr_prk = ffi.from_buffer(prk)
    ptr_salt = ffi.from_buffer(salt)
    ptr_ikm = ffi.from_buffer(ikm)
    lib.ecc_kdf_hkdf_sha512_extract(
        ptr_prk,
        ptr_salt,
        salt_len,
        ptr_ikm,
        ikm_len
    )
    return None


def ecc_kdf_hkdf_sha512_expand(
    okm: bytearray,
    prk: bytes,
    info: bytes,
    info_len: int,
    len: int
) -> None:
    """
    Computes the HKDF-SHA-512 expand of the input using a key.
    
    See https://datatracker.ietf.org/doc/html/rfc5869
    
    okm -- (output) output keying material of length `len`, size:len
    prk -- a pseudorandom key, size:ecc_kdf_hkdf_sha512_KEYSIZE
    info -- optional context and application specific information, size:info_len
    info_len -- length of `info`
    len -- length of output keying material in octets, max allowed value is 16320
    """
    ptr_okm = ffi.from_buffer(okm)
    ptr_prk = ffi.from_buffer(prk)
    ptr_info = ffi.from_buffer(info)
    lib.ecc_kdf_hkdf_sha512_expand(
        ptr_okm,
        ptr_prk,
        ptr_info,
        info_len,
        len
    )
    return None


def ecc_kdf_scrypt(
    out: bytearray,
    passphrase: bytes,
    passphrase_len: int,
    salt: bytes,
    salt_len: int,
    cost: int,
    block_size: int,
    parallelization: int,
    len: int
) -> int:
    """
    See https://datatracker.ietf.org/doc/html/rfc7914
    
    out -- (output) size:len
    passphrase -- size:passphrase_len
    passphrase_len -- the length of `passphrase`
    salt -- size:salt_len
    salt_len -- the length of `salt`
    cost -- cpu/memory cost
    block_size -- block size
    parallelization -- parallelization
    len -- intended output length
    """
    ptr_out = ffi.from_buffer(out)
    ptr_passphrase = ffi.from_buffer(passphrase)
    ptr_salt = ffi.from_buffer(salt)
    fun_ret = lib.ecc_kdf_scrypt(
        ptr_out,
        ptr_passphrase,
        passphrase_len,
        ptr_salt,
        salt_len,
        cost,
        block_size,
        parallelization,
        len
    )
    return fun_ret


# ed25519

ecc_ed25519_ELEMENTSIZE = 32
"""
Size of the serialized group elements.
"""

ecc_ed25519_UNIFORMSIZE = 32
"""
Size of the input to perform the Elligator 2 map operation.
"""

ecc_ed25519_SCALARSIZE = 32
"""
Size of the scalar used in the curve operations.
"""

ecc_ed25519_NONREDUCEDSCALARSIZE = 64
"""
Size of a non reduced scalar.
"""

def ecc_ed25519_is_valid_point(
    p: bytes
) -> int:
    """
    Checks that p represents a point on the edwards25519 curve, in canonical
    form, on the main subgroup, and that the point doesn't have a small order.
    
    p -- potential point to test, size:ecc_ed25519_ELEMENTSIZE
    return 1 on success, and 0 if the checks didn't pass
    """
    ptr_p = ffi.from_buffer(p)
    fun_ret = lib.ecc_ed25519_is_valid_point(
        ptr_p
    )
    return fun_ret


def ecc_ed25519_add(
    r: bytearray,
    p: bytes,
    q: bytes
) -> int:
    """
    Adds the point p to the point q and stores the resulting point into r.
    
    r -- (output) the result, size:ecc_ed25519_ELEMENTSIZE
    p -- input point operand, size:ecc_ed25519_ELEMENTSIZE
    q -- input point operand, size:ecc_ed25519_ELEMENTSIZE
    return 0 on success, or -1 if p and/or q are not valid points
    """
    ptr_r = ffi.from_buffer(r)
    ptr_p = ffi.from_buffer(p)
    ptr_q = ffi.from_buffer(q)
    fun_ret = lib.ecc_ed25519_add(
        ptr_r,
        ptr_p,
        ptr_q
    )
    return fun_ret


def ecc_ed25519_sub(
    r: bytearray,
    p: bytes,
    q: bytes
) -> int:
    """
    Subtracts the point p to the point q and stores the resulting point into r.
    
    r -- (output) the result, size:ecc_ed25519_ELEMENTSIZE
    p -- input point operand, size:ecc_ed25519_ELEMENTSIZE
    q -- input point operand, size:ecc_ed25519_ELEMENTSIZE
    return 0 on success, or -1 if p and/or q are not valid points
    """
    ptr_r = ffi.from_buffer(r)
    ptr_p = ffi.from_buffer(p)
    ptr_q = ffi.from_buffer(q)
    fun_ret = lib.ecc_ed25519_sub(
        ptr_r,
        ptr_p,
        ptr_q
    )
    return fun_ret


def ecc_ed25519_from_uniform(
    p: bytearray,
    r: bytes
) -> None:
    """
    Maps a 32 bytes vector r to a point, and stores its compressed
    representation into p. The point is guaranteed to be on the main
    subgroup.
    
    This function directly exposes the Elligator 2 map. Uses the high
    bit to set the sign of the X coordinate, and the resulting point is
    multiplied by the cofactor.
    
    p -- (output) point in the main subgroup, size:ecc_ed25519_ELEMENTSIZE
    r -- input vector, size:ecc_ed25519_UNIFORMSIZE
    """
    ptr_p = ffi.from_buffer(p)
    ptr_r = ffi.from_buffer(r)
    lib.ecc_ed25519_from_uniform(
        ptr_p,
        ptr_r
    )
    return None


def ecc_ed25519_random(
    p: bytearray
) -> None:
    """
    Fills p with the representation of a random group element.
    
    p -- (output) random group element, size:ecc_ed25519_ELEMENTSIZE
    """
    ptr_p = ffi.from_buffer(p)
    lib.ecc_ed25519_random(
        ptr_p
    )
    return None


def ecc_ed25519_scalar_random(
    r: bytearray
) -> None:
    """
    Chose a random scalar in the [0..L[ interval, L being the order of the
    main subgroup (2^252 + 27742317777372353535851937790883648493) and fill
    r with the bytes.
    
    r -- (output) scalar, size:ecc_ed25519_SCALARSIZE
    """
    ptr_r = ffi.from_buffer(r)
    lib.ecc_ed25519_scalar_random(
        ptr_r
    )
    return None


def ecc_ed25519_scalar_invert(
    recip: bytearray,
    s: bytes
) -> int:
    """
    Computes the multiplicative inverse of s over L, and puts it into recip.
    
    recip -- (output) the result, size:ecc_ed25519_SCALARSIZE
    s -- an scalar, size:ecc_ed25519_SCALARSIZE
    return 0 on success, or -1 if s is zero
    """
    ptr_recip = ffi.from_buffer(recip)
    ptr_s = ffi.from_buffer(s)
    fun_ret = lib.ecc_ed25519_scalar_invert(
        ptr_recip,
        ptr_s
    )
    return fun_ret


def ecc_ed25519_scalar_negate(
    neg: bytearray,
    s: bytes
) -> None:
    """
    Returns neg so that s + neg = 0 (mod L).
    
    neg -- (output) the result, size:ecc_ed25519_SCALARSIZE
    s -- an scalar, size:ecc_ed25519_SCALARSIZE
    """
    ptr_neg = ffi.from_buffer(neg)
    ptr_s = ffi.from_buffer(s)
    lib.ecc_ed25519_scalar_negate(
        ptr_neg,
        ptr_s
    )
    return None


def ecc_ed25519_scalar_complement(
    comp: bytearray,
    s: bytes
) -> None:
    """
    Returns comp so that s + comp = 1 (mod L).
    
    comp -- (output) the result, size:ecc_ed25519_SCALARSIZE
    s -- an scalar, size:ecc_ed25519_SCALARSIZE
    """
    ptr_comp = ffi.from_buffer(comp)
    ptr_s = ffi.from_buffer(s)
    lib.ecc_ed25519_scalar_complement(
        ptr_comp,
        ptr_s
    )
    return None


def ecc_ed25519_scalar_add(
    z: bytearray,
    x: bytes,
    y: bytes
) -> None:
    """
    Stores x + y (mod L) into z.
    
    z -- (output) the result, size:ecc_ed25519_SCALARSIZE
    x -- input scalar operand, size:ecc_ed25519_SCALARSIZE
    y -- input scalar operand, size:ecc_ed25519_SCALARSIZE
    """
    ptr_z = ffi.from_buffer(z)
    ptr_x = ffi.from_buffer(x)
    ptr_y = ffi.from_buffer(y)
    lib.ecc_ed25519_scalar_add(
        ptr_z,
        ptr_x,
        ptr_y
    )
    return None


def ecc_ed25519_scalar_sub(
    z: bytearray,
    x: bytes,
    y: bytes
) -> None:
    """
    Stores x - y (mod L) into z.
    
    z -- (output) the result, size:ecc_ed25519_SCALARSIZE
    x -- input scalar operand, size:ecc_ed25519_SCALARSIZE
    y -- input scalar operand, size:ecc_ed25519_SCALARSIZE
    """
    ptr_z = ffi.from_buffer(z)
    ptr_x = ffi.from_buffer(x)
    ptr_y = ffi.from_buffer(y)
    lib.ecc_ed25519_scalar_sub(
        ptr_z,
        ptr_x,
        ptr_y
    )
    return None


def ecc_ed25519_scalar_mul(
    z: bytearray,
    x: bytes,
    y: bytes
) -> None:
    """
    Stores x * y (mod L) into z.
    
    z -- (output) the result, size:ecc_ed25519_SCALARSIZE
    x -- input scalar operand, size:ecc_ed25519_SCALARSIZE
    y -- input scalar operand, size:ecc_ed25519_SCALARSIZE
    """
    ptr_z = ffi.from_buffer(z)
    ptr_x = ffi.from_buffer(x)
    ptr_y = ffi.from_buffer(y)
    lib.ecc_ed25519_scalar_mul(
        ptr_z,
        ptr_x,
        ptr_y
    )
    return None


def ecc_ed25519_scalar_reduce(
    r: bytearray,
    s: bytes
) -> None:
    """
    Reduces s to s mod L and puts the bytes representing the integer
    into r where L = (2^252 + 27742317777372353535851937790883648493) is
    the order of the group.
    
    The interval `s` is sampled from should be at least 317 bits to
    ensure almost uniformity of `r` over `L`.
    
    r -- (output) the reduced scalar, size:ecc_ed25519_SCALARSIZE
    s -- the integer to reduce, size:ecc_ed25519_NONREDUCEDSCALARSIZE
    """
    ptr_r = ffi.from_buffer(r)
    ptr_s = ffi.from_buffer(s)
    lib.ecc_ed25519_scalar_reduce(
        ptr_r,
        ptr_s
    )
    return None


def ecc_ed25519_scalarmult(
    q: bytearray,
    n: bytes,
    p: bytes
) -> int:
    """
    Multiplies a point p by a valid scalar n (without clamping) and puts
    the Y coordinate of the resulting point into q.
    
    This function returns 0 on success, or -1 if n is 0 or if p is not
    on the curve, not on the main subgroup, is a point of small order,
    or is not provided in canonical form.
    
    q -- (output) the result, size:ecc_ed25519_ELEMENTSIZE
    n -- the valid input scalar, size:ecc_ed25519_SCALARSIZE
    p -- the point on the curve, size:ecc_ed25519_ELEMENTSIZE
    return 0 on success, or -1 otherwise.
    """
    ptr_q = ffi.from_buffer(q)
    ptr_n = ffi.from_buffer(n)
    ptr_p = ffi.from_buffer(p)
    fun_ret = lib.ecc_ed25519_scalarmult(
        ptr_q,
        ptr_n,
        ptr_p
    )
    return fun_ret


def ecc_ed25519_scalarmult_base(
    q: bytearray,
    n: bytes
) -> int:
    """
    Multiplies the base point (x, 4/5) by a scalar n (without clamping) and puts
    the Y coordinate of the resulting point into q.
    
    q -- (output) the result, size:ecc_ed25519_ELEMENTSIZE
    n -- the valid input scalar, size:ecc_ed25519_SCALARSIZE
    return -1 if n is 0, and 0 otherwise.
    """
    ptr_q = ffi.from_buffer(q)
    ptr_n = ffi.from_buffer(n)
    fun_ret = lib.ecc_ed25519_scalarmult_base(
        ptr_q,
        ptr_n
    )
    return fun_ret


# ristretto255

ecc_ristretto255_ELEMENTSIZE = 32
"""
Size of the serialized group elements.
"""

ecc_ristretto255_HASHSIZE = 64
"""
Size of the hash input to use on the hash to map operation.
"""

ecc_ristretto255_SCALARSIZE = 32
"""
Size of the scalar used in the curve operations.
"""

ecc_ristretto255_NONREDUCEDSCALARSIZE = 64
"""
Size of a non reduced scalar.
"""

def ecc_ristretto255_is_valid_point(
    p: bytes
) -> int:
    """
    Checks that p is a valid ristretto255-encoded element. This operation
    only checks that p is in canonical form.
    
    p -- potential point to test, size:ecc_ristretto255_ELEMENTSIZE
    return 1 on success, and 0 if the checks didn't pass.
    """
    ptr_p = ffi.from_buffer(p)
    fun_ret = lib.ecc_ristretto255_is_valid_point(
        ptr_p
    )
    return fun_ret


def ecc_ristretto255_add(
    r: bytearray,
    p: bytes,
    q: bytes
) -> int:
    """
    Adds the element represented by p to the element q and stores
    the resulting element into r.
    
    r -- (output) the result, size:ecc_ristretto255_ELEMENTSIZE
    p -- input point operand, size:ecc_ristretto255_ELEMENTSIZE
    q -- input point operand, size:ecc_ristretto255_ELEMENTSIZE
    return 0 on success, or -1 if p and/or q are not valid encoded elements
    """
    ptr_r = ffi.from_buffer(r)
    ptr_p = ffi.from_buffer(p)
    ptr_q = ffi.from_buffer(q)
    fun_ret = lib.ecc_ristretto255_add(
        ptr_r,
        ptr_p,
        ptr_q
    )
    return fun_ret


def ecc_ristretto255_sub(
    r: bytearray,
    p: bytes,
    q: bytes
) -> int:
    """
    Subtracts the element represented by p to the element q and stores
    the resulting element into r.
    
    r -- (output) the result, size:ecc_ristretto255_ELEMENTSIZE
    p -- input point operand, size:ecc_ristretto255_ELEMENTSIZE
    q -- input point operand, size:ecc_ristretto255_ELEMENTSIZE
    return 0 on success, or -1 if p and/or q are not valid encoded elements
    """
    ptr_r = ffi.from_buffer(r)
    ptr_p = ffi.from_buffer(p)
    ptr_q = ffi.from_buffer(q)
    fun_ret = lib.ecc_ristretto255_sub(
        ptr_r,
        ptr_p,
        ptr_q
    )
    return fun_ret


def ecc_ristretto255_generator(
    g: bytearray
) -> None:
    """
    
    
    g -- (output) size:ecc_ristretto255_ELEMENTSIZE
    """
    ptr_g = ffi.from_buffer(g)
    lib.ecc_ristretto255_generator(
        ptr_g
    )
    return None


def ecc_ristretto255_from_hash(
    p: bytearray,
    r: bytes
) -> None:
    """
    Maps a 64 bytes vector r (usually the output of a hash function) to
    a group element, and stores its representation into p.
    
    p -- (output) group element, size:ecc_ristretto255_ELEMENTSIZE
    r -- bytes vector hash, size:ecc_ristretto255_HASHSIZE
    """
    ptr_p = ffi.from_buffer(p)
    ptr_r = ffi.from_buffer(r)
    lib.ecc_ristretto255_from_hash(
        ptr_p,
        ptr_r
    )
    return None


def ecc_ristretto255_random(
    p: bytearray
) -> None:
    """
    Fills p with the representation of a random group element.
    
    p -- (output) random group element, size:ecc_ristretto255_ELEMENTSIZE
    """
    ptr_p = ffi.from_buffer(p)
    lib.ecc_ristretto255_random(
        ptr_p
    )
    return None


def ecc_ristretto255_scalar_random(
    r: bytearray
) -> None:
    """
    Fills r with a bytes representation of the scalar in
    the ]0..L[ interval where L is the order of the
    group (2^252 + 27742317777372353535851937790883648493).
    
    r -- (output) random scalar, size:ecc_ristretto255_SCALARSIZE
    """
    ptr_r = ffi.from_buffer(r)
    lib.ecc_ristretto255_scalar_random(
        ptr_r
    )
    return None


def ecc_ristretto255_scalar_invert(
    recip: bytearray,
    s: bytes
) -> int:
    """
    Computes the multiplicative inverse of s over L, and puts it into recip.
    
    recip -- (output) the result, size:ecc_ristretto255_SCALARSIZE
    s -- an scalar, size:ecc_ristretto255_SCALARSIZE
    return 0 on success, or -1 if s is zero
    """
    ptr_recip = ffi.from_buffer(recip)
    ptr_s = ffi.from_buffer(s)
    fun_ret = lib.ecc_ristretto255_scalar_invert(
        ptr_recip,
        ptr_s
    )
    return fun_ret


def ecc_ristretto255_scalar_negate(
    neg: bytearray,
    s: bytes
) -> None:
    """
    Returns neg so that s + neg = 0 (mod L).
    
    neg -- (output) the result, size:ecc_ristretto255_SCALARSIZE
    s -- an scalar, size:ecc_ristretto255_SCALARSIZE
    """
    ptr_neg = ffi.from_buffer(neg)
    ptr_s = ffi.from_buffer(s)
    lib.ecc_ristretto255_scalar_negate(
        ptr_neg,
        ptr_s
    )
    return None


def ecc_ristretto255_scalar_complement(
    comp: bytearray,
    s: bytes
) -> None:
    """
    Returns comp so that s + comp = 1 (mod L).
    
    comp -- (output) the result, size:ecc_ristretto255_SCALARSIZE
    s -- an scalar, size:ecc_ristretto255_SCALARSIZE
    """
    ptr_comp = ffi.from_buffer(comp)
    ptr_s = ffi.from_buffer(s)
    lib.ecc_ristretto255_scalar_complement(
        ptr_comp,
        ptr_s
    )
    return None


def ecc_ristretto255_scalar_add(
    z: bytearray,
    x: bytes,
    y: bytes
) -> None:
    """
    Stores x + y (mod L) into z.
    
    z -- (output) the result, size:ecc_ristretto255_SCALARSIZE
    x -- input scalar operand, size:ecc_ristretto255_SCALARSIZE
    y -- input scalar operand, size:ecc_ristretto255_SCALARSIZE
    """
    ptr_z = ffi.from_buffer(z)
    ptr_x = ffi.from_buffer(x)
    ptr_y = ffi.from_buffer(y)
    lib.ecc_ristretto255_scalar_add(
        ptr_z,
        ptr_x,
        ptr_y
    )
    return None


def ecc_ristretto255_scalar_sub(
    z: bytearray,
    x: bytes,
    y: bytes
) -> None:
    """
    Stores x - y (mod L) into z.
    
    z -- (output) the result, size:ecc_ristretto255_SCALARSIZE
    x -- input scalar operand, size:ecc_ristretto255_SCALARSIZE
    y -- input scalar operand, size:ecc_ristretto255_SCALARSIZE
    """
    ptr_z = ffi.from_buffer(z)
    ptr_x = ffi.from_buffer(x)
    ptr_y = ffi.from_buffer(y)
    lib.ecc_ristretto255_scalar_sub(
        ptr_z,
        ptr_x,
        ptr_y
    )
    return None


def ecc_ristretto255_scalar_mul(
    z: bytearray,
    x: bytes,
    y: bytes
) -> None:
    """
    Stores x * y (mod L) into z.
    
    z -- (output) the result, size:ecc_ristretto255_SCALARSIZE
    x -- input scalar operand, size:ecc_ristretto255_SCALARSIZE
    y -- input scalar operand, size:ecc_ristretto255_SCALARSIZE
    """
    ptr_z = ffi.from_buffer(z)
    ptr_x = ffi.from_buffer(x)
    ptr_y = ffi.from_buffer(y)
    lib.ecc_ristretto255_scalar_mul(
        ptr_z,
        ptr_x,
        ptr_y
    )
    return None


def ecc_ristretto255_scalar_reduce(
    r: bytearray,
    s: bytes
) -> None:
    """
    Reduces s to s mod L and puts the bytes integer into r where
    L = 2^252 + 27742317777372353535851937790883648493 is the order
    of the group.
    
    The interval `s` is sampled from should be at least 317 bits to
    ensure almost uniformity of `r` over `L`.
    
    r -- (output) the reduced scalar, size:ecc_ristretto255_SCALARSIZE
    s -- the integer to reduce, size:ecc_ristretto255_NONREDUCEDSCALARSIZE
    """
    ptr_r = ffi.from_buffer(r)
    ptr_s = ffi.from_buffer(s)
    lib.ecc_ristretto255_scalar_reduce(
        ptr_r,
        ptr_s
    )
    return None


def ecc_ristretto255_scalarmult(
    q: bytearray,
    n: bytes,
    p: bytes
) -> int:
    """
    Multiplies an element represented by p by a valid scalar n
    and puts the resulting element into q.
    
    q -- (output) the result, size:ecc_ristretto255_ELEMENTSIZE
    n -- the valid input scalar, size:ecc_ristretto255_SCALARSIZE
    p -- the point on the curve, size:ecc_ristretto255_ELEMENTSIZE
    return 0 on success, or -1 if q is the identity element.
    """
    ptr_q = ffi.from_buffer(q)
    ptr_n = ffi.from_buffer(n)
    ptr_p = ffi.from_buffer(p)
    fun_ret = lib.ecc_ristretto255_scalarmult(
        ptr_q,
        ptr_n,
        ptr_p
    )
    return fun_ret


def ecc_ristretto255_scalarmult_base(
    q: bytearray,
    n: bytes
) -> int:
    """
    Multiplies the generator by a valid scalar n and puts the resulting
    element into q.
    
    q -- (output) the result, size:ecc_ristretto255_ELEMENTSIZE
    n -- the valid input scalar, size:ecc_ristretto255_SCALARSIZE
    return -1 if n is 0, and 0 otherwise.
    """
    ptr_q = ffi.from_buffer(q)
    ptr_n = ffi.from_buffer(n)
    fun_ret = lib.ecc_ristretto255_scalarmult_base(
        ptr_q,
        ptr_n
    )
    return fun_ret


# bls12_381

ecc_bls12_381_G1SIZE = 48
"""
Size of a an element in G1.
"""

ecc_bls12_381_G2SIZE = 96
"""
Size of an element in G2.
"""

ecc_bls12_381_SCALARSIZE = 32
"""
Size of the scalar used in the curve operations.
"""

ecc_bls12_381_FPSIZE = 48
"""
Size of an element in Fp.
"""

ecc_bls12_381_FP12SIZE = 576
"""
Size of an element in Fp12.
"""

def ecc_bls12_381_fp_random(
    ret: bytearray
) -> None:
    """
    Computes a random element of BLS12-381 Fp.
    
    ret -- (output) the result, size:ecc_bls12_381_FPSIZE
    """
    ptr_ret = ffi.from_buffer(ret)
    lib.ecc_bls12_381_fp_random(
        ptr_ret
    )
    return None


def ecc_bls12_381_fp12_one(
    ret: bytearray
) -> None:
    """
    Get the identity element of BLS12-381 Fp12.
    
    ret -- (output) the result, size:ecc_bls12_381_FP12SIZE
    """
    ptr_ret = ffi.from_buffer(ret)
    lib.ecc_bls12_381_fp12_one(
        ptr_ret
    )
    return None


def ecc_bls12_381_fp12_is_one(
    a: bytes
) -> int:
    """
    Determine if an element is the identity in BLS12-381 Fp12.
    
    a -- the input, size:ecc_bls12_381_FP12SIZE
    return 1 if the element a is the identity in BLS12-381 Fp12.
    """
    ptr_a = ffi.from_buffer(a)
    fun_ret = lib.ecc_bls12_381_fp12_is_one(
        ptr_a
    )
    return fun_ret


def ecc_bls12_381_fp12_inverse(
    ret: bytearray,
    a: bytes
) -> None:
    """
    Computes the inverse of an element in BLS12-381 Fp12.
    
    ret -- (output) the result, size:ecc_bls12_381_FP12SIZE
    a -- the input, size:ecc_bls12_381_FP12SIZE
    """
    ptr_ret = ffi.from_buffer(ret)
    ptr_a = ffi.from_buffer(a)
    lib.ecc_bls12_381_fp12_inverse(
        ptr_ret,
        ptr_a
    )
    return None


def ecc_bls12_381_fp12_sqr(
    ret: bytearray,
    a: bytes
) -> None:
    """
    Computes the square of an element in BLS12-381 Fp12.
    
    ret -- (output) the result, size:ecc_bls12_381_FP12SIZE
    a -- the input, size:ecc_bls12_381_FP12SIZE
    """
    ptr_ret = ffi.from_buffer(ret)
    ptr_a = ffi.from_buffer(a)
    lib.ecc_bls12_381_fp12_sqr(
        ptr_ret,
        ptr_a
    )
    return None


def ecc_bls12_381_fp12_mul(
    ret: bytearray,
    a: bytes,
    b: bytes
) -> None:
    """
    Perform a * b in Fp12.
    
    ret -- (output) the result, size:ecc_bls12_381_FP12SIZE
    a -- input group element, size:ecc_bls12_381_FP12SIZE
    b -- input group element, size:ecc_bls12_381_FP12SIZE
    """
    ptr_ret = ffi.from_buffer(ret)
    ptr_a = ffi.from_buffer(a)
    ptr_b = ffi.from_buffer(b)
    lib.ecc_bls12_381_fp12_mul(
        ptr_ret,
        ptr_a,
        ptr_b
    )
    return None


def ecc_bls12_381_fp12_pow(
    ret: bytearray,
    a: bytes,
    n: int
) -> None:
    """
    This is a naive implementation of an iterative exponentiation by squaring.
    
    NOTE: This method is not side-channel attack resistant on `n`, the algorithm
    leaks information about it, don't use this if `n` is a secret.
    
    ret -- (output) the result, size:ecc_bls12_381_FP12SIZE
    a -- the base, size:ecc_bls12_381_FP12SIZE
    n -- the exponent
    """
    ptr_ret = ffi.from_buffer(ret)
    ptr_a = ffi.from_buffer(a)
    lib.ecc_bls12_381_fp12_pow(
        ptr_ret,
        ptr_a,
        n
    )
    return None


def ecc_bls12_381_fp12_random(
    ret: bytearray
) -> None:
    """
    Computes a random element of BLS12-381 Fp12.
    
    ret -- (output) the result, size:ecc_bls12_381_FP12SIZE
    """
    ptr_ret = ffi.from_buffer(ret)
    lib.ecc_bls12_381_fp12_random(
        ptr_ret
    )
    return None


def ecc_bls12_381_g1_add(
    r: bytearray,
    p: bytes,
    q: bytes
) -> None:
    """
    
    
    r -- (output) size:ecc_bls12_381_G1SIZE
    p -- size:ecc_bls12_381_G1SIZE
    q -- size:ecc_bls12_381_G1SIZE
    """
    ptr_r = ffi.from_buffer(r)
    ptr_p = ffi.from_buffer(p)
    ptr_q = ffi.from_buffer(q)
    lib.ecc_bls12_381_g1_add(
        ptr_r,
        ptr_p,
        ptr_q
    )
    return None


def ecc_bls12_381_g1_negate(
    neg: bytearray,
    p: bytes
) -> None:
    """
    
    
    neg -- (output) size:ecc_bls12_381_G1SIZE
    p -- size:ecc_bls12_381_G1SIZE
    """
    ptr_neg = ffi.from_buffer(neg)
    ptr_p = ffi.from_buffer(p)
    lib.ecc_bls12_381_g1_negate(
        ptr_neg,
        ptr_p
    )
    return None


def ecc_bls12_381_g1_generator(
    g: bytearray
) -> None:
    """
    
    
    g -- (output) size:ecc_bls12_381_G1SIZE
    """
    ptr_g = ffi.from_buffer(g)
    lib.ecc_bls12_381_g1_generator(
        ptr_g
    )
    return None


def ecc_bls12_381_g1_scalarmult(
    q: bytearray,
    n: bytes,
    p: bytes
) -> None:
    """
    Multiplies an element represented by p by a valid scalar n
    and puts the resulting element into q.
    
    q -- (output) the result, size:ecc_bls12_381_G1SIZE
    n -- the valid input scalar, size:ecc_bls12_381_SCALARSIZE
    p -- the point on the curve, size:ecc_bls12_381_G1SIZE
    """
    ptr_q = ffi.from_buffer(q)
    ptr_n = ffi.from_buffer(n)
    ptr_p = ffi.from_buffer(p)
    lib.ecc_bls12_381_g1_scalarmult(
        ptr_q,
        ptr_n,
        ptr_p
    )
    return None


def ecc_bls12_381_g1_scalarmult_base(
    q: bytearray,
    n: bytes
) -> None:
    """
    Multiplies the generator by a valid scalar n and puts the resulting
    element into q.
    
    q -- (output) the result, size:ecc_bls12_381_G1SIZE
    n -- the valid input scalar, size:ecc_bls12_381_SCALARSIZE
    """
    ptr_q = ffi.from_buffer(q)
    ptr_n = ffi.from_buffer(n)
    lib.ecc_bls12_381_g1_scalarmult_base(
        ptr_q,
        ptr_n
    )
    return None


def ecc_bls12_381_g2_add(
    r: bytearray,
    p: bytes,
    q: bytes
) -> None:
    """
    
    
    r -- (output) size:ecc_bls12_381_G2SIZE
    p -- size:ecc_bls12_381_G2SIZE
    q -- size:ecc_bls12_381_G2SIZE
    """
    ptr_r = ffi.from_buffer(r)
    ptr_p = ffi.from_buffer(p)
    ptr_q = ffi.from_buffer(q)
    lib.ecc_bls12_381_g2_add(
        ptr_r,
        ptr_p,
        ptr_q
    )
    return None


def ecc_bls12_381_g2_negate(
    neg: bytearray,
    p: bytes
) -> None:
    """
    
    
    neg -- (output) size:ecc_bls12_381_G2SIZE
    p -- size:ecc_bls12_381_G2SIZE
    """
    ptr_neg = ffi.from_buffer(neg)
    ptr_p = ffi.from_buffer(p)
    lib.ecc_bls12_381_g2_negate(
        ptr_neg,
        ptr_p
    )
    return None


def ecc_bls12_381_g2_generator(
    g: bytearray
) -> None:
    """
    
    
    g -- (output) size:ecc_bls12_381_G2SIZE
    """
    ptr_g = ffi.from_buffer(g)
    lib.ecc_bls12_381_g2_generator(
        ptr_g
    )
    return None


def ecc_bls12_381_g2_scalarmult_base(
    q: bytearray,
    n: bytes
) -> None:
    """
    Multiplies the generator by a valid scalar n and puts the resulting
    element into q.
    
    q -- (output) the result, size:ecc_bls12_381_G2SIZE
    n -- the valid input scalar, size:ecc_bls12_381_SCALARSIZE
    """
    ptr_q = ffi.from_buffer(q)
    ptr_n = ffi.from_buffer(n)
    lib.ecc_bls12_381_g2_scalarmult_base(
        ptr_q,
        ptr_n
    )
    return None


def ecc_bls12_381_scalar_random(
    r: bytearray
) -> None:
    """
    Fills r with a bytes representation of an scalar.
    
    r -- (output) random scalar, size:ecc_bls12_381_SCALARSIZE
    """
    ptr_r = ffi.from_buffer(r)
    lib.ecc_bls12_381_scalar_random(
        ptr_r
    )
    return None


def ecc_bls12_381_pairing(
    ret: bytearray,
    p1_g1: bytes,
    p2_g2: bytes
) -> None:
    """
    Evaluates a pairing of BLS12-381.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-09#section-2.2
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-09#section-2.4
    
    G1 is a subgroup of E(GF(p)) of order r.
    G2 is a subgroup of E'(GF(p^2)) of order r.
    GT is a subgroup of a multiplicative group (GF(p^12))^* of order r.
    
    ret -- (output) the result of the pairing evaluation in GT, size:ecc_bls12_381_FP12SIZE
    p1_g1 -- point in G1, size:ecc_bls12_381_G1SIZE
    p2_g2 -- point in G2, size:ecc_bls12_381_G2SIZE
    """
    ptr_ret = ffi.from_buffer(ret)
    ptr_p1_g1 = ffi.from_buffer(p1_g1)
    ptr_p2_g2 = ffi.from_buffer(p2_g2)
    lib.ecc_bls12_381_pairing(
        ptr_ret,
        ptr_p1_g1,
        ptr_p2_g2
    )
    return None


def ecc_bls12_381_pairing_miller_loop(
    ret: bytearray,
    p1_g1: bytes,
    p2_g2: bytes
) -> None:
    """
    
    
    ret -- (output) size:ecc_bls12_381_FP12SIZE
    p1_g1 -- size:ecc_bls12_381_G1SIZE
    p2_g2 -- size:ecc_bls12_381_G2SIZE
    """
    ptr_ret = ffi.from_buffer(ret)
    ptr_p1_g1 = ffi.from_buffer(p1_g1)
    ptr_p2_g2 = ffi.from_buffer(p2_g2)
    lib.ecc_bls12_381_pairing_miller_loop(
        ptr_ret,
        ptr_p1_g1,
        ptr_p2_g2
    )
    return None


def ecc_bls12_381_pairing_final_exp(
    ret: bytearray,
    a: bytes
) -> None:
    """
    
    
    ret -- (output) size:ecc_bls12_381_FP12SIZE
    a -- size:ecc_bls12_381_FP12SIZE
    """
    ptr_ret = ffi.from_buffer(ret)
    ptr_a = ffi.from_buffer(a)
    lib.ecc_bls12_381_pairing_final_exp(
        ptr_ret,
        ptr_a
    )
    return None


def ecc_bls12_381_pairing_final_verify(
    a: bytes,
    b: bytes
) -> int:
    """
    Perform the verification of a pairing match. Useful if the
    inputs are raw output values from the miller loop.
    
    a -- the first argument to verify, size:ecc_bls12_381_FP12SIZE
    b -- the second argument to verify, size:ecc_bls12_381_FP12SIZE
    return 1 if it's a pairing match, else 0
    """
    ptr_a = ffi.from_buffer(a)
    ptr_b = ffi.from_buffer(b)
    fun_ret = lib.ecc_bls12_381_pairing_final_verify(
        ptr_a,
        ptr_b
    )
    return fun_ret


# h2c

ecc_h2c_expand_message_xmd_sha256_MAXSIZE = 256
"""
*
"""

ecc_h2c_expand_message_xmd_sha256_DSTMAXSIZE = 256
"""
*
"""

ecc_h2c_expand_message_xmd_sha512_MAXSIZE = 256
"""
*
"""

ecc_h2c_expand_message_xmd_sha512_DSTMAXSIZE = 256
"""
*
"""

def ecc_h2c_expand_message_xmd_sha256(
    out: bytearray,
    msg: bytes,
    msg_len: int,
    dst: bytes,
    dst_len: int,
    len: int
) -> None:
    """
    Produces a uniformly random byte string using SHA-256.
    
    In order to make this method to use only the stack, len should be
    <
    = 256.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1
    
    out -- (output) a byte string, should be at least of size `len`, size:len
    msg -- a byte string, size:msg_len
    msg_len -- the length of `msg`
    dst -- a byte string of at most 255 bytes, size:dst_len
    dst_len -- the length of `dst`, should be less or equal to 256
    len -- the length of the requested output in bytes, should be less or equal to 256
    """
    ptr_out = ffi.from_buffer(out)
    ptr_msg = ffi.from_buffer(msg)
    ptr_dst = ffi.from_buffer(dst)
    lib.ecc_h2c_expand_message_xmd_sha256(
        ptr_out,
        ptr_msg,
        msg_len,
        ptr_dst,
        dst_len,
        len
    )
    return None


def ecc_h2c_expand_message_xmd_sha512(
    out: bytearray,
    msg: bytes,
    msg_len: int,
    dst: bytes,
    dst_len: int,
    len: int
) -> None:
    """
    Produces a uniformly random byte string using SHA-512.
    
    In order to make this method to use only the stack, len should be
    <
    = 256.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1
    
    out -- (output) a byte string, should be at least of size `len`, size:len
    msg -- a byte string, size:msg_len
    msg_len -- the length of `msg`
    dst -- a byte string of at most 255 bytes, size:dst_len
    dst_len -- the length of `dst`, should be
    <
    = 256
    len -- the length of the requested output in bytes, should be
    <
    = 256
    """
    ptr_out = ffi.from_buffer(out)
    ptr_msg = ffi.from_buffer(msg)
    ptr_dst = ffi.from_buffer(dst)
    lib.ecc_h2c_expand_message_xmd_sha512(
        ptr_out,
        ptr_msg,
        msg_len,
        ptr_dst,
        dst_len,
        len
    )
    return None


# oprf

ecc_oprf_ristretto255_sha512_ELEMENTSIZE = 32
"""
Size of a serialized group element, since this is the ristretto255
curve the size is 32 bytes.
"""

ecc_oprf_ristretto255_sha512_SCALARSIZE = 32
"""
Size of a serialized scalar, since this is the ristretto255
curve the size is 32 bytes.
"""

ecc_oprf_ristretto255_sha512_PROOFSIZE = 64
"""
Size of a proof. Proof is a sequence of two scalars.
"""

ecc_oprf_ristretto255_sha512_Nh = 64
"""
Size of the protocol output in the `Finalize` operations, since
this is ristretto255 with SHA-512, the size is 64 bytes.
"""

ecc_oprf_ristretto255_sha512_MODE_BASE = 0
"""
A client and server interact to compute output = F(skS, input, info).
"""

ecc_oprf_ristretto255_sha512_MODE_VERIFIABLE = 1
"""
A client and server interact to compute output = F(skS, input, info) and
the client also receives proof that the server used skS in computing
the function.
"""

def ecc_oprf_ristretto255_sha512_Evaluate(
    evaluatedElement: bytearray,
    skS: bytes,
    blindedElement: bytes,
    info: bytes,
    infoLen: int
) -> int:
    """
    Evaluates serialized representations of blinded group elements from the
    client as inputs.
    
    This operation could fail if internally, there is an attempt to invert
    the `0` scalar.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.1.1
    
    evaluatedElement -- (output) evaluated element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    skS -- private key, size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    blindedElement -- blinded element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    info -- opaque byte string no larger than 200 bytes, size:infoLen
    infoLen -- the size of `info`
    return 0 on success, or -1 if an error
    """
    ptr_evaluatedElement = ffi.from_buffer(evaluatedElement)
    ptr_skS = ffi.from_buffer(skS)
    ptr_blindedElement = ffi.from_buffer(blindedElement)
    ptr_info = ffi.from_buffer(info)
    fun_ret = lib.ecc_oprf_ristretto255_sha512_Evaluate(
        ptr_evaluatedElement,
        ptr_skS,
        ptr_blindedElement,
        ptr_info,
        infoLen
    )
    return fun_ret


def ecc_oprf_ristretto255_sha512_VerifiableEvaluateWithScalar(
    evaluatedElement: bytearray,
    proof: bytearray,
    skS: bytes,
    blindedElement: bytes,
    info: bytes,
    infoLen: int,
    r: bytes
) -> int:
    """
    Evaluates serialized representations of blinded group elements from the
    client as inputs and produces a proof that `skS` was used in computing
    the result.
    
    This operation could fail if internally, there is an attempt to invert
    the `0` scalar.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.2.1
    
    evaluatedElement -- (output) evaluated element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    proof -- (output) size:ecc_oprf_ristretto255_sha512_PROOFSIZE
    skS -- private key, size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    blindedElement -- blinded element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    info -- opaque byte string no larger than 200 bytes, size:infoLen
    infoLen -- the size of `info`
    r -- size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    return 0 on success, or -1 if an error
    """
    ptr_evaluatedElement = ffi.from_buffer(evaluatedElement)
    ptr_proof = ffi.from_buffer(proof)
    ptr_skS = ffi.from_buffer(skS)
    ptr_blindedElement = ffi.from_buffer(blindedElement)
    ptr_info = ffi.from_buffer(info)
    ptr_r = ffi.from_buffer(r)
    fun_ret = lib.ecc_oprf_ristretto255_sha512_VerifiableEvaluateWithScalar(
        ptr_evaluatedElement,
        ptr_proof,
        ptr_skS,
        ptr_blindedElement,
        ptr_info,
        infoLen,
        ptr_r
    )
    return fun_ret


def ecc_oprf_ristretto255_sha512_VerifiableEvaluate(
    evaluatedElement: bytearray,
    proof: bytearray,
    skS: bytes,
    blindedElement: bytes,
    info: bytes,
    infoLen: int
) -> int:
    """
    Evaluates serialized representations of blinded group elements from the
    client as inputs and produces a proof that `skS` was used in computing
    the result.
    
    This operation could fail if internally, there is an attempt to invert
    the `0` scalar.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.2.1
    
    evaluatedElement -- (output) evaluated element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    proof -- (output) size:ecc_oprf_ristretto255_sha512_PROOFSIZE
    skS -- private key, size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    blindedElement -- blinded element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    info -- opaque byte string no larger than 200 bytes, size:infoLen
    infoLen -- the size of `info`
    return 0 on success, or -1 if an error
    """
    ptr_evaluatedElement = ffi.from_buffer(evaluatedElement)
    ptr_proof = ffi.from_buffer(proof)
    ptr_skS = ffi.from_buffer(skS)
    ptr_blindedElement = ffi.from_buffer(blindedElement)
    ptr_info = ffi.from_buffer(info)
    fun_ret = lib.ecc_oprf_ristretto255_sha512_VerifiableEvaluate(
        ptr_evaluatedElement,
        ptr_proof,
        ptr_skS,
        ptr_blindedElement,
        ptr_info,
        infoLen
    )
    return fun_ret


def ecc_oprf_ristretto255_sha512_GenerateProofWithScalar(
    proof: bytearray,
    k: bytes,
    A: bytes,
    B: bytes,
    C: bytes,
    D: bytes,
    r: bytes
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.2.2
    
    proof -- (output) size:ecc_oprf_ristretto255_sha512_PROOFSIZE
    k -- size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    A -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    B -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    C -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    D -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    r -- size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    """
    ptr_proof = ffi.from_buffer(proof)
    ptr_k = ffi.from_buffer(k)
    ptr_A = ffi.from_buffer(A)
    ptr_B = ffi.from_buffer(B)
    ptr_C = ffi.from_buffer(C)
    ptr_D = ffi.from_buffer(D)
    ptr_r = ffi.from_buffer(r)
    lib.ecc_oprf_ristretto255_sha512_GenerateProofWithScalar(
        ptr_proof,
        ptr_k,
        ptr_A,
        ptr_B,
        ptr_C,
        ptr_D,
        ptr_r
    )
    return None


def ecc_oprf_ristretto255_sha512_GenerateProof(
    proof: bytearray,
    k: bytes,
    A: bytes,
    B: bytes,
    C: bytes,
    D: bytes
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.2.2
    
    proof -- (output) size:ecc_oprf_ristretto255_sha512_PROOFSIZE
    k -- size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    A -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    B -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    C -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    D -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    """
    ptr_proof = ffi.from_buffer(proof)
    ptr_k = ffi.from_buffer(k)
    ptr_A = ffi.from_buffer(A)
    ptr_B = ffi.from_buffer(B)
    ptr_C = ffi.from_buffer(C)
    ptr_D = ffi.from_buffer(D)
    lib.ecc_oprf_ristretto255_sha512_GenerateProof(
        ptr_proof,
        ptr_k,
        ptr_A,
        ptr_B,
        ptr_C,
        ptr_D
    )
    return None


def ecc_oprf_ristretto255_sha512_ComputeComposites(
    M: bytearray,
    Z: bytearray,
    B: bytes,
    Cs: bytes,
    Ds: bytes,
    m: int
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.2.3
    
    M -- (output) size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    Z -- (output) size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    B -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    Cs -- size:m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    Ds -- size:m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    m -- the size of the `Cs` and `Ds` arrays
    """
    ptr_M = ffi.from_buffer(M)
    ptr_Z = ffi.from_buffer(Z)
    ptr_B = ffi.from_buffer(B)
    ptr_Cs = ffi.from_buffer(Cs)
    ptr_Ds = ffi.from_buffer(Ds)
    lib.ecc_oprf_ristretto255_sha512_ComputeComposites(
        ptr_M,
        ptr_Z,
        ptr_B,
        ptr_Cs,
        ptr_Ds,
        m
    )
    return None


def ecc_oprf_ristretto255_sha512_ComputeCompositesFast(
    M: bytearray,
    Z: bytearray,
    k: bytes,
    B: bytes,
    Cs: bytes,
    Ds: bytes,
    m: int
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.2.3
    
    M -- (output) size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    Z -- (output) size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    k -- size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    B -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    Cs -- size:m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    Ds -- size:m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    m -- the size of the `Cs` and `Ds` arrays
    """
    ptr_M = ffi.from_buffer(M)
    ptr_Z = ffi.from_buffer(Z)
    ptr_k = ffi.from_buffer(k)
    ptr_B = ffi.from_buffer(B)
    ptr_Cs = ffi.from_buffer(Cs)
    ptr_Ds = ffi.from_buffer(Ds)
    lib.ecc_oprf_ristretto255_sha512_ComputeCompositesFast(
        ptr_M,
        ptr_Z,
        ptr_k,
        ptr_B,
        ptr_Cs,
        ptr_Ds,
        m
    )
    return None


def ecc_oprf_ristretto255_sha512_BlindWithScalar(
    blindedElement: bytearray,
    input: bytes,
    inputLen: int,
    blind: bytes,
    mode: int
) -> None:
    """
    Same as calling `ecc_oprf_ristretto255_sha512_Blind` with an
    specified scalar blind.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.3.1
    
    blindedElement -- (output) blinded element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    input -- message to blind, size:inputLen
    inputLen -- length of `input`
    blind -- scalar to use in the blind operation, size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    mode -- oprf mode
    """
    ptr_blindedElement = ffi.from_buffer(blindedElement)
    ptr_input = ffi.from_buffer(input)
    ptr_blind = ffi.from_buffer(blind)
    lib.ecc_oprf_ristretto255_sha512_BlindWithScalar(
        ptr_blindedElement,
        ptr_input,
        inputLen,
        ptr_blind,
        mode
    )
    return None


def ecc_oprf_ristretto255_sha512_Blind(
    blindedElement: bytearray,
    blind: bytearray,
    input: bytes,
    inputLen: int,
    mode: int
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.3.1
    
    blindedElement -- (output) blinded element, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    blind -- (output) scalar used in the blind operation, size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    input -- message to blind, size:inputLen
    inputLen -- length of `input`
    mode -- oprf mode
    """
    ptr_blindedElement = ffi.from_buffer(blindedElement)
    ptr_blind = ffi.from_buffer(blind)
    ptr_input = ffi.from_buffer(input)
    lib.ecc_oprf_ristretto255_sha512_Blind(
        ptr_blindedElement,
        ptr_blind,
        ptr_input,
        inputLen,
        mode
    )
    return None


def ecc_oprf_ristretto255_sha512_Unblind(
    unblindedElement: bytearray,
    blind: bytes,
    evaluatedElement: bytes
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.3.1
    
    unblindedElement -- (output) size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    blind -- size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    evaluatedElement -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    """
    ptr_unblindedElement = ffi.from_buffer(unblindedElement)
    ptr_blind = ffi.from_buffer(blind)
    ptr_evaluatedElement = ffi.from_buffer(evaluatedElement)
    lib.ecc_oprf_ristretto255_sha512_Unblind(
        ptr_unblindedElement,
        ptr_blind,
        ptr_evaluatedElement
    )
    return None


def ecc_oprf_ristretto255_sha512_Finalize(
    output: bytearray,
    input: bytes,
    inputLen: int,
    blind: bytes,
    evaluatedElement: bytes,
    info: bytes,
    infoLen: int
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.3.2
    
    output -- (output) size:ecc_oprf_ristretto255_sha512_Nh
    input -- the input message, size:inputLen
    inputLen -- the length of `input`
    blind -- size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    evaluatedElement -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    info -- size:infoLen
    infoLen -- the length of `info`
    """
    ptr_output = ffi.from_buffer(output)
    ptr_input = ffi.from_buffer(input)
    ptr_blind = ffi.from_buffer(blind)
    ptr_evaluatedElement = ffi.from_buffer(evaluatedElement)
    ptr_info = ffi.from_buffer(info)
    lib.ecc_oprf_ristretto255_sha512_Finalize(
        ptr_output,
        ptr_input,
        inputLen,
        ptr_blind,
        ptr_evaluatedElement,
        ptr_info,
        infoLen
    )
    return None


def ecc_oprf_ristretto255_sha512_VerifyProof(
    A: bytes,
    B: bytes,
    C: bytes,
    D: bytes,
    proof: bytes
) -> int:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.4.1
    
    A -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    B -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    C -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    D -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    proof -- size:ecc_oprf_ristretto255_sha512_PROOFSIZE
    return on success verification returns 1, else 0.
    """
    ptr_A = ffi.from_buffer(A)
    ptr_B = ffi.from_buffer(B)
    ptr_C = ffi.from_buffer(C)
    ptr_D = ffi.from_buffer(D)
    ptr_proof = ffi.from_buffer(proof)
    fun_ret = lib.ecc_oprf_ristretto255_sha512_VerifyProof(
        ptr_A,
        ptr_B,
        ptr_C,
        ptr_D,
        ptr_proof
    )
    return fun_ret


def ecc_oprf_ristretto255_sha512_VerifiableUnblind(
    unblindedElement: bytearray,
    blind: bytes,
    evaluatedElement: bytes,
    blindedElement: bytes,
    pkS: bytes,
    proof: bytes,
    info: bytes,
    infoLen: int
) -> int:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.4.2
    
    unblindedElement -- (output) size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    blind -- size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    evaluatedElement -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    blindedElement -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    pkS -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    proof -- size:ecc_oprf_ristretto255_sha512_PROOFSIZE
    info -- size:infoLen
    infoLen -- the length of `info`
    return on success verification returns 0, else -1.
    """
    ptr_unblindedElement = ffi.from_buffer(unblindedElement)
    ptr_blind = ffi.from_buffer(blind)
    ptr_evaluatedElement = ffi.from_buffer(evaluatedElement)
    ptr_blindedElement = ffi.from_buffer(blindedElement)
    ptr_pkS = ffi.from_buffer(pkS)
    ptr_proof = ffi.from_buffer(proof)
    ptr_info = ffi.from_buffer(info)
    fun_ret = lib.ecc_oprf_ristretto255_sha512_VerifiableUnblind(
        ptr_unblindedElement,
        ptr_blind,
        ptr_evaluatedElement,
        ptr_blindedElement,
        ptr_pkS,
        ptr_proof,
        ptr_info,
        infoLen
    )
    return fun_ret


def ecc_oprf_ristretto255_sha512_VerifiableFinalize(
    output: bytearray,
    input: bytes,
    inputLen: int,
    blind: bytes,
    evaluatedElement: bytes,
    blindedElement: bytes,
    pkS: bytes,
    proof: bytes,
    info: bytes,
    infoLen: int
) -> int:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.4.3
    
    output -- (output) size:ecc_oprf_ristretto255_sha512_Nh
    input -- size:inputLen
    inputLen -- the length of `input`
    blind -- size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    evaluatedElement -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    blindedElement -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    pkS -- size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    proof -- size:ecc_oprf_ristretto255_sha512_PROOFSIZE
    info -- size:infoLen
    infoLen -- the length of `info`
    return on success verification returns 0, else -1.
    """
    ptr_output = ffi.from_buffer(output)
    ptr_input = ffi.from_buffer(input)
    ptr_blind = ffi.from_buffer(blind)
    ptr_evaluatedElement = ffi.from_buffer(evaluatedElement)
    ptr_blindedElement = ffi.from_buffer(blindedElement)
    ptr_pkS = ffi.from_buffer(pkS)
    ptr_proof = ffi.from_buffer(proof)
    ptr_info = ffi.from_buffer(info)
    fun_ret = lib.ecc_oprf_ristretto255_sha512_VerifiableFinalize(
        ptr_output,
        ptr_input,
        inputLen,
        ptr_blind,
        ptr_evaluatedElement,
        ptr_blindedElement,
        ptr_pkS,
        ptr_proof,
        ptr_info,
        infoLen
    )
    return fun_ret


def ecc_oprf_ristretto255_sha512_HashToGroupWithDST(
    out: bytearray,
    input: bytes,
    inputLen: int,
    dst: bytes,
    dstLen: int
) -> None:
    """
    Same as calling `ecc_oprf_ristretto255_sha512_HashToGroup` with an
    specified DST string.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-2.1
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-4.1
    
    out -- (output) element of the group, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    input -- input string to map, size:inputLen
    inputLen -- length of `input`
    dst -- domain separation tag (DST), size:dstLen
    dstLen -- length of `dst`
    """
    ptr_out = ffi.from_buffer(out)
    ptr_input = ffi.from_buffer(input)
    ptr_dst = ffi.from_buffer(dst)
    lib.ecc_oprf_ristretto255_sha512_HashToGroupWithDST(
        ptr_out,
        ptr_input,
        inputLen,
        ptr_dst,
        dstLen
    )
    return None


def ecc_oprf_ristretto255_sha512_HashToGroup(
    out: bytearray,
    input: bytes,
    inputLen: int,
    mode: int
) -> None:
    """
    Deterministically maps an array of bytes "x" to an element of "GG" in
    the ristretto255 curve.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-2.1
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-4.1
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-13#section-2.2.5
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3
    
    out -- (output) element of the group, size:ecc_oprf_ristretto255_sha512_ELEMENTSIZE
    input -- input string to map, size:inputLen
    inputLen -- length of `input`
    mode -- mode to build the internal DST string (modeBase=0x00, modeVerifiable=0x01)
    """
    ptr_out = ffi.from_buffer(out)
    ptr_input = ffi.from_buffer(input)
    lib.ecc_oprf_ristretto255_sha512_HashToGroup(
        ptr_out,
        ptr_input,
        inputLen,
        mode
    )
    return None


def ecc_oprf_ristretto255_sha512_HashToScalarWithDST(
    out: bytearray,
    input: bytes,
    inputLen: int,
    dst: bytes,
    dstLen: int
) -> None:
    """
    
    
    out -- (output) size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    input -- size:inputLen
    inputLen -- the length of `input`
    dst -- size:dstLen
    dstLen -- the length of `dst`
    """
    ptr_out = ffi.from_buffer(out)
    ptr_input = ffi.from_buffer(input)
    ptr_dst = ffi.from_buffer(dst)
    lib.ecc_oprf_ristretto255_sha512_HashToScalarWithDST(
        ptr_out,
        ptr_input,
        inputLen,
        ptr_dst,
        dstLen
    )
    return None


def ecc_oprf_ristretto255_sha512_HashToScalar(
    out: bytearray,
    input: bytes,
    inputLen: int,
    mode: int
) -> None:
    """
    
    
    out -- (output) size:ecc_oprf_ristretto255_sha512_SCALARSIZE
    input -- size:inputLen
    inputLen -- the length of `input`
    mode -- oprf mode
    """
    ptr_out = ffi.from_buffer(out)
    ptr_input = ffi.from_buffer(input)
    lib.ecc_oprf_ristretto255_sha512_HashToScalar(
        ptr_out,
        ptr_input,
        inputLen,
        mode
    )
    return None


# opaque

ecc_opaque_ristretto255_sha512_Nn = 32
"""
The size all random nonces used in this protocol.
"""

ecc_opaque_ristretto255_sha512_Nm = 64
"""
The output size of the "MAC=HMAC-SHA-512" function in bytes.
"""

ecc_opaque_ristretto255_sha512_Nh = 64
"""
The output size of the "Hash=SHA-512" function in bytes.
"""

ecc_opaque_ristretto255_sha512_Nx = 64
"""
The size of pseudorandom keys.
"""

ecc_opaque_ristretto255_sha512_Npk = 32
"""
The size of public keys used in the AKE.
"""

ecc_opaque_ristretto255_sha512_Nsk = 32
"""
The size of private keys used in the AKE.
"""

ecc_opaque_ristretto255_sha512_Noe = 32
"""
The size of a serialized OPRF group element.
"""

ecc_opaque_ristretto255_sha512_Nok = 32
"""
The size of an OPRF private key.
"""

ecc_opaque_ristretto255_sha512_Ne = 96
"""
Envelope size (Ne = Nn + Nm).
"""

ecc_opaque_ristretto255_sha512_IDENTITYMAXSIZE = 200
"""
*
"""

ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE = 440
"""
*
"""

ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE = 32
"""
*
"""

ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE = 64
"""
*
"""

ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE = 192
"""
*
"""

ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE = 32
"""
*
"""

ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE = 192
"""
*
"""

ecc_opaque_ristretto255_sha512_KE1SIZE = 96
"""
*
"""

ecc_opaque_ristretto255_sha512_KE2SIZE = 320
"""
*
"""

ecc_opaque_ristretto255_sha512_KE3SIZE = 64
"""
*
"""

ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE = 160
"""
*
"""

ecc_opaque_ristretto255_sha512_SERVERSTATESIZE = 128
"""
*
"""

ecc_opaque_ristretto255_sha512_MHF_IDENTITY = 0
"""
Use Identity for the Memory Hard Function (MHF).
"""

ecc_opaque_ristretto255_sha512_MHF_SCRYPT = 1
"""
Use Scrypt(32768,8,1) for the Memory Hard Function (MHF).
"""

def ecc_opaque_ristretto255_sha512_DeriveKeyPair(
    private_key: bytearray,
    public_key: bytearray,
    seed: bytes,
    seed_len: int
) -> None:
    """
    Derive a private and public key pair deterministically from a seed.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-2.1
    
    private_key -- (output) a private key, size:ecc_opaque_ristretto255_sha512_Nsk
    public_key -- (output) the associated public key, size:ecc_opaque_ristretto255_sha512_Npk
    seed -- pseudo-random byte sequence used as a seed, size:seed_len
    seed_len -- the length of `seed`
    """
    ptr_private_key = ffi.from_buffer(private_key)
    ptr_public_key = ffi.from_buffer(public_key)
    ptr_seed = ffi.from_buffer(seed)
    lib.ecc_opaque_ristretto255_sha512_DeriveKeyPair(
        ptr_private_key,
        ptr_public_key,
        ptr_seed,
        seed_len
    )
    return None


def ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
    cleartext_credentials: bytearray,
    server_public_key: bytes,
    client_public_key: bytes,
    server_identity: bytes,
    server_identity_len: int,
    client_identity: bytes,
    client_identity_len: int
) -> None:
    """
    Constructs a "CleartextCredentials" structure given application
    credential information.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-4
    
    cleartext_credentials -- (output) a CleartextCredentials structure, size:ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE
    server_public_key -- the encoded server public key for the AKE protocol, size:ecc_opaque_ristretto255_sha512_Npk
    client_public_key -- the encoded client public key for the AKE protocol, size:ecc_opaque_ristretto255_sha512_Npk
    server_identity -- the optional encoded server identity, size:server_identity_len
    server_identity_len -- the length of `server_identity`
    client_identity -- the optional encoded client identity, size:client_identity_len
    client_identity_len -- the length of `client_identity`
    """
    ptr_cleartext_credentials = ffi.from_buffer(cleartext_credentials)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_client_public_key = ffi.from_buffer(client_public_key)
    ptr_server_identity = ffi.from_buffer(server_identity)
    ptr_client_identity = ffi.from_buffer(client_identity)
    lib.ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
        ptr_cleartext_credentials,
        ptr_server_public_key,
        ptr_client_public_key,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len
    )
    return None


def ecc_opaque_ristretto255_sha512_EnvelopeStoreWithNonce(
    envelope: bytearray,
    client_public_key: bytearray,
    masking_key: bytearray,
    export_key: bytearray,
    randomized_pwd: bytes,
    server_public_key: bytes,
    server_identity: bytes,
    server_identity_len: int,
    client_identity: bytes,
    client_identity_len: int,
    nonce: bytes
) -> None:
    """
    Same as calling `ecc_opaque_ristretto255_sha512_EnvelopeStore` with an
    specified `nonce`.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-4.2
    
    envelope -- (output) size:ecc_opaque_ristretto255_sha512_Ne
    client_public_key -- (output) size:ecc_opaque_ristretto255_sha512_Npk
    masking_key -- (output) size:ecc_opaque_ristretto255_sha512_Nh
    export_key -- (output) size:ecc_opaque_ristretto255_sha512_Nh
    randomized_pwd -- size:64
    server_public_key -- size:ecc_opaque_ristretto255_sha512_Npk
    server_identity -- size:server_identity_len
    server_identity_len -- the length of `server_identity`
    client_identity -- size:client_identity_len
    client_identity_len -- the length of `client_identity`
    nonce -- size:ecc_opaque_ristretto255_sha512_Nn
    """
    ptr_envelope = ffi.from_buffer(envelope)
    ptr_client_public_key = ffi.from_buffer(client_public_key)
    ptr_masking_key = ffi.from_buffer(masking_key)
    ptr_export_key = ffi.from_buffer(export_key)
    ptr_randomized_pwd = ffi.from_buffer(randomized_pwd)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_server_identity = ffi.from_buffer(server_identity)
    ptr_client_identity = ffi.from_buffer(client_identity)
    ptr_nonce = ffi.from_buffer(nonce)
    lib.ecc_opaque_ristretto255_sha512_EnvelopeStoreWithNonce(
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
        ptr_nonce
    )
    return None


def ecc_opaque_ristretto255_sha512_EnvelopeStore(
    envelope: bytearray,
    client_public_key: bytearray,
    masking_key: bytearray,
    export_key: bytearray,
    randomized_pwd: bytes,
    server_public_key: bytes,
    server_identity: bytes,
    server_identity_len: int,
    client_identity: bytes,
    client_identity_len: int
) -> None:
    """
    Creates an "Envelope" at registration.
    
    In order to work with stack allocated memory (i.e. fixed and not dynamic
    allocation), it's necessary to add the restriction on length of the
    identities to less than 200 bytes.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-4.2
    
    envelope -- (output) size:ecc_opaque_ristretto255_sha512_Ne
    client_public_key -- (output) size:ecc_opaque_ristretto255_sha512_Npk
    masking_key -- (output) size:ecc_opaque_ristretto255_sha512_Nh
    export_key -- (output) size:ecc_opaque_ristretto255_sha512_Nh
    randomized_pwd -- size:64
    server_public_key -- size:ecc_opaque_ristretto255_sha512_Npk
    server_identity -- size:server_identity_len
    server_identity_len -- the length of `server_identity`
    client_identity -- size:client_identity_len
    client_identity_len -- the length of `client_identity`
    """
    ptr_envelope = ffi.from_buffer(envelope)
    ptr_client_public_key = ffi.from_buffer(client_public_key)
    ptr_masking_key = ffi.from_buffer(masking_key)
    ptr_export_key = ffi.from_buffer(export_key)
    ptr_randomized_pwd = ffi.from_buffer(randomized_pwd)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_server_identity = ffi.from_buffer(server_identity)
    ptr_client_identity = ffi.from_buffer(client_identity)
    lib.ecc_opaque_ristretto255_sha512_EnvelopeStore(
        ptr_envelope,
        ptr_client_public_key,
        ptr_masking_key,
        ptr_export_key,
        ptr_randomized_pwd,
        ptr_server_public_key,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len
    )
    return None


def ecc_opaque_ristretto255_sha512_EnvelopeRecover(
    client_private_key: bytearray,
    export_key: bytearray,
    randomized_pwd: bytes,
    server_public_key: bytes,
    envelope_raw: bytes,
    server_identity: bytes,
    server_identity_len: int,
    client_identity: bytes,
    client_identity_len: int
) -> int:
    """
    This functions attempts to recover the credentials from the input. On
    success returns 0, else -1.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-4.2
    
    client_private_key -- (output) size:ecc_opaque_ristretto255_sha512_Nsk
    export_key -- (output) size:ecc_opaque_ristretto255_sha512_Nh
    randomized_pwd -- size:64
    server_public_key -- size:ecc_opaque_ristretto255_sha512_Npk
    envelope_raw -- size:ecc_opaque_ristretto255_sha512_Ne
    server_identity -- size:server_identity_len
    server_identity_len -- the length of `server_identity`
    client_identity -- size:client_identity_len
    client_identity_len -- the length of `client_identity`
    return on success returns 0, else -1.
    """
    ptr_client_private_key = ffi.from_buffer(client_private_key)
    ptr_export_key = ffi.from_buffer(export_key)
    ptr_randomized_pwd = ffi.from_buffer(randomized_pwd)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_envelope_raw = ffi.from_buffer(envelope_raw)
    ptr_server_identity = ffi.from_buffer(server_identity)
    ptr_client_identity = ffi.from_buffer(client_identity)
    fun_ret = lib.ecc_opaque_ristretto255_sha512_EnvelopeRecover(
        ptr_client_private_key,
        ptr_export_key,
        ptr_randomized_pwd,
        ptr_server_public_key,
        ptr_envelope_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len
    )
    return fun_ret


def ecc_opaque_ristretto255_sha512_RecoverPublicKey(
    public_key: bytearray,
    private_key: bytes
) -> None:
    """
    Recover the public key related to the input "private_key".
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-2
    
    public_key -- (output) size:ecc_opaque_ristretto255_sha512_Npk
    private_key -- size:ecc_opaque_ristretto255_sha512_Nsk
    """
    ptr_public_key = ffi.from_buffer(public_key)
    ptr_private_key = ffi.from_buffer(private_key)
    lib.ecc_opaque_ristretto255_sha512_RecoverPublicKey(
        ptr_public_key,
        ptr_private_key
    )
    return None


def ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(
    private_key: bytearray,
    public_key: bytearray
) -> None:
    """
    Returns a randomly generated private and public key pair.
    
    This is implemented by generating a random "seed", then
    calling internally DeriveAuthKeyPair.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-2
    
    private_key -- (output) a private key, size:ecc_opaque_ristretto255_sha512_Nsk
    public_key -- (output) the associated public key, size:ecc_opaque_ristretto255_sha512_Npk
    """
    ptr_private_key = ffi.from_buffer(private_key)
    ptr_public_key = ffi.from_buffer(public_key)
    lib.ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(
        ptr_private_key,
        ptr_public_key
    )
    return None


def ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
    private_key: bytearray,
    public_key: bytearray,
    seed: bytes,
    seed_len: int
) -> None:
    """
    Derive a private and public authentication key pair deterministically
    from the input "seed".
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-4.3.1
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-2
    
    private_key -- (output) a private key, size:ecc_opaque_ristretto255_sha512_Nsk
    public_key -- (output) the associated public key, size:ecc_opaque_ristretto255_sha512_Npk
    seed -- pseudo-random byte sequence used as a seed, size:seed_len
    seed_len -- the length of `seed`
    """
    ptr_private_key = ffi.from_buffer(private_key)
    ptr_public_key = ffi.from_buffer(public_key)
    ptr_seed = ffi.from_buffer(seed)
    lib.ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
        ptr_private_key,
        ptr_public_key,
        ptr_seed,
        seed_len
    )
    return None


def ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
    request: bytearray,
    password: bytes,
    password_len: int,
    blind: bytes
) -> None:
    """
    Same as calling CreateRegistrationRequest with a specified blind.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-5.1.1.1
    
    request -- (output) a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
    password -- an opaque byte string containing the client's password, size:password_len
    password_len -- the length of `password`
    blind -- the OPRF scalar value to use, size:ecc_opaque_ristretto255_sha512_Noe
    """
    ptr_request = ffi.from_buffer(request)
    ptr_password = ffi.from_buffer(password)
    ptr_blind = ffi.from_buffer(blind)
    lib.ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
        ptr_request,
        ptr_password,
        password_len,
        ptr_blind
    )
    return None


def ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
    request: bytearray,
    blind: bytearray,
    password: bytes,
    password_len: int
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-5.1.1.1
    
    request -- (output) a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
    blind -- (output) an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Noe
    password -- an opaque byte string containing the client's password, size:password_len
    password_len -- the length of `password`
    """
    ptr_request = ffi.from_buffer(request)
    ptr_blind = ffi.from_buffer(blind)
    ptr_password = ffi.from_buffer(password)
    lib.ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
        ptr_request,
        ptr_blind,
        ptr_password,
        password_len
    )
    return None


def ecc_opaque_ristretto255_sha512_CreateRegistrationResponseWithOprfKey(
    response: bytearray,
    request: bytes,
    server_public_key: bytes,
    credential_identifier: bytes,
    credential_identifier_len: int,
    oprf_key: bytes
) -> None:
    """
    Same as calling CreateRegistrationResponse with a specific oprf_seed.
    
    In order to make this method not to use dynamic memory allocation, there is a
    limit of credential_identifier_len
    <
    = 200.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-5.1.1.2
    
    response -- (output) size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
    request -- size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
    server_public_key -- size:ecc_opaque_ristretto255_sha512_Npk
    credential_identifier -- size:credential_identifier_len
    credential_identifier_len -- the length of `credential_identifier`
    oprf_key -- size:32
    """
    ptr_response = ffi.from_buffer(response)
    ptr_request = ffi.from_buffer(request)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_credential_identifier = ffi.from_buffer(credential_identifier)
    ptr_oprf_key = ffi.from_buffer(oprf_key)
    lib.ecc_opaque_ristretto255_sha512_CreateRegistrationResponseWithOprfKey(
        ptr_response,
        ptr_request,
        ptr_server_public_key,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_key
    )
    return None


def ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
    response: bytearray,
    oprf_key: bytearray,
    request: bytes,
    server_public_key: bytes,
    credential_identifier: bytes,
    credential_identifier_len: int,
    oprf_seed: bytes
) -> None:
    """
    In order to make this method not to use dynamic memory allocation, there is a
    limit of credential_identifier_len
    <
    = 200.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-5.1.1.2
    
    response -- (output) a RegistrationResponse structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
    oprf_key -- (output) the per-client OPRF key known only to the server, size:ecc_opaque_ristretto255_sha512_Nsk
    request -- a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
    server_public_key -- the server's public key, size:ecc_opaque_ristretto255_sha512_Npk
    credential_identifier -- an identifier that uniquely represents the credential being registered, size:credential_identifier_len
    credential_identifier_len -- the length of `credential_identifier`
    oprf_seed -- the server-side seed of Nh bytes used to generate an oprf_key, size:ecc_opaque_ristretto255_sha512_Nh
    """
    ptr_response = ffi.from_buffer(response)
    ptr_oprf_key = ffi.from_buffer(oprf_key)
    ptr_request = ffi.from_buffer(request)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_credential_identifier = ffi.from_buffer(credential_identifier)
    ptr_oprf_seed = ffi.from_buffer(oprf_seed)
    lib.ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
        ptr_response,
        ptr_oprf_key,
        ptr_request,
        ptr_server_public_key,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed
    )
    return None


def ecc_opaque_ristretto255_sha512_FinalizeRequestWithNonce(
    record: bytearray,
    export_key: bytearray,
    password: bytes,
    password_len: int,
    blind: bytes,
    response: bytes,
    server_identity: bytes,
    server_identity_len: int,
    client_identity: bytes,
    client_identity_len: int,
    mhf: int,
    nonce: bytes
) -> None:
    """
    Same as calling `ecc_opaque_ristretto255_sha512_FinalizeRequest` with an
    specified `nonce`.
    
    To create the user record used for further authentication, the client
    executes the following function. Since this works in the internal key mode, the
    "client_private_key" is null.
    
    record -- (output) a RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE
    export_key -- (output) an additional client key, size:ecc_opaque_ristretto255_sha512_Nh
    password -- an opaque byte string containing the client's password, size:password_len
    password_len -- the length of `password`
    blind -- the OPRF scalar value used for blinding, size:ecc_opaque_ristretto255_sha512_Noe
    response -- a RegistrationResponse structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
    server_identity -- the optional encoded server identity, size:server_identity_len
    server_identity_len -- the length of `server_identity`
    client_identity -- the optional encoded client identity, size:client_identity_len
    client_identity_len -- the length of `client_identity`
    mhf -- the memory hard function to use
    nonce -- size:ecc_opaque_ristretto255_sha512_Nn
    """
    ptr_record = ffi.from_buffer(record)
    ptr_export_key = ffi.from_buffer(export_key)
    ptr_password = ffi.from_buffer(password)
    ptr_blind = ffi.from_buffer(blind)
    ptr_response = ffi.from_buffer(response)
    ptr_server_identity = ffi.from_buffer(server_identity)
    ptr_client_identity = ffi.from_buffer(client_identity)
    ptr_nonce = ffi.from_buffer(nonce)
    lib.ecc_opaque_ristretto255_sha512_FinalizeRequestWithNonce(
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
        ptr_nonce
    )
    return None


def ecc_opaque_ristretto255_sha512_FinalizeRequest(
    record: bytearray,
    export_key: bytearray,
    password: bytes,
    password_len: int,
    blind: bytes,
    response: bytes,
    server_identity: bytes,
    server_identity_len: int,
    client_identity: bytes,
    client_identity_len: int,
    mhf: int
) -> None:
    """
    To create the user record used for further authentication, the client
    executes the following function. Since this works in the internal key mode, the
    "client_private_key" is null.
    
    record -- (output) a RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE
    export_key -- (output) an additional client key, size:ecc_opaque_ristretto255_sha512_Nh
    password -- an opaque byte string containing the client's password, size:password_len
    password_len -- the length of `password`
    blind -- the OPRF scalar value used for blinding, size:ecc_opaque_ristretto255_sha512_Noe
    response -- a RegistrationResponse structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
    server_identity -- the optional encoded server identity, size:server_identity_len
    server_identity_len -- the length of `server_identity`
    client_identity -- the optional encoded client identity, size:client_identity_len
    client_identity_len -- the length of `client_identity`
    mhf -- the memory hard function to use
    """
    ptr_record = ffi.from_buffer(record)
    ptr_export_key = ffi.from_buffer(export_key)
    ptr_password = ffi.from_buffer(password)
    ptr_blind = ffi.from_buffer(blind)
    ptr_response = ffi.from_buffer(response)
    ptr_server_identity = ffi.from_buffer(server_identity)
    ptr_client_identity = ffi.from_buffer(client_identity)
    lib.ecc_opaque_ristretto255_sha512_FinalizeRequest(
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
        mhf
    )
    return None


def ecc_opaque_ristretto255_sha512_CreateCredentialRequestWithBlind(
    request: bytearray,
    password: bytes,
    password_len: int,
    blind: bytes
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.1.2.1
    
    request -- (output) a CredentialRequest structure, size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
    password -- an opaque byte string containing the client's password, size:password_len
    password_len -- the length of `password`
    blind -- an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Noe
    """
    ptr_request = ffi.from_buffer(request)
    ptr_password = ffi.from_buffer(password)
    ptr_blind = ffi.from_buffer(blind)
    lib.ecc_opaque_ristretto255_sha512_CreateCredentialRequestWithBlind(
        ptr_request,
        ptr_password,
        password_len,
        ptr_blind
    )
    return None


def ecc_opaque_ristretto255_sha512_CreateCredentialRequest(
    request: bytearray,
    blind: bytearray,
    password: bytes,
    password_len: int
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.1.2.1
    
    request -- (output) a CredentialRequest structure, size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
    blind -- (output) an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Noe
    password -- an opaque byte string containing the client's password, size:password_len
    password_len -- the length of `password`
    """
    ptr_request = ffi.from_buffer(request)
    ptr_blind = ffi.from_buffer(blind)
    ptr_password = ffi.from_buffer(password)
    lib.ecc_opaque_ristretto255_sha512_CreateCredentialRequest(
        ptr_request,
        ptr_blind,
        ptr_password,
        password_len
    )
    return None


def ecc_opaque_ristretto255_sha512_CreateCredentialResponseWithMasking(
    response_raw: bytearray,
    request_raw: bytes,
    server_public_key: bytes,
    record_raw: bytes,
    credential_identifier: bytes,
    credential_identifier_len: int,
    oprf_seed: bytes,
    masking_nonce: bytes
) -> None:
    """
    In order to make this method not to use dynamic memory allocation, there is a
    limit of credential_identifier_len
    <
    = 200.
    
    There are two scenarios to handle for the construction of a
    CredentialResponse object: either the record for the client exists
    (corresponding to a properly registered client), or it was never
    created (corresponding to a client that has yet to register).
    
    In the case of a record that does not exist, the server SHOULD invoke
    the CreateCredentialResponse function where the record argument is
    configured so that:
    
    - record.masking_key is set to a random byte string of length Nh, and
    - record.envelope is set to the byte string consisting only of
    zeros, of length Ne
    
    response_raw -- (output) size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
    request_raw -- size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
    server_public_key -- size:ecc_opaque_ristretto255_sha512_Npk
    record_raw -- size:ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE
    credential_identifier -- size:credential_identifier_len
    credential_identifier_len -- the length of `credential_identifier`
    oprf_seed -- size:ecc_opaque_ristretto255_sha512_Nh
    masking_nonce -- size:ecc_opaque_ristretto255_sha512_Nn
    """
    ptr_response_raw = ffi.from_buffer(response_raw)
    ptr_request_raw = ffi.from_buffer(request_raw)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_record_raw = ffi.from_buffer(record_raw)
    ptr_credential_identifier = ffi.from_buffer(credential_identifier)
    ptr_oprf_seed = ffi.from_buffer(oprf_seed)
    ptr_masking_nonce = ffi.from_buffer(masking_nonce)
    lib.ecc_opaque_ristretto255_sha512_CreateCredentialResponseWithMasking(
        ptr_response_raw,
        ptr_request_raw,
        ptr_server_public_key,
        ptr_record_raw,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed,
        ptr_masking_nonce
    )
    return None


def ecc_opaque_ristretto255_sha512_CreateCredentialResponse(
    response_raw: bytearray,
    request_raw: bytes,
    server_public_key: bytes,
    record_raw: bytes,
    credential_identifier: bytes,
    credential_identifier_len: int,
    oprf_seed: bytes
) -> None:
    """
    In order to make this method not to use dynamic memory allocation, there is a
    limit of credential_identifier_len
    <
    = 200.
    
    There are two scenarios to handle for the construction of a
    CredentialResponse object: either the record for the client exists
    (corresponding to a properly registered client), or it was never
    created (corresponding to a client that has yet to register).
    
    In the case of a record that does not exist, the server SHOULD invoke
    the CreateCredentialResponse function where the record argument is
    configured so that:
    
    - record.masking_key is set to a random byte string of length Nh, and
    - record.envelope is set to the byte string consisting only of
    zeros, of length Ne
    
    response_raw -- (output) size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
    request_raw -- size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
    server_public_key -- size:ecc_opaque_ristretto255_sha512_Npk
    record_raw -- size:ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE
    credential_identifier -- size:credential_identifier_len
    credential_identifier_len -- the length of `credential_identifier`
    oprf_seed -- size:ecc_opaque_ristretto255_sha512_Nh
    """
    ptr_response_raw = ffi.from_buffer(response_raw)
    ptr_request_raw = ffi.from_buffer(request_raw)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_record_raw = ffi.from_buffer(record_raw)
    ptr_credential_identifier = ffi.from_buffer(credential_identifier)
    ptr_oprf_seed = ffi.from_buffer(oprf_seed)
    lib.ecc_opaque_ristretto255_sha512_CreateCredentialResponse(
        ptr_response_raw,
        ptr_request_raw,
        ptr_server_public_key,
        ptr_record_raw,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed
    )
    return None


def ecc_opaque_ristretto255_sha512_RecoverCredentials(
    client_private_key: bytearray,
    server_public_key: bytearray,
    export_key: bytearray,
    password: bytes,
    password_len: int,
    blind: bytes,
    response: bytes,
    server_identity: bytes,
    server_identity_len: int,
    client_identity: bytes,
    client_identity_len: int,
    mhf: int
) -> int:
    """
    
    
    client_private_key -- (output) size:ecc_opaque_ristretto255_sha512_Nsk
    server_public_key -- (output) size:ecc_opaque_ristretto255_sha512_Npk
    export_key -- (output) size:ecc_opaque_ristretto255_sha512_Nh
    password -- size:password_len
    password_len -- the length of `password`
    blind -- size:ecc_opaque_ristretto255_sha512_Noe
    response -- size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
    server_identity -- size:server_identity_len
    server_identity_len -- the length of `server_identity`
    client_identity -- size:client_identity_len
    client_identity_len -- the length of `client_identity`
    mhf -- the memory hard function to use
    return on success returns 0, else -1.
    """
    ptr_client_private_key = ffi.from_buffer(client_private_key)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_export_key = ffi.from_buffer(export_key)
    ptr_password = ffi.from_buffer(password)
    ptr_blind = ffi.from_buffer(blind)
    ptr_response = ffi.from_buffer(response)
    ptr_server_identity = ffi.from_buffer(server_identity)
    ptr_client_identity = ffi.from_buffer(client_identity)
    fun_ret = lib.ecc_opaque_ristretto255_sha512_RecoverCredentials(
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
        mhf
    )
    return fun_ret


def ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
    out: bytearray,
    secret: bytes,
    label: bytes,
    label_len: int,
    context: bytes,
    context_len: int,
    length: int
) -> None:
    """
    
    
    out -- (output) size:length
    secret -- size:64
    label -- size:label_len
    label_len -- the length of `label`
    context -- size:context_len
    context_len -- the length of `context`
    length -- the length of the output
    """
    ptr_out = ffi.from_buffer(out)
    ptr_secret = ffi.from_buffer(secret)
    ptr_label = ffi.from_buffer(label)
    ptr_context = ffi.from_buffer(context)
    lib.ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
        ptr_out,
        ptr_secret,
        ptr_label,
        label_len,
        ptr_context,
        context_len,
        length
    )
    return None


def ecc_opaque_ristretto255_sha512_3DH_Derive_Secret(
    out: bytearray,
    secret: bytes,
    label: bytes,
    label_len: int,
    transcript_hash: bytes,
    transcript_hash_len: int
) -> None:
    """
    
    
    out -- (output) size:ecc_opaque_ristretto255_sha512_Nx
    secret -- size:64
    label -- size:label_len
    label_len -- the length of `label`
    transcript_hash -- size:transcript_hash_len
    transcript_hash_len -- the length of `transcript_hash`
    """
    ptr_out = ffi.from_buffer(out)
    ptr_secret = ffi.from_buffer(secret)
    ptr_label = ffi.from_buffer(label)
    ptr_transcript_hash = ffi.from_buffer(transcript_hash)
    lib.ecc_opaque_ristretto255_sha512_3DH_Derive_Secret(
        ptr_out,
        ptr_secret,
        ptr_label,
        label_len,
        ptr_transcript_hash,
        transcript_hash_len
    )
    return None


def ecc_opaque_ristretto255_sha512_3DH_Preamble(
    preamble: bytearray,
    preamble_len: int,
    context: bytes,
    context_len: int,
    client_identity: bytes,
    client_identity_len: int,
    client_public_key: bytes,
    ke1: bytes,
    server_identity: bytes,
    server_identity_len: int,
    server_public_key: bytes,
    ke2: bytes
) -> int:
    """
    The OPAQUE-3DH key schedule requires a preamble.
    
    OPAQUE-3DH can optionally include shared "context" information in the
    transcript, such as configuration parameters or application-specific
    info, e.g. "appXYZ-v1.2.3".
    
    preamble -- (output) the protocol transcript with identities and messages, size:preamble_len
    preamble_len -- the length of `preamble`
    context -- optional shared context information, size:context_len
    context_len -- the length of `context`
    client_identity -- the optional encoded client identity, size:client_identity_len
    client_identity_len -- the length of `client_identity`
    client_public_key -- size:ecc_opaque_ristretto255_sha512_Npk
    ke1 -- a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
    server_identity -- the optional encoded server identity, size:server_identity_len
    server_identity_len -- the length of `server_identity`
    server_public_key -- size:ecc_opaque_ristretto255_sha512_Npk
    ke2 -- a ke2 structure as defined in KE2, size:ecc_opaque_ristretto255_sha512_KE2SIZE
    return the protocol transcript with identities and messages
    """
    ptr_preamble = ffi.from_buffer(preamble)
    ptr_context = ffi.from_buffer(context)
    ptr_client_identity = ffi.from_buffer(client_identity)
    ptr_client_public_key = ffi.from_buffer(client_public_key)
    ptr_ke1 = ffi.from_buffer(ke1)
    ptr_server_identity = ffi.from_buffer(server_identity)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_ke2 = ffi.from_buffer(ke2)
    fun_ret = lib.ecc_opaque_ristretto255_sha512_3DH_Preamble(
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
        ptr_ke2
    )
    return fun_ret


def ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM(
    ikm: bytearray,
    sk1: bytes,
    pk1: bytes,
    sk2: bytes,
    pk2: bytes,
    sk3: bytes,
    pk3: bytes
) -> None:
    """
    Computes the OPAQUE-3DH shared secret derived during the key
    exchange protocol.
    
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.2.2
    
    ikm -- (output) size:96
    sk1 -- size:32
    pk1 -- size:32
    sk2 -- size:32
    pk2 -- size:32
    sk3 -- size:32
    pk3 -- size:32
    """
    ptr_ikm = ffi.from_buffer(ikm)
    ptr_sk1 = ffi.from_buffer(sk1)
    ptr_pk1 = ffi.from_buffer(pk1)
    ptr_sk2 = ffi.from_buffer(sk2)
    ptr_pk2 = ffi.from_buffer(pk2)
    ptr_sk3 = ffi.from_buffer(sk3)
    ptr_pk3 = ffi.from_buffer(pk3)
    lib.ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM(
        ptr_ikm,
        ptr_sk1,
        ptr_pk1,
        ptr_sk2,
        ptr_pk2,
        ptr_sk3,
        ptr_pk3
    )
    return None


def ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
    km2: bytearray,
    km3: bytearray,
    session_key: bytearray,
    ikm: bytes,
    ikm_len: int,
    preamble: bytes,
    preamble_len: int
) -> None:
    """
    
    
    km2 -- (output) size:64
    km3 -- (output) size:64
    session_key -- (output) size:64
    ikm -- size:ikm_len
    ikm_len -- the length of `ikm`
    preamble -- size:preamble_len
    preamble_len -- the length of `preamble`
    """
    ptr_km2 = ffi.from_buffer(km2)
    ptr_km3 = ffi.from_buffer(km3)
    ptr_session_key = ffi.from_buffer(session_key)
    ptr_ikm = ffi.from_buffer(ikm)
    ptr_preamble = ffi.from_buffer(preamble)
    lib.ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
        ptr_km2,
        ptr_km3,
        ptr_session_key,
        ptr_ikm,
        ikm_len,
        ptr_preamble,
        preamble_len
    )
    return None


def ecc_opaque_ristretto255_sha512_3DH_ClientInitWithSecrets(
    ke1: bytearray,
    state: bytearray,
    password: bytes,
    password_len: int,
    blind: bytes,
    client_nonce: bytes,
    client_secret: bytes,
    client_keyshare: bytes
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.3
    
    ke1 -- (output) a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
    state -- (input, output) a ClientState structure, size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
    password -- an opaque byte string containing the client's password, size:password_len
    password_len -- the length of `password`
    blind -- size:ecc_opaque_ristretto255_sha512_Noe
    client_nonce -- size:ecc_opaque_ristretto255_sha512_Nn
    client_secret -- size:ecc_opaque_ristretto255_sha512_Nsk
    client_keyshare -- size:ecc_opaque_ristretto255_sha512_Npk
    """
    ptr_ke1 = ffi.from_buffer(ke1)
    ptr_state = ffi.from_buffer(state)
    ptr_password = ffi.from_buffer(password)
    ptr_blind = ffi.from_buffer(blind)
    ptr_client_nonce = ffi.from_buffer(client_nonce)
    ptr_client_secret = ffi.from_buffer(client_secret)
    ptr_client_keyshare = ffi.from_buffer(client_keyshare)
    lib.ecc_opaque_ristretto255_sha512_3DH_ClientInitWithSecrets(
        ptr_ke1,
        ptr_state,
        ptr_password,
        password_len,
        ptr_blind,
        ptr_client_nonce,
        ptr_client_secret,
        ptr_client_keyshare
    )
    return None


def ecc_opaque_ristretto255_sha512_3DH_ClientInit(
    ke1: bytearray,
    state: bytearray,
    password: bytes,
    password_len: int
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.3
    
    ke1 -- (output) a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
    state -- (input, output) a ClientState structure, size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
    password -- an opaque byte string containing the client's password, size:password_len
    password_len -- the length of `password`
    """
    ptr_ke1 = ffi.from_buffer(ke1)
    ptr_state = ffi.from_buffer(state)
    ptr_password = ffi.from_buffer(password)
    lib.ecc_opaque_ristretto255_sha512_3DH_ClientInit(
        ptr_ke1,
        ptr_state,
        ptr_password,
        password_len
    )
    return None


def ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
    ke3_raw: bytearray,
    session_key: bytearray,
    export_key: bytearray,
    state_raw: bytearray,
    password: bytes,
    password_len: int,
    client_identity: bytes,
    client_identity_len: int,
    server_identity: bytes,
    server_identity_len: int,
    ke2: bytes,
    mhf: int,
    context: bytes,
    context_len: int
) -> int:
    """
    
    
    ke3_raw -- (output) a KE3 message structure, size:ecc_opaque_ristretto255_sha512_KE3SIZE
    session_key -- (output) the session's shared secret, size:64
    export_key -- (output) an additional client key, size:64
    state_raw -- (input, output) a ClientState structure, size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
    password -- an opaque byte string containing the client's password, size:password_len
    password_len -- the length of `password`
    client_identity -- the optional encoded client identity, which is set
    to client_public_key if not specified, size:client_identity_len
    client_identity_len -- the length of `client_identity`
    server_identity -- the optional encoded server identity, which is set
    to server_public_key if not specified, size:server_identity_len
    server_identity_len -- the length of `server_identity`
    ke2 -- a KE2 message structure, size:ecc_opaque_ristretto255_sha512_KE2SIZE
    mhf -- the memory hard function to use
    context -- the application specific context, size:context_len
    context_len -- the length of `context`
    return 0 if is able to recover credentials and authenticate with the server, else -1
    """
    ptr_ke3_raw = ffi.from_buffer(ke3_raw)
    ptr_session_key = ffi.from_buffer(session_key)
    ptr_export_key = ffi.from_buffer(export_key)
    ptr_state_raw = ffi.from_buffer(state_raw)
    ptr_password = ffi.from_buffer(password)
    ptr_client_identity = ffi.from_buffer(client_identity)
    ptr_server_identity = ffi.from_buffer(server_identity)
    ptr_ke2 = ffi.from_buffer(ke2)
    ptr_context = ffi.from_buffer(context)
    fun_ret = lib.ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
        ptr_ke3_raw,
        ptr_session_key,
        ptr_export_key,
        ptr_state_raw,
        ptr_password,
        password_len,
        ptr_client_identity,
        client_identity_len,
        ptr_server_identity,
        server_identity_len,
        ptr_ke2,
        mhf,
        ptr_context,
        context_len
    )
    return fun_ret


def ecc_opaque_ristretto255_sha512_3DH_StartWithSecrets(
    ke1: bytearray,
    state: bytearray,
    credential_request: bytes,
    client_nonce: bytes,
    client_secret: bytes,
    client_keyshare: bytes
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.3.1
    
    ke1 -- (output) size:ecc_opaque_ristretto255_sha512_KE1SIZE
    state -- (input, output) size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
    credential_request -- size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
    client_nonce -- size:ecc_opaque_ristretto255_sha512_Nn
    client_secret -- size:ecc_opaque_ristretto255_sha512_Nsk
    client_keyshare -- size:ecc_opaque_ristretto255_sha512_Npk
    """
    ptr_ke1 = ffi.from_buffer(ke1)
    ptr_state = ffi.from_buffer(state)
    ptr_credential_request = ffi.from_buffer(credential_request)
    ptr_client_nonce = ffi.from_buffer(client_nonce)
    ptr_client_secret = ffi.from_buffer(client_secret)
    ptr_client_keyshare = ffi.from_buffer(client_keyshare)
    lib.ecc_opaque_ristretto255_sha512_3DH_StartWithSecrets(
        ptr_ke1,
        ptr_state,
        ptr_credential_request,
        ptr_client_nonce,
        ptr_client_secret,
        ptr_client_keyshare
    )
    return None


def ecc_opaque_ristretto255_sha512_3DH_Start(
    ke1: bytearray,
    state: bytearray,
    credential_request: bytes
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.3.1
    
    ke1 -- (output) size:ecc_opaque_ristretto255_sha512_KE1SIZE
    state -- (input, output) size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
    credential_request -- size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
    """
    ptr_ke1 = ffi.from_buffer(ke1)
    ptr_state = ffi.from_buffer(state)
    ptr_credential_request = ffi.from_buffer(credential_request)
    lib.ecc_opaque_ristretto255_sha512_3DH_Start(
        ptr_ke1,
        ptr_state,
        ptr_credential_request
    )
    return None


def ecc_opaque_ristretto255_sha512_3DH_ClientFinalize(
    ke3_raw: bytearray,
    session_key: bytearray,
    state_raw: bytearray,
    client_identity: bytes,
    client_identity_len: int,
    client_private_key: bytes,
    server_identity: bytes,
    server_identity_len: int,
    server_public_key: bytes,
    ke2_raw: bytes,
    context: bytes,
    context_len: int
) -> int:
    """
    
    
    ke3_raw -- (output) size:ecc_opaque_ristretto255_sha512_KE3SIZE
    session_key -- (output) size:64
    state_raw -- (input, output) size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
    client_identity -- size:client_identity_len
    client_identity_len -- the length of `client_identity`
    client_private_key -- size:ecc_opaque_ristretto255_sha512_Nsk
    server_identity -- size:server_identity_len
    server_identity_len -- the lenght of `server_identity`
    server_public_key -- size:ecc_opaque_ristretto255_sha512_Npk
    ke2_raw -- size:ecc_opaque_ristretto255_sha512_KE2SIZE
    context -- the application specific context, size:context_len
    context_len -- the length of `context`
    return 0 if success, else -1
    """
    ptr_ke3_raw = ffi.from_buffer(ke3_raw)
    ptr_session_key = ffi.from_buffer(session_key)
    ptr_state_raw = ffi.from_buffer(state_raw)
    ptr_client_identity = ffi.from_buffer(client_identity)
    ptr_client_private_key = ffi.from_buffer(client_private_key)
    ptr_server_identity = ffi.from_buffer(server_identity)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_ke2_raw = ffi.from_buffer(ke2_raw)
    ptr_context = ffi.from_buffer(context)
    fun_ret = lib.ecc_opaque_ristretto255_sha512_3DH_ClientFinalize(
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
        context_len
    )
    return fun_ret


def ecc_opaque_ristretto255_sha512_3DH_ServerInitWithSecrets(
    ke2_raw: bytearray,
    state_raw: bytearray,
    server_identity: bytes,
    server_identity_len: int,
    server_private_key: bytes,
    server_public_key: bytes,
    client_identity: bytes,
    client_identity_len: int,
    record_raw: bytes,
    credential_identifier: bytes,
    credential_identifier_len: int,
    oprf_seed: bytes,
    ke1_raw: bytes,
    context: bytes,
    context_len: int,
    masking_nonce: bytes,
    server_nonce: bytes,
    server_secret: bytes,
    server_keyshare: bytes
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.4
    
    ke2_raw -- (output) a KE2 structure, size:ecc_opaque_ristretto255_sha512_KE2SIZE
    state_raw -- (input, output) a ServerState structure, size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
    server_identity -- the optional encoded server identity, which is set to
    server_public_key if null, size:server_identity_len
    server_identity_len -- the length of `server_identity`
    server_private_key -- the server's private key, size:ecc_opaque_ristretto255_sha512_Nsk
    server_public_key -- the server's public key, size:ecc_opaque_ristretto255_sha512_Npk
    client_identity -- the optional encoded server identity, which is set to
    client_public_key if null, size:client_identity_len
    client_identity_len -- the length of `client_identity`
    record_raw -- the client's RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE
    credential_identifier -- an identifier that uniquely represents the credential
    being registered, size:credential_identifier_len
    credential_identifier_len -- the length of `credential_identifier`
    oprf_seed -- the server-side seed of Nh bytes used to generate an oprf_key, size:ecc_opaque_ristretto255_sha512_Nh
    ke1_raw -- a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
    context -- the application specific context, size:context_len
    context_len -- the length of `context`
    masking_nonce -- size:ecc_opaque_ristretto255_sha512_Nn
    server_nonce -- size:ecc_opaque_ristretto255_sha512_Nn
    server_secret -- size:ecc_opaque_ristretto255_sha512_Nsk
    server_keyshare -- size:ecc_opaque_ristretto255_sha512_Npk
    """
    ptr_ke2_raw = ffi.from_buffer(ke2_raw)
    ptr_state_raw = ffi.from_buffer(state_raw)
    ptr_server_identity = ffi.from_buffer(server_identity)
    ptr_server_private_key = ffi.from_buffer(server_private_key)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_client_identity = ffi.from_buffer(client_identity)
    ptr_record_raw = ffi.from_buffer(record_raw)
    ptr_credential_identifier = ffi.from_buffer(credential_identifier)
    ptr_oprf_seed = ffi.from_buffer(oprf_seed)
    ptr_ke1_raw = ffi.from_buffer(ke1_raw)
    ptr_context = ffi.from_buffer(context)
    ptr_masking_nonce = ffi.from_buffer(masking_nonce)
    ptr_server_nonce = ffi.from_buffer(server_nonce)
    ptr_server_secret = ffi.from_buffer(server_secret)
    ptr_server_keyshare = ffi.from_buffer(server_keyshare)
    lib.ecc_opaque_ristretto255_sha512_3DH_ServerInitWithSecrets(
        ptr_ke2_raw,
        ptr_state_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_server_private_key,
        ptr_server_public_key,
        ptr_client_identity,
        client_identity_len,
        ptr_record_raw,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed,
        ptr_ke1_raw,
        ptr_context,
        context_len,
        ptr_masking_nonce,
        ptr_server_nonce,
        ptr_server_secret,
        ptr_server_keyshare
    )
    return None


def ecc_opaque_ristretto255_sha512_3DH_ServerInit(
    ke2_raw: bytearray,
    state_raw: bytearray,
    server_identity: bytes,
    server_identity_len: int,
    server_private_key: bytes,
    server_public_key: bytes,
    client_identity: bytes,
    client_identity_len: int,
    record_raw: bytes,
    credential_identifier: bytes,
    credential_identifier_len: int,
    oprf_seed: bytes,
    ke1_raw: bytes,
    context: bytes,
    context_len: int
) -> None:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.4
    
    ke2_raw -- (output) a KE2 structure, size:ecc_opaque_ristretto255_sha512_KE2SIZE
    state_raw -- (input, output) a ServerState structure, size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
    server_identity -- the optional encoded server identity, which is set to
    server_public_key if null, size:server_identity_len
    server_identity_len -- the length of `server_identity`
    server_private_key -- the server's private key, size:ecc_opaque_ristretto255_sha512_Nsk
    server_public_key -- the server's public key, size:ecc_opaque_ristretto255_sha512_Npk
    client_identity -- the optional encoded server identity, which is set to
    client_public_key if null, size:client_identity_len
    client_identity_len -- the length of `client_identity`
    record_raw -- the client's RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE
    credential_identifier -- an identifier that uniquely represents the credential
    being registered, size:credential_identifier_len
    credential_identifier_len -- the length of `credential_identifier`
    oprf_seed -- the server-side seed of Nh bytes used to generate an oprf_key, size:ecc_opaque_ristretto255_sha512_Nh
    ke1_raw -- a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
    context -- the application specific context, size:context_len
    context_len -- the length of `context`
    """
    ptr_ke2_raw = ffi.from_buffer(ke2_raw)
    ptr_state_raw = ffi.from_buffer(state_raw)
    ptr_server_identity = ffi.from_buffer(server_identity)
    ptr_server_private_key = ffi.from_buffer(server_private_key)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_client_identity = ffi.from_buffer(client_identity)
    ptr_record_raw = ffi.from_buffer(record_raw)
    ptr_credential_identifier = ffi.from_buffer(credential_identifier)
    ptr_oprf_seed = ffi.from_buffer(oprf_seed)
    ptr_ke1_raw = ffi.from_buffer(ke1_raw)
    ptr_context = ffi.from_buffer(context)
    lib.ecc_opaque_ristretto255_sha512_3DH_ServerInit(
        ptr_ke2_raw,
        ptr_state_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_server_private_key,
        ptr_server_public_key,
        ptr_client_identity,
        client_identity_len,
        ptr_record_raw,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed,
        ptr_ke1_raw,
        ptr_context,
        context_len
    )
    return None


def ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
    session_key: bytearray,
    state_raw: bytearray,
    ke3_raw: bytes
) -> int:
    """
    See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.4
    
    session_key -- (output) the shared session secret if and only if KE3 is valid, size:64
    state_raw -- (input, output) a ServerState structure, size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
    ke3_raw -- a KE3 structure, size:ecc_opaque_ristretto255_sha512_KE3SIZE
    return 0 if the user was authenticated, else -1
    """
    ptr_session_key = ffi.from_buffer(session_key)
    ptr_state_raw = ffi.from_buffer(state_raw)
    ptr_ke3_raw = ffi.from_buffer(ke3_raw)
    fun_ret = lib.ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
        ptr_session_key,
        ptr_state_raw,
        ptr_ke3_raw
    )
    return fun_ret


def ecc_opaque_ristretto255_sha512_3DH_ResponseWithSecrets(
    ke2_raw: bytearray,
    state_raw: bytearray,
    server_identity: bytes,
    server_identity_len: int,
    server_private_key: bytes,
    server_public_key: bytes,
    client_identity: bytes,
    client_identity_len: int,
    client_public_key: bytes,
    ke1_raw: bytes,
    credential_response_raw: bytes,
    context: bytes,
    context_len: int,
    server_nonce: bytes,
    server_secret: bytes,
    server_keyshare: bytes
) -> None:
    """
    
    
    ke2_raw -- (output) size:ecc_opaque_ristretto255_sha512_KE2SIZE
    state_raw -- (input, output) size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
    server_identity -- size:server_identity_len
    server_identity_len -- the length of `server_identity`
    server_private_key -- size:ecc_opaque_ristretto255_sha512_Nsk
    server_public_key -- size:ecc_opaque_ristretto255_sha512_Npk
    client_identity -- size:client_identity_len
    client_identity_len -- the length of `client_identity`
    client_public_key -- size:ecc_opaque_ristretto255_sha512_Npk
    ke1_raw -- size:ecc_opaque_ristretto255_sha512_KE1SIZE
    credential_response_raw -- size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
    context -- size:context_len
    context_len -- the length of `context`
    server_nonce -- size:ecc_opaque_ristretto255_sha512_Nn
    server_secret -- size:ecc_opaque_ristretto255_sha512_Nsk
    server_keyshare -- size:ecc_opaque_ristretto255_sha512_Npk
    """
    ptr_ke2_raw = ffi.from_buffer(ke2_raw)
    ptr_state_raw = ffi.from_buffer(state_raw)
    ptr_server_identity = ffi.from_buffer(server_identity)
    ptr_server_private_key = ffi.from_buffer(server_private_key)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_client_identity = ffi.from_buffer(client_identity)
    ptr_client_public_key = ffi.from_buffer(client_public_key)
    ptr_ke1_raw = ffi.from_buffer(ke1_raw)
    ptr_credential_response_raw = ffi.from_buffer(credential_response_raw)
    ptr_context = ffi.from_buffer(context)
    ptr_server_nonce = ffi.from_buffer(server_nonce)
    ptr_server_secret = ffi.from_buffer(server_secret)
    ptr_server_keyshare = ffi.from_buffer(server_keyshare)
    lib.ecc_opaque_ristretto255_sha512_3DH_ResponseWithSecrets(
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
        ptr_server_keyshare
    )
    return None


def ecc_opaque_ristretto255_sha512_3DH_Response(
    ke2_raw: bytearray,
    state_raw: bytearray,
    server_identity: bytes,
    server_identity_len: int,
    server_private_key: bytes,
    server_public_key: bytes,
    client_identity: bytes,
    client_identity_len: int,
    client_public_key: bytes,
    ke1_raw: bytes,
    credential_response_raw: bytes,
    context: bytes,
    context_len: int
) -> None:
    """
    
    
    ke2_raw -- (output) size:ecc_opaque_ristretto255_sha512_KE2SIZE
    state_raw -- (input, output) size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
    server_identity -- size:server_identity_len
    server_identity_len -- the length of `server_identity`
    server_private_key -- size:ecc_opaque_ristretto255_sha512_Nsk
    server_public_key -- size:ecc_opaque_ristretto255_sha512_Npk
    client_identity -- size:client_identity_len
    client_identity_len -- the length of `client_identity`
    client_public_key -- size:ecc_opaque_ristretto255_sha512_Npk
    ke1_raw -- size:ecc_opaque_ristretto255_sha512_KE1SIZE
    credential_response_raw -- size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
    context -- size:context_len
    context_len -- the length of `context`
    """
    ptr_ke2_raw = ffi.from_buffer(ke2_raw)
    ptr_state_raw = ffi.from_buffer(state_raw)
    ptr_server_identity = ffi.from_buffer(server_identity)
    ptr_server_private_key = ffi.from_buffer(server_private_key)
    ptr_server_public_key = ffi.from_buffer(server_public_key)
    ptr_client_identity = ffi.from_buffer(client_identity)
    ptr_client_public_key = ffi.from_buffer(client_public_key)
    ptr_ke1_raw = ffi.from_buffer(ke1_raw)
    ptr_credential_response_raw = ffi.from_buffer(credential_response_raw)
    ptr_context = ffi.from_buffer(context)
    lib.ecc_opaque_ristretto255_sha512_3DH_Response(
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
        context_len
    )
    return None


# sign

ecc_sign_ed25519_SIGNATURESIZE = 64
"""
Signature size.
"""

ecc_sign_ed25519_SEEDSIZE = 32
"""
Seed size.
"""

ecc_sign_ed25519_PUBLICKEYSIZE = 32
"""
Public key size.
"""

ecc_sign_ed25519_SECRETKEYSIZE = 64
"""
Secret key size.
"""

ecc_sign_eth_bls_PRIVATEKEYSIZE = 32
"""
Size of the signing private key (size of a scalar in BLS12-381).
"""

ecc_sign_eth_bls_PUBLICKEYSIZE = 48
"""
Size of the signing public key (size of a compressed G1 element in BLS12-381).
"""

ecc_sign_eth_bls_SIGNATURESIZE = 96
"""
Signature size (size of a compressed G2 element in BLS12-381).
"""

def ecc_sign_ed25519_Sign(
    signature: bytearray,
    message: bytes,
    message_len: int,
    sk: bytes
) -> None:
    """
    Signs the `message` whose length is `message_len` in bytes, using the
    secret key `sk`, and puts the signature into `signature`.
    
    signature -- (output) the signature, size:ecc_sign_ed25519_SIGNATURESIZE
    message -- input message, size:message_len
    message_len -- the length of `message`
    sk -- the secret key, size:ecc_sign_ed25519_SECRETKEYSIZE
    """
    ptr_signature = ffi.from_buffer(signature)
    ptr_message = ffi.from_buffer(message)
    ptr_sk = ffi.from_buffer(sk)
    lib.ecc_sign_ed25519_Sign(
        ptr_signature,
        ptr_message,
        message_len,
        ptr_sk
    )
    return None


def ecc_sign_ed25519_Verify(
    signature: bytes,
    message: bytes,
    message_len: int,
    pk: bytes
) -> int:
    """
    Verifies that `signature` is a valid signature for the `message` whose length
    is `message_len` in bytes, using the signer's public key `pk`.
    
    signature -- the signature, size:ecc_sign_ed25519_SIGNATURESIZE
    message -- input message, size:message_len
    message_len -- the length of `message`
    pk -- the public key, size:ecc_sign_ed25519_PUBLICKEYSIZE
    return -1 if the signature fails verification, or 0 on success
    """
    ptr_signature = ffi.from_buffer(signature)
    ptr_message = ffi.from_buffer(message)
    ptr_pk = ffi.from_buffer(pk)
    fun_ret = lib.ecc_sign_ed25519_Verify(
        ptr_signature,
        ptr_message,
        message_len,
        ptr_pk
    )
    return fun_ret


def ecc_sign_ed25519_KeyPair(
    pk: bytearray,
    sk: bytearray
) -> None:
    """
    Generates a random key pair of public and private keys.
    
    pk -- (output) public key, size:ecc_sign_ed25519_PUBLICKEYSIZE
    sk -- (output) private key, size:ecc_sign_ed25519_SECRETKEYSIZE
    """
    ptr_pk = ffi.from_buffer(pk)
    ptr_sk = ffi.from_buffer(sk)
    lib.ecc_sign_ed25519_KeyPair(
        ptr_pk,
        ptr_sk
    )
    return None


def ecc_sign_ed25519_SeedKeyPair(
    pk: bytearray,
    sk: bytearray,
    seed: bytes
) -> None:
    """
    Generates a random key pair of public and private keys derived
    from a `seed`.
    
    pk -- (output) public key, size:ecc_sign_ed25519_PUBLICKEYSIZE
    sk -- (output) private key, size:ecc_sign_ed25519_SECRETKEYSIZE
    seed -- seed to generate the keys, size:ecc_sign_ed25519_SEEDSIZE
    """
    ptr_pk = ffi.from_buffer(pk)
    ptr_sk = ffi.from_buffer(sk)
    ptr_seed = ffi.from_buffer(seed)
    lib.ecc_sign_ed25519_SeedKeyPair(
        ptr_pk,
        ptr_sk,
        ptr_seed
    )
    return None


def ecc_sign_ed25519_SkToSeed(
    seed: bytearray,
    sk: bytes
) -> None:
    """
    Extracts the seed from the secret key `sk` and copies it into `seed`.
    
    seed -- (output) the seed used to generate the secret key, size:ecc_sign_ed25519_SEEDSIZE
    sk -- the secret key, size:ecc_sign_ed25519_SECRETKEYSIZE
    """
    ptr_seed = ffi.from_buffer(seed)
    ptr_sk = ffi.from_buffer(sk)
    lib.ecc_sign_ed25519_SkToSeed(
        ptr_seed,
        ptr_sk
    )
    return None


def ecc_sign_ed25519_SkToPk(
    pk: bytearray,
    sk: bytes
) -> None:
    """
    Extracts the public key from the secret key `sk` and copies it into `pk`.
    
    pk -- (output) the public key, size:ecc_sign_ed25519_PUBLICKEYSIZE
    sk -- the secret key, size:ecc_sign_ed25519_SECRETKEYSIZE
    """
    ptr_pk = ffi.from_buffer(pk)
    ptr_sk = ffi.from_buffer(sk)
    lib.ecc_sign_ed25519_SkToPk(
        ptr_pk,
        ptr_sk
    )
    return None


def ecc_sign_eth_bls_KeyGen(
    sk: bytearray,
    ikm: bytes,
    ikm_len: int
) -> None:
    """
    Generates a secret key `sk` deterministically from a secret
    octet string `ikm`. The secret key is guaranteed to be nonzero.
    
    For security, `ikm` MUST be infeasible to guess, e.g., generated
    by a trusted source of randomness and be at least 32 bytes long.
    
    sk -- (output) a secret key, size:ecc_sign_eth_bls_PRIVATEKEYSIZE
    ikm -- a secret octet string, size:ikm_len
    ikm_len -- the length of `ikm`
    """
    ptr_sk = ffi.from_buffer(sk)
    ptr_ikm = ffi.from_buffer(ikm)
    lib.ecc_sign_eth_bls_KeyGen(
        ptr_sk,
        ptr_ikm,
        ikm_len
    )
    return None


def ecc_sign_eth_bls_SkToPk(
    pk: bytearray,
    sk: bytes
) -> None:
    """
    Takes a secret key `sk` and outputs the corresponding public key `pk`.
    
    pk -- (output) a public key, size:ecc_sign_eth_bls_PUBLICKEYSIZE
    sk -- the secret key, size:ecc_sign_eth_bls_PRIVATEKEYSIZE
    """
    ptr_pk = ffi.from_buffer(pk)
    ptr_sk = ffi.from_buffer(sk)
    lib.ecc_sign_eth_bls_SkToPk(
        ptr_pk,
        ptr_sk
    )
    return None


def ecc_sign_eth_bls_KeyValidate(
    pk: bytes
) -> int:
    """
    Ensures that a public key is valid.  In particular, it ensures
    that a public key represents a valid, non-identity point that
    is in the correct subgroup.
    
    pk -- a public key in the format output by SkToPk, size:ecc_sign_eth_bls_PUBLICKEYSIZE
    return 0 for valid or -1 for invalid
    """
    ptr_pk = ffi.from_buffer(pk)
    fun_ret = lib.ecc_sign_eth_bls_KeyValidate(
        ptr_pk
    )
    return fun_ret


def ecc_sign_eth_bls_Sign(
    signature: bytearray,
    sk: bytes,
    message: bytes,
    message_len: int
) -> None:
    """
    Computes a signature from sk, a secret key, and a message message
    and put the result in sig.
    
    signature -- (output) the signature, size:ecc_sign_eth_bls_SIGNATURESIZE
    sk -- the secret key, size:ecc_sign_eth_bls_PRIVATEKEYSIZE
    message -- input message, size:message_len
    message_len -- the length of `message`
    """
    ptr_signature = ffi.from_buffer(signature)
    ptr_sk = ffi.from_buffer(sk)
    ptr_message = ffi.from_buffer(message)
    lib.ecc_sign_eth_bls_Sign(
        ptr_signature,
        ptr_sk,
        ptr_message,
        message_len
    )
    return None


def ecc_sign_eth_bls_Verify(
    pk: bytes,
    message: bytes,
    message_len: int,
    signature: bytes
) -> int:
    """
    Checks that a signature is valid for the message under the public key pk.
    
    pk -- the public key, size:ecc_sign_eth_bls_PUBLICKEYSIZE
    message -- input message, size:message_len
    message_len -- the length of `message`
    signature -- the signature, size:ecc_sign_eth_bls_SIGNATURESIZE
    return 0 if valid, -1 if invalid
    """
    ptr_pk = ffi.from_buffer(pk)
    ptr_message = ffi.from_buffer(message)
    ptr_signature = ffi.from_buffer(signature)
    fun_ret = lib.ecc_sign_eth_bls_Verify(
        ptr_pk,
        ptr_message,
        message_len,
        ptr_signature
    )
    return fun_ret


def ecc_sign_eth_bls_Aggregate(
    signature: bytearray,
    signatures: bytes,
    n: int
) -> int:
    """
    Aggregates multiple signatures into one.
    
    signature -- (output) the aggregated signature that combines all inputs, size:ecc_sign_eth_bls_SIGNATURESIZE
    signatures -- array of individual signatures, size:n*ecc_sign_eth_bls_SIGNATURESIZE
    n -- amount of signatures in the array `signatures`
    return 0 if valid, -1 if invalid
    """
    ptr_signature = ffi.from_buffer(signature)
    ptr_signatures = ffi.from_buffer(signatures)
    fun_ret = lib.ecc_sign_eth_bls_Aggregate(
        ptr_signature,
        ptr_signatures,
        n
    )
    return fun_ret


def ecc_sign_eth_bls_FastAggregateVerify(
    pks: bytes,
    n: int,
    message: bytes,
    message_len: int,
    signature: bytes
) -> int:
    """
    
    
    pks -- size:n*ecc_sign_eth_bls_PUBLICKEYSIZE
    n -- the number of public keys in `pks`
    message -- size:message_len
    message_len -- the length of `message`
    signature -- size:ecc_sign_eth_bls_SIGNATURESIZE
    return 0 if valid, -1 if invalid
    """
    ptr_pks = ffi.from_buffer(pks)
    ptr_message = ffi.from_buffer(message)
    ptr_signature = ffi.from_buffer(signature)
    fun_ret = lib.ecc_sign_eth_bls_FastAggregateVerify(
        ptr_pks,
        n,
        ptr_message,
        message_len,
        ptr_signature
    )
    return fun_ret


def ecc_sign_eth_bls_AggregateVerify(
    n: int,
    pks: bytes,
    messages: bytes,
    messages_len: int,
    signature: bytes
) -> int:
    """
    Checks an aggregated signature over several (PK, message) pairs. The
    messages are concatenated and in PASCAL-encoded form [size, chars].
    
    In order to keep the API simple, the maximum length of a message is 255.
    
    n -- number of pairs
    pks -- size:n*ecc_sign_eth_bls_PUBLICKEYSIZE
    messages -- size:messages_len
    messages_len -- total length of the buffer `messages`
    signature -- size:ecc_sign_eth_bls_SIGNATURESIZE
    return 0 if valid, -1 if invalid
    """
    ptr_pks = ffi.from_buffer(pks)
    ptr_messages = ffi.from_buffer(messages)
    ptr_signature = ffi.from_buffer(signature)
    fun_ret = lib.ecc_sign_eth_bls_AggregateVerify(
        n,
        ptr_pks,
        ptr_messages,
        messages_len,
        ptr_signature
    )
    return fun_ret


# pre

ecc_pre_schema1_MESSAGESIZE = 576
"""
Size of the PRE-SCHEMA1 plaintext and ciphertext messages (size of a Fp12 element in BLS12-381).
"""

ecc_pre_schema1_SEEDSIZE = 32
"""
Size of the PRE-SCHEMA1 seed used in all operations.
"""

ecc_pre_schema1_PUBLICKEYSIZE = 48
"""
Size of the PRE-SCHEMA1 public key (size of a G1 element in BLS12-381).
"""

ecc_pre_schema1_PRIVATEKEYSIZE = 32
"""
Size of the PRE-SCHEMA1 private key (size of a scalar in BLS12-381).
"""

ecc_pre_schema1_SIGNINGPUBLICKEYSIZE = 32
"""
Size of the PRE-SCHEMA1 signing public key (ed25519 signing public key size).
"""

ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE = 64
"""
Size of the PRE-SCHEMA1 signing private key (ed25519 signing secret key size).
"""

ecc_pre_schema1_SIGNATURESIZE = 64
"""
Size of the PRE-SCHEMA1 signature (ed25519 signature size).
"""

ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE = 752
"""
Size of the whole ciphertext structure, that is the result of the simple Encrypt operation.
"""

ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE = 2096
"""
Size of the whole ciphertext structure, that is the result of the one-hop ReEncrypt operation.
"""

ecc_pre_schema1_REKEYSIZE = 816
"""
Size of the whole re-encryption key structure.
"""

def ecc_pre_schema1_MessageGen(
    m: bytearray
) -> None:
    """
    Generates a random message suitable to use in the protocol.
    
    The output can be used in other key derivation algorithms for other
    symmetric encryption protocols.
    
    m -- (output) a random plaintext message, size:ecc_pre_schema1_MESSAGESIZE
    """
    ptr_m = ffi.from_buffer(m)
    lib.ecc_pre_schema1_MessageGen(
        ptr_m
    )
    return None


def ecc_pre_schema1_DeriveKey(
    pk: bytearray,
    sk: bytearray,
    seed: bytes
) -> None:
    """
    Derive a public/private key pair deterministically
    from the input "seed".
    
    pk -- (output) public key, size:ecc_pre_schema1_PUBLICKEYSIZE
    sk -- (output) private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
    seed -- input seed to generate the key pair, size:ecc_pre_schema1_SEEDSIZE
    """
    ptr_pk = ffi.from_buffer(pk)
    ptr_sk = ffi.from_buffer(sk)
    ptr_seed = ffi.from_buffer(seed)
    lib.ecc_pre_schema1_DeriveKey(
        ptr_pk,
        ptr_sk,
        ptr_seed
    )
    return None


def ecc_pre_schema1_KeyGen(
    pk: bytearray,
    sk: bytearray
) -> None:
    """
    Generate a public/private key pair.
    
    pk -- (output) public key, size:ecc_pre_schema1_PUBLICKEYSIZE
    sk -- (output) private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
    """
    ptr_pk = ffi.from_buffer(pk)
    ptr_sk = ffi.from_buffer(sk)
    lib.ecc_pre_schema1_KeyGen(
        ptr_pk,
        ptr_sk
    )
    return None


def ecc_pre_schema1_DeriveSigningKey(
    spk: bytearray,
    ssk: bytearray,
    seed: bytes
) -> None:
    """
    Derive a signing public/private key pair deterministically
    from the input "seed".
    
    spk -- (output) signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
    ssk -- (output) signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
    seed -- input seed to generate the key pair, size:ecc_pre_schema1_SEEDSIZE
    """
    ptr_spk = ffi.from_buffer(spk)
    ptr_ssk = ffi.from_buffer(ssk)
    ptr_seed = ffi.from_buffer(seed)
    lib.ecc_pre_schema1_DeriveSigningKey(
        ptr_spk,
        ptr_ssk,
        ptr_seed
    )
    return None


def ecc_pre_schema1_SigningKeyGen(
    spk: bytearray,
    ssk: bytearray
) -> None:
    """
    Generate a signing public/private key pair.
    
    spk -- (output) signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
    ssk -- (output) signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
    """
    ptr_spk = ffi.from_buffer(spk)
    ptr_ssk = ffi.from_buffer(ssk)
    lib.ecc_pre_schema1_SigningKeyGen(
        ptr_spk,
        ptr_ssk
    )
    return None


def ecc_pre_schema1_EncryptWithSeed(
    C_j_raw: bytearray,
    m: bytes,
    pk_j: bytes,
    spk_i: bytes,
    ssk_i: bytes,
    seed: bytes
) -> None:
    """
    Encrypt a message `m` to delegatee j, given j’s public key (pk_j) and the
    sender i’s signing key pair (spk_i, ssk_i). Produces a ciphertext C_j.
    
    This is also called encryption of level 1, since it's used to encrypt to
    itself (i.e j == i), in order to have later the ciphertext re-encrypted
    by the proxy with the re-encryption key (level 2).
    
    C_j_raw -- (output) a CiphertextLevel1_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE
    m -- the plaintext message, size:ecc_pre_schema1_MESSAGESIZE
    pk_j -- delegatee's public key, size:ecc_pre_schema1_PUBLICKEYSIZE
    spk_i -- sender signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
    ssk_i -- sender signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
    seed -- seed used to generate the internal ephemeral key, size:ecc_pre_schema1_SEEDSIZE
    """
    ptr_C_j_raw = ffi.from_buffer(C_j_raw)
    ptr_m = ffi.from_buffer(m)
    ptr_pk_j = ffi.from_buffer(pk_j)
    ptr_spk_i = ffi.from_buffer(spk_i)
    ptr_ssk_i = ffi.from_buffer(ssk_i)
    ptr_seed = ffi.from_buffer(seed)
    lib.ecc_pre_schema1_EncryptWithSeed(
        ptr_C_j_raw,
        ptr_m,
        ptr_pk_j,
        ptr_spk_i,
        ptr_ssk_i,
        ptr_seed
    )
    return None


def ecc_pre_schema1_Encrypt(
    C_j_raw: bytearray,
    m: bytes,
    pk_j: bytes,
    spk_i: bytes,
    ssk_i: bytes
) -> None:
    """
    Encrypt a message `m` to delegatee j, given j’s public key (pk_j) and the
    sender i’s signing key pair (spk_i, ssk_i). Produces a ciphertext C_j.
    
    This is also called encryption of level 1, since it's used to encrypt to
    itself (i.e j == i), in order to have later the ciphertext re-encrypted
    by the proxy with the re-encryption key (level 2).
    
    C_j_raw -- (output) a CiphertextLevel1_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE
    m -- the plaintext message, size:ecc_pre_schema1_MESSAGESIZE
    pk_j -- delegatee's public key, size:ecc_pre_schema1_PUBLICKEYSIZE
    spk_i -- sender signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
    ssk_i -- sender signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
    """
    ptr_C_j_raw = ffi.from_buffer(C_j_raw)
    ptr_m = ffi.from_buffer(m)
    ptr_pk_j = ffi.from_buffer(pk_j)
    ptr_spk_i = ffi.from_buffer(spk_i)
    ptr_ssk_i = ffi.from_buffer(ssk_i)
    lib.ecc_pre_schema1_Encrypt(
        ptr_C_j_raw,
        ptr_m,
        ptr_pk_j,
        ptr_spk_i,
        ptr_ssk_i
    )
    return None


def ecc_pre_schema1_ReKeyGen(
    tk_i_j_raw: bytearray,
    sk_i: bytes,
    pk_j: bytes,
    spk_i: bytes,
    ssk_i: bytes
) -> None:
    """
    Generate a re-encryption key from user i (the delegator) to user j (the delegatee).
    
    Requires the delegator’s private key (sk_i), the delegatee’s public key (pk_j), and
    the delegator’s signing key pair (spk_i, ssk_i).
    
    tk_i_j_raw -- (output) a ReKey_t structure, size:ecc_pre_schema1_REKEYSIZE
    sk_i -- delegator’s private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
    pk_j -- delegatee’s public key, size:ecc_pre_schema1_PUBLICKEYSIZE
    spk_i -- delegator’s signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
    ssk_i -- delegator’s signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
    """
    ptr_tk_i_j_raw = ffi.from_buffer(tk_i_j_raw)
    ptr_sk_i = ffi.from_buffer(sk_i)
    ptr_pk_j = ffi.from_buffer(pk_j)
    ptr_spk_i = ffi.from_buffer(spk_i)
    ptr_ssk_i = ffi.from_buffer(ssk_i)
    lib.ecc_pre_schema1_ReKeyGen(
        ptr_tk_i_j_raw,
        ptr_sk_i,
        ptr_pk_j,
        ptr_spk_i,
        ptr_ssk_i
    )
    return None


def ecc_pre_schema1_ReEncrypt(
    C_j_raw: bytearray,
    C_i_raw: bytes,
    tk_i_j_raw: bytes,
    spk_i: bytes,
    pk_j: bytes,
    spk: bytes,
    ssk: bytes
) -> int:
    """
    Re-encrypt a ciphertext encrypted to i (C_i) into a ciphertext encrypted
    to j (C_j), given a re-encryption key (tk_i_j) and the proxy’s signing key
    pair (spk, ssk).
    
    This operation is performed by the proxy and is also called encryption of
    level 2, since it takes a ciphertext from a level 1 and re-encrypt it.
    
    It also validate the signature on the encrypted ciphertext and re-encryption key.
    
    C_j_raw -- (output) a CiphertextLevel2_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE
    C_i_raw -- a CiphertextLevel1_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE
    tk_i_j_raw -- a ReKey_t structure, size:ecc_pre_schema1_REKEYSIZE
    spk_i -- delegator’s signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
    pk_j -- delegatee’s public key, size:ecc_pre_schema1_PUBLICKEYSIZE
    spk -- proxy’s signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
    ssk -- proxy’s signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
    return 0 if all the signatures are valid, -1 if there is an error
    """
    ptr_C_j_raw = ffi.from_buffer(C_j_raw)
    ptr_C_i_raw = ffi.from_buffer(C_i_raw)
    ptr_tk_i_j_raw = ffi.from_buffer(tk_i_j_raw)
    ptr_spk_i = ffi.from_buffer(spk_i)
    ptr_pk_j = ffi.from_buffer(pk_j)
    ptr_spk = ffi.from_buffer(spk)
    ptr_ssk = ffi.from_buffer(ssk)
    fun_ret = lib.ecc_pre_schema1_ReEncrypt(
        ptr_C_j_raw,
        ptr_C_i_raw,
        ptr_tk_i_j_raw,
        ptr_spk_i,
        ptr_pk_j,
        ptr_spk,
        ptr_ssk
    )
    return fun_ret


def ecc_pre_schema1_DecryptLevel1(
    m: bytearray,
    C_i_raw: bytes,
    sk_i: bytes,
    spk_i: bytes
) -> int:
    """
    Decrypt a signed ciphertext (C_i) given the private key of the recipient
    i (sk_i). Returns the original message that was encrypted, m.
    
    This operations is usually performed by the delegator, since it encrypted
    the message just to be stored and later be re-encrypted by the proxy.
    
    It also validate the signature on the encrypted ciphertext.
    
    m -- (output) the original plaintext message, size:ecc_pre_schema1_MESSAGESIZE
    C_i_raw -- a CiphertextLevel1_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE
    sk_i -- recipient private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
    spk_i -- recipient signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
    return 0 if all the signatures are valid, -1 if there is an error
    """
    ptr_m = ffi.from_buffer(m)
    ptr_C_i_raw = ffi.from_buffer(C_i_raw)
    ptr_sk_i = ffi.from_buffer(sk_i)
    ptr_spk_i = ffi.from_buffer(spk_i)
    fun_ret = lib.ecc_pre_schema1_DecryptLevel1(
        ptr_m,
        ptr_C_i_raw,
        ptr_sk_i,
        ptr_spk_i
    )
    return fun_ret


def ecc_pre_schema1_DecryptLevel2(
    m: bytearray,
    C_j_raw: bytes,
    sk_j: bytes,
    spk: bytes
) -> int:
    """
    Decrypt a signed ciphertext (C_j) given the private key of the recipient
    j (sk_j). Returns the original message that was encrypted, m.
    
    This operations is usually performed by the delegatee, since it is the proxy
    that re-encrypt the message and send the ciphertext to the final recipient.
    
    It also validate the signature on the encrypted ciphertext.
    
    m -- (output) the original plaintext message, size:ecc_pre_schema1_MESSAGESIZE
    C_j_raw -- a CiphertextLevel2_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE
    sk_j -- recipient private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
    spk -- proxy’s signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
    return 0 if all the signatures are valid, -1 if there is an error
    """
    ptr_m = ffi.from_buffer(m)
    ptr_C_j_raw = ffi.from_buffer(C_j_raw)
    ptr_sk_j = ffi.from_buffer(sk_j)
    ptr_spk = ffi.from_buffer(spk)
    fun_ret = lib.ecc_pre_schema1_DecryptLevel2(
        ptr_m,
        ptr_C_j_raw,
        ptr_sk_j,
        ptr_spk
    )
    return fun_ret


# frost

ecc_frost_ristretto255_sha512_SCALARSIZE = 32
"""
Size of a scalar, since this is using the ristretto255
curve the size is 32 bytes.
"""

ecc_frost_ristretto255_sha512_ELEMENTSIZE = 32
"""
Size of an element, since this is using the ristretto255
curve the size is 32 bytes.
"""

ecc_frost_ristretto255_sha512_SECRETKEYSIZE = 32
"""
Size of a private key, since this is using the ristretto255
curve the size is 32 bytes, the size of an scalar.
"""

ecc_frost_ristretto255_sha512_PUBLICKEYSIZE = 32
"""
Size of a public key, since this is using the ristretto255
curve the size is 32 bytes, the size of a group element.
"""

ecc_frost_ristretto255_sha512_SIGNATURESIZE = 64
"""
Size of a schnorr signature, a pair of a scalar and an element.
"""

ecc_frost_ristretto255_sha512_POINTSIZE = 64
"""
Size of a scalar point for polynomial evaluation (x, y).
"""

ecc_frost_ristretto255_sha512_NONCEPAIRSIZE = 64
"""
Size of a nonce tuple.
"""

ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE = 64
"""
Size of a nonce commitment tuple.
"""

ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE = 66
"""
Size of a signing commitment structure.
"""

def ecc_frost_ristretto255_sha512_H1(
    h1: bytearray,
    m: bytes,
    m_len: int
) -> None:
    """
    Map arbitrary inputs to non-zero Scalar elements of the prime-order group scalar field.
    
    h1 -- (output) size:ecc_frost_ristretto255_sha512_SCALARSIZE
    m -- size:m_len
    m_len -- the length of `m`
    """
    ptr_h1 = ffi.from_buffer(h1)
    ptr_m = ffi.from_buffer(m)
    lib.ecc_frost_ristretto255_sha512_H1(
        ptr_h1,
        ptr_m,
        m_len
    )
    return None


def ecc_frost_ristretto255_sha512_H1_2(
    h1: bytearray,
    m1: bytes,
    m1_len: int,
    m2: bytes,
    m2_len: int
) -> None:
    """
    Map arbitrary inputs to non-zero Scalar elements of the prime-order group scalar field.
    
    This is a variant of H2 that folds internally all inputs in the same
    hash calculation.
    
    h1 -- (output) size:ecc_frost_ristretto255_sha512_SCALARSIZE
    m1 -- size:m1_len
    m1_len -- the length of `m1`
    m2 -- size:m2_len
    m2_len -- the length of `m2`
    """
    ptr_h1 = ffi.from_buffer(h1)
    ptr_m1 = ffi.from_buffer(m1)
    ptr_m2 = ffi.from_buffer(m2)
    lib.ecc_frost_ristretto255_sha512_H1_2(
        ptr_h1,
        ptr_m1,
        m1_len,
        ptr_m2,
        m2_len
    )
    return None


def ecc_frost_ristretto255_sha512_H2(
    h2: bytearray,
    m: bytes,
    m_len: int
) -> None:
    """
    Map arbitrary inputs to non-zero Scalar elements of the prime-order group scalar field.
    
    h2 -- (output) size:ecc_frost_ristretto255_sha512_SCALARSIZE
    m -- size:m_len
    m_len -- the length of `m`
    """
    ptr_h2 = ffi.from_buffer(h2)
    ptr_m = ffi.from_buffer(m)
    lib.ecc_frost_ristretto255_sha512_H2(
        ptr_h2,
        ptr_m,
        m_len
    )
    return None


def ecc_frost_ristretto255_sha512_H2_3(
    h2: bytearray,
    m1: bytes,
    m1_len: int,
    m2: bytes,
    m2_len: int,
    m3: bytes,
    m3_len: int
) -> None:
    """
    Map arbitrary inputs to non-zero Scalar elements of the prime-order group scalar field.
    
    This is a variant of H2 that folds internally all inputs in the same
    hash calculation.
    
    h2 -- (output) size:ecc_frost_ristretto255_sha512_SCALARSIZE
    m1 -- size:m1_len
    m1_len -- the length of `m1`
    m2 -- size:m2_len
    m2_len -- the length of `m2`
    m3 -- size:m3_len
    m3_len -- the length of `m3`
    """
    ptr_h2 = ffi.from_buffer(h2)
    ptr_m1 = ffi.from_buffer(m1)
    ptr_m2 = ffi.from_buffer(m2)
    ptr_m3 = ffi.from_buffer(m3)
    lib.ecc_frost_ristretto255_sha512_H2_3(
        ptr_h2,
        ptr_m1,
        m1_len,
        ptr_m2,
        m2_len,
        ptr_m3,
        m3_len
    )
    return None


def ecc_frost_ristretto255_sha512_H3(
    h3: bytearray,
    m: bytes,
    m_len: int
) -> None:
    """
    This is an alias for the ciphersuite hash function with
    domain separation applied.
    
    h3 -- (output) size:64
    m -- size:m_len
    m_len -- the length of `m`
    """
    ptr_h3 = ffi.from_buffer(h3)
    ptr_m = ffi.from_buffer(m)
    lib.ecc_frost_ristretto255_sha512_H3(
        ptr_h3,
        ptr_m,
        m_len
    )
    return None


def ecc_frost_ristretto255_sha512_schnorr_signature_generate(
    signature: bytearray,
    msg: bytes,
    msg_len: int,
    SK: bytes
) -> None:
    """
    Generate a single-party setting Schnorr signature.
    
    signature -- (output) signature, size:ecc_frost_ristretto255_sha512_SIGNATURESIZE
    msg -- message to be signed, size:msg_len
    msg_len -- the length of `msg`
    SK -- private key, a scalar, size:ecc_frost_ristretto255_sha512_SECRETKEYSIZE
    """
    ptr_signature = ffi.from_buffer(signature)
    ptr_msg = ffi.from_buffer(msg)
    ptr_SK = ffi.from_buffer(SK)
    lib.ecc_frost_ristretto255_sha512_schnorr_signature_generate(
        ptr_signature,
        ptr_msg,
        msg_len,
        ptr_SK
    )
    return None


def ecc_frost_ristretto255_sha512_schnorr_signature_verify(
    msg: bytes,
    msg_len: int,
    signature: bytes,
    PK: bytes
) -> int:
    """
    Verify a Schnorr signature.
    
    msg -- signed message, size:msg_len
    msg_len -- the length of `msg`
    signature -- signature, size:ecc_frost_ristretto255_sha512_SIGNATURESIZE
    PK -- public key, a group element, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
    return 1 if signature is valid, and 0 otherwise
    """
    ptr_msg = ffi.from_buffer(msg)
    ptr_signature = ffi.from_buffer(signature)
    ptr_PK = ffi.from_buffer(PK)
    fun_ret = lib.ecc_frost_ristretto255_sha512_schnorr_signature_verify(
        ptr_msg,
        msg_len,
        ptr_signature,
        ptr_PK
    )
    return fun_ret


def ecc_frost_ristretto255_sha512_polynomial_evaluate(
    value: bytearray,
    x: bytes,
    coeffs: bytes,
    coeffs_len: int
) -> None:
    """
    Evaluate a polynomial f at a particular input x, i.e., y = f(x)
    using Horner's method.
    
    value -- (output) scalar result of the polynomial evaluated at input x, size:ecc_frost_ristretto255_sha512_SCALARSIZE
    x -- input at which to evaluate the polynomial, a scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
    coeffs -- the polynomial coefficients, a list of scalars, size:coeffs_len*ecc_frost_ristretto255_sha512_SCALARSIZE
    coeffs_len -- the number of coefficients in `coeffs`
    """
    ptr_value = ffi.from_buffer(value)
    ptr_x = ffi.from_buffer(x)
    ptr_coeffs = ffi.from_buffer(coeffs)
    lib.ecc_frost_ristretto255_sha512_polynomial_evaluate(
        ptr_value,
        ptr_x,
        ptr_coeffs,
        coeffs_len
    )
    return None


def ecc_frost_ristretto255_sha512_derive_lagrange_coefficient(
    L_i: bytearray,
    x_i: bytes,
    L: bytes,
    L_len: int
) -> None:
    """
    Lagrange coefficients are used in FROST to evaluate a polynomial f at f(0),
    given a set of t other points, where f is represented as a set of coefficients.
    
    L_i -- (output) the i-th Lagrange coefficient, size:ecc_frost_ristretto255_sha512_SCALARSIZE
    x_i -- an x-coordinate contained in L, a scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
    L -- the set of x-coordinates, each a scalar, size:L_len*ecc_frost_ristretto255_sha512_SCALARSIZE
    L_len -- the number of x-coordinates in `L`
    """
    ptr_L_i = ffi.from_buffer(L_i)
    ptr_x_i = ffi.from_buffer(x_i)
    ptr_L = ffi.from_buffer(L)
    lib.ecc_frost_ristretto255_sha512_derive_lagrange_coefficient(
        ptr_L_i,
        ptr_x_i,
        ptr_L,
        L_len
    )
    return None


def ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points(
    L_i: bytearray,
    x_i: bytes,
    L: bytes,
    L_len: int
) -> None:
    """
    This is an optimization that works like `ecc_frost_ristretto255_sha512_derive_lagrange_coefficient`
    but with a set of points (x, y).
    
    L_i -- (output) the i-th Lagrange coefficient, size:ecc_frost_ristretto255_sha512_SCALARSIZE
    x_i -- an x-coordinate contained in L, a scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
    L -- the set of (x, y)-points, size:L_len*ecc_frost_ristretto255_sha512_POINTSIZE
    L_len -- the number of (x, y)-points in `L`
    """
    ptr_L_i = ffi.from_buffer(L_i)
    ptr_x_i = ffi.from_buffer(x_i)
    ptr_L = ffi.from_buffer(L)
    lib.ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points(
        ptr_L_i,
        ptr_x_i,
        ptr_L,
        L_len
    )
    return None


def ecc_frost_ristretto255_sha512_polynomial_interpolation(
    constant_term: bytearray,
    points: bytes,
    points_len: int
) -> None:
    """
    Secret sharing requires "splitting" a secret, which is represented
    as a constant term of some polynomial f of degree t. Recovering the
    constant term occurs with a set of t points using polynomial interpolation.
    
    constant_term -- (output) the constant term of f, i.e., f(0), size:ecc_frost_ristretto255_sha512_SCALARSIZE
    points -- a set of `t` points on a polynomial f, each a tuple of two scalar values representing the x and y coordinates, size:points_len*ecc_frost_ristretto255_sha512_POINTSIZE
    points_len -- the number of points in `points`
    """
    ptr_constant_term = ffi.from_buffer(constant_term)
    ptr_points = ffi.from_buffer(points)
    lib.ecc_frost_ristretto255_sha512_polynomial_interpolation(
        ptr_constant_term,
        ptr_points,
        points_len
    )
    return None


def ecc_frost_ristretto255_sha512_compute_binding_factor(
    binding_factor: bytearray,
    encoded_commitment_list: bytes,
    encoded_commitment_list_len: int,
    msg: bytes,
    msg_len: int
) -> None:
    """
    Compute the binding factor based on the signer commitment list and a message to be signed.
    
    binding_factor -- (output) a Scalar representing the binding factor, size:ecc_frost_ristretto255_sha512_SCALARSIZE
    encoded_commitment_list -- an encoded commitment list, size:encoded_commitment_list_len*ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE
    encoded_commitment_list_len -- the number of elements in `encoded_commitment_list`
    msg -- the message to be signed (sent by the Coordinator), size:msg_len
    msg_len -- the length of `msg`
    """
    ptr_binding_factor = ffi.from_buffer(binding_factor)
    ptr_encoded_commitment_list = ffi.from_buffer(encoded_commitment_list)
    ptr_msg = ffi.from_buffer(msg)
    lib.ecc_frost_ristretto255_sha512_compute_binding_factor(
        ptr_binding_factor,
        ptr_encoded_commitment_list,
        encoded_commitment_list_len,
        ptr_msg,
        msg_len
    )
    return None


def ecc_frost_ristretto255_sha512_compute_challenge(
    challenge: bytearray,
    group_commitment: bytes,
    group_public_key: bytes,
    msg: bytes,
    msg_len: int
) -> None:
    """
    Create the per-message challenge.
    
    challenge -- (output) a challenge Scalar value, size:ecc_frost_ristretto255_sha512_SCALARSIZE
    group_commitment -- an Element representing the group commitment, size:ecc_frost_ristretto255_sha512_ELEMENTSIZE
    group_public_key -- public key corresponding to the signer secret key share, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
    msg -- the message to be signed (sent by the Coordinator), size:msg_len
    msg_len -- the length of `msg`
    """
    ptr_challenge = ffi.from_buffer(challenge)
    ptr_group_commitment = ffi.from_buffer(group_commitment)
    ptr_group_public_key = ffi.from_buffer(group_public_key)
    ptr_msg = ffi.from_buffer(msg)
    lib.ecc_frost_ristretto255_sha512_compute_challenge(
        ptr_challenge,
        ptr_group_commitment,
        ptr_group_public_key,
        ptr_msg,
        msg_len
    )
    return None


def ecc_frost_ristretto255_sha512_commit_with_nonce(
    comm: bytearray,
    nonce: bytes
) -> None:
    """
    Generate a pair of public commitments corresponding to the nonce pair.
    
    comm -- (output) a nonce commitment pair, size:ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE
    nonce -- a nonce pair, size:ecc_frost_ristretto255_sha512_NONCEPAIRSIZE
    """
    ptr_comm = ffi.from_buffer(comm)
    ptr_nonce = ffi.from_buffer(nonce)
    lib.ecc_frost_ristretto255_sha512_commit_with_nonce(
        ptr_comm,
        ptr_nonce
    )
    return None


def ecc_frost_ristretto255_sha512_commit(
    nonce: bytearray,
    comm: bytearray
) -> None:
    """
    Generate a pair of nonces and their corresponding public commitments.
    
    nonce -- (output) a nonce pair, size:ecc_frost_ristretto255_sha512_NONCEPAIRSIZE
    comm -- (output) a nonce commitment pair, size:ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE
    """
    ptr_nonce = ffi.from_buffer(nonce)
    ptr_comm = ffi.from_buffer(comm)
    lib.ecc_frost_ristretto255_sha512_commit(
        ptr_nonce,
        ptr_comm
    )
    return None


def ecc_frost_ristretto255_sha512_group_commitment(
    group_comm: bytearray,
    commitment_list: bytes,
    commitment_list_len: int,
    binding_factor: bytes
) -> None:
    """
    Create the group commitment from a commitment list.
    
    group_comm -- (output) size:ecc_frost_ristretto255_sha512_ELEMENTSIZE
    commitment_list -- a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE
    commitment_list_len -- the number of elements in `commitment_list`
    binding_factor -- size:ecc_frost_ristretto255_sha512_SCALARSIZE
    """
    ptr_group_comm = ffi.from_buffer(group_comm)
    ptr_commitment_list = ffi.from_buffer(commitment_list)
    ptr_binding_factor = ffi.from_buffer(binding_factor)
    lib.ecc_frost_ristretto255_sha512_group_commitment(
        ptr_group_comm,
        ptr_commitment_list,
        commitment_list_len,
        ptr_binding_factor
    )
    return None


def ecc_frost_ristretto255_sha512_sign(
    sig_share: bytearray,
    comm_share: bytearray,
    index: int,
    sk_i: bytes,
    group_public_key: bytes,
    nonce_i: bytes,
    comm_i: bytes,
    msg: bytes,
    msg_len: int,
    commitment_list: bytes,
    commitment_list_len: int,
    participant_list: bytes,
    participant_list_len: int
) -> None:
    """
    To produce a signature share.
    
    sig_share -- (output) signature share, size:ecc_frost_ristretto255_sha512_SCALARSIZE
    comm_share -- (output) commitment share, size:ecc_frost_ristretto255_sha512_ELEMENTSIZE
    index -- index `i` of the signer. Note index will never equal `0` and must be less thant 256
    sk_i -- signer secret key share, size:ecc_frost_ristretto255_sha512_SECRETKEYSIZE
    group_public_key -- public key corresponding to the signer secret key share, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
    nonce_i -- pair of scalar values generated in round one, size:ecc_frost_ristretto255_sha512_NONCEPAIRSIZE
    comm_i -- pair of element values generated in round one, size:ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE
    msg -- the message to be signed (sent by the Coordinator), size:msg_len
    msg_len -- the length of `msg`
    commitment_list -- a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE
    commitment_list_len -- the number of elements in `commitment_list`
    participant_list -- a set containing identifiers for each signer, size:participant_list_len
    participant_list_len -- the number of elements in `participant_list`
    """
    ptr_sig_share = ffi.from_buffer(sig_share)
    ptr_comm_share = ffi.from_buffer(comm_share)
    ptr_sk_i = ffi.from_buffer(sk_i)
    ptr_group_public_key = ffi.from_buffer(group_public_key)
    ptr_nonce_i = ffi.from_buffer(nonce_i)
    ptr_comm_i = ffi.from_buffer(comm_i)
    ptr_msg = ffi.from_buffer(msg)
    ptr_commitment_list = ffi.from_buffer(commitment_list)
    ptr_participant_list = ffi.from_buffer(participant_list)
    lib.ecc_frost_ristretto255_sha512_sign(
        ptr_sig_share,
        ptr_comm_share,
        index,
        ptr_sk_i,
        ptr_group_public_key,
        ptr_nonce_i,
        ptr_comm_i,
        ptr_msg,
        msg_len,
        ptr_commitment_list,
        commitment_list_len,
        ptr_participant_list,
        participant_list_len
    )
    return None


def ecc_frost_ristretto255_sha512_verify_signature_share(
    index: int,
    public_key_share_i: bytes,
    comm_i: bytes,
    sig_share_i: bytes,
    commitment_list: bytes,
    commitment_list_len: int,
    participant_list: bytes,
    participant_list_len: int,
    group_public_key: bytes,
    msg: bytes,
    msg_len: int
) -> int:
    """
    Check that the signature share is valid.
    
    index -- Index `i` of the signer. Note index will never equal `0`.
    public_key_share_i -- the public key for the ith signer, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
    comm_i -- pair of Element values (hiding_nonce_commitment, binding_nonce_commitment) generated in round one from the ith signer, size:ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE
    sig_share_i -- a Scalar value indicating the signature share as produced in round two from the ith signer, size:ecc_frost_ristretto255_sha512_SCALARSIZE
    commitment_list -- a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE
    commitment_list_len -- the number of elements in `commitment_list`
    participant_list -- a set containing identifiers for each signer, size:participant_list_len
    participant_list_len -- the number of elements in `participant_list`
    group_public_key -- the public key for the group, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
    msg -- the message to be signed (sent by the Coordinator), size:msg_len
    msg_len -- the length of `msg`
    return 1 if the signature share is valid, and 0 otherwise.
    """
    ptr_public_key_share_i = ffi.from_buffer(public_key_share_i)
    ptr_comm_i = ffi.from_buffer(comm_i)
    ptr_sig_share_i = ffi.from_buffer(sig_share_i)
    ptr_commitment_list = ffi.from_buffer(commitment_list)
    ptr_participant_list = ffi.from_buffer(participant_list)
    ptr_group_public_key = ffi.from_buffer(group_public_key)
    ptr_msg = ffi.from_buffer(msg)
    fun_ret = lib.ecc_frost_ristretto255_sha512_verify_signature_share(
        index,
        ptr_public_key_share_i,
        ptr_comm_i,
        ptr_sig_share_i,
        ptr_commitment_list,
        commitment_list_len,
        ptr_participant_list,
        participant_list_len,
        ptr_group_public_key,
        ptr_msg,
        msg_len
    )
    return fun_ret


def ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_secret_and_coefficients(
    public_key: bytearray,
    secret_key_shares: bytes,
    n: int,
    t: int,
    secret_key: bytes,
    coefficients: bytes
) -> None:
    """
    Generates a group secret s uniformly at random and uses
    Shamir and Verifiable Secret Sharing to create secret shares
    of s to be sent to all other participants.
    
    public_key -- (output) public key Element, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
    secret_key_shares -- shares of the secret key, each a Scalar value, size:n*ecc_frost_ristretto255_sha512_SCALARSIZE
    n -- the number of shares to generate
    t -- the threshold of the secret sharing scheme
    secret_key -- a secret key Scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
    coefficients -- size:t*ecc_frost_ristretto255_sha512_SCALARSIZE
    """
    ptr_public_key = ffi.from_buffer(public_key)
    ptr_secret_key_shares = ffi.from_buffer(secret_key_shares)
    ptr_secret_key = ffi.from_buffer(secret_key)
    ptr_coefficients = ffi.from_buffer(coefficients)
    lib.ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_secret_and_coefficients(
        ptr_public_key,
        ptr_secret_key_shares,
        n,
        t,
        ptr_secret_key,
        ptr_coefficients
    )
    return None


def ecc_frost_ristretto255_sha512_trusted_dealer_keygen(
    secret_key: bytearray,
    public_key: bytearray,
    secret_key_shares: bytearray,
    n: int,
    t: int
) -> None:
    """
    Generates a group secret s uniformly at random and uses
    Shamir and Verifiable Secret Sharing to create secret shares
    of s to be sent to all other participants.
    
    secret_key -- (output) a secret key Scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
    public_key -- (output) public key Element, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
    secret_key_shares -- (output) shares of the secret key, each a Scalar value, size:n*ecc_frost_ristretto255_sha512_SCALARSIZE
    n -- the number of shares to generate
    t -- the threshold of the secret sharing scheme
    """
    ptr_secret_key = ffi.from_buffer(secret_key)
    ptr_public_key = ffi.from_buffer(public_key)
    ptr_secret_key_shares = ffi.from_buffer(secret_key_shares)
    lib.ecc_frost_ristretto255_sha512_trusted_dealer_keygen(
        ptr_secret_key,
        ptr_public_key,
        ptr_secret_key_shares,
        n,
        t
    )
    return None


def ecc_frost_ristretto255_sha512_secret_share_shard_with_coefficients(
    points: bytes,
    n: int,
    t: int,
    coefficients: bytes
) -> None:
    """
    Split a secret into shares.
    
    points -- A list of n secret shares, each of which is an element of F, size:n*ecc_frost_ristretto255_sha512_SCALARSIZE
    n -- the number of shares to generate
    t -- the threshold of the secret sharing scheme
    coefficients -- size:t*ecc_frost_ristretto255_sha512_SCALARSIZE
    """
    ptr_points = ffi.from_buffer(points)
    ptr_coefficients = ffi.from_buffer(coefficients)
    lib.ecc_frost_ristretto255_sha512_secret_share_shard_with_coefficients(
        ptr_points,
        n,
        t,
        ptr_coefficients
    )
    return None


def ecc_frost_ristretto255_sha512_secret_share_shard(
    points: bytearray,
    s: bytes,
    n: int,
    t: int
) -> None:
    """
    Split a secret into shares.
    
    points -- (output) A list of n secret shares, each of which is an element of F, size:n*ecc_frost_ristretto255_sha512_SCALARSIZE
    s -- secret to be shared, an element of F, size:ecc_frost_ristretto255_sha512_SCALARSIZE
    n -- the number of shares to generate
    t -- the threshold of the secret sharing scheme
    """
    ptr_points = ffi.from_buffer(points)
    ptr_s = ffi.from_buffer(s)
    lib.ecc_frost_ristretto255_sha512_secret_share_shard(
        ptr_points,
        ptr_s,
        n,
        t
    )
    return None


def ecc_frost_ristretto255_sha512_frost_aggregate(
    signature: bytearray,
    group_commitment: bytes,
    sig_shares: bytes,
    sig_shares_len: int
) -> None:
    """
    Performs the aggregate operation to obtain the resulting signature.
    
    signature -- (output) a Schnorr signature consisting of an Element and Scalar value, size:ecc_frost_ristretto255_sha512_SIGNATURESIZE
    group_commitment -- the group commitment returned by compute_group_commitment, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
    sig_shares -- a set of signature shares z_i for each signer, size:sig_shares_len*ecc_frost_ristretto255_sha512_SCALARSIZE
    sig_shares_len -- the number of elements in `sig_shares`, must satisfy THRESHOLD_LIMIT
    <
    = sig_shares_len
    <
    = MAX_SIGNERS
    """
    ptr_signature = ffi.from_buffer(signature)
    ptr_group_commitment = ffi.from_buffer(group_commitment)
    ptr_sig_shares = ffi.from_buffer(sig_shares)
    lib.ecc_frost_ristretto255_sha512_frost_aggregate(
        ptr_signature,
        ptr_group_commitment,
        ptr_sig_shares,
        sig_shares_len
    )
    return None

