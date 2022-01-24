"""
Copyright (c) 2022, Alden Torres

Licensed under the terms of the MIT license.
Copy of the license at https://opensource.org/licenses/MIT
"""

from ._libecc_cffi import ffi, lib


def ecc_randombytes(buf: bytearray, n: int):
    ptr_buf = ffi.from_buffer(buf)
    lib.ecc_randombytes(ptr_buf, n)
