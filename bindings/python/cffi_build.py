"""
Copyright (c) 2022, Alden Torres

Licensed under the terms of the MIT license.
Copy of the license at https://opensource.org/licenses/MIT
"""

from cffi import FFI

ffibuilder = FFI()

ffibuilder.cdef(
    """
    void ecc_randombytes(unsigned char *buf, int n);
    """
)

ffibuilder.set_source(
    module_name="_libecc_cffi",
    source=
    """
    #include "../../../../src/ecc.h"
    """,
    include_dirs=["../../../src"],
    library_dirs=["../../../../build", "../../../../build/libsodium/lib", "../../../../deps/blst"],
    libraries=["ecc_static", "sodium", "blst"]
)

if __name__ == "__main__":
    ffibuilder.compile(tmpdir="src/libecc", verbose=True)
