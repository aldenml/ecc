#!/usr/bin/env bash
set -x

clang -Xclang -ast-dump=json -fsyntax-only src/util.h > build/util.h.json
clang -Xclang -ast-dump=json -fsyntax-only src/hash.h > build/hash.h.json
clang -Xclang -ast-dump=json -fsyntax-only src/mac.h > build/mac.h.json
clang -Xclang -ast-dump=json -fsyntax-only src/kdf.h > build/kdf.h.json
clang -Xclang -ast-dump=json -fsyntax-only src/ed25519.h > build/ed25519.h.json
clang -Xclang -ast-dump=json -fsyntax-only src/ristretto255.h > build/ristretto255.h.json
clang -Xclang -ast-dump=json -fsyntax-only src/bls12_381.h > build/bls12_381.h.json
clang -Xclang -ast-dump=json -fsyntax-only src/h2c.h > build/h2c.h.json
clang -Xclang -ast-dump=json -fsyntax-only src/oprf.h > build/oprf.h.json
clang -Xclang -ast-dump=json -fsyntax-only src/opaque.h > build/opaque.h.json
clang -Xclang -ast-dump=json -fsyntax-only src/sign.h > build/sign.h.json
clang -Xclang -ast-dump=json -fsyntax-only src/pre.h > build/pre.h.json
