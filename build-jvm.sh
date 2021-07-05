#!/usr/bin/env bash
set -x

#rm -rf build
#
#pushd deps/libsodium
#make clean
#popd
#
#cmake -DCMAKE_BUILD_TYPE=Release -B build -G "Ninja" .
#cmake --build build --config Release --parallel 2 --target libsodium-external
#cmake --build build --config Release --parallel 2 --target blst-external
#cmake --build build --config Release --parallel 2

swig -c++ -java -o jvm/libecc.cpp \
    -outdir jvm \
    -package org.ssohub.crypto.ecc \
    -DECC_OPRF_EXPORT="" \
    -DECC_OPAQUE_EXPORT="" \
    -DECC_EXPORT="" \
    jvm/ecc.i
