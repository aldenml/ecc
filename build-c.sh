#!/usr/bin/env bash
set -x

rm -rf build

pushd deps/libsodium
[ -d "build-aux" ] && make clean
popd

cmake -DCMAKE_BUILD_TYPE=Release -B build -G "Ninja" .
cmake --build build --config Release --parallel 2 --target libsodium-external
cmake --build build --config Release --parallel 2 --target blst-external
cmake --build build --config Release --parallel 2

cp build/libecc-jvm.{dylib,so} bindings/jvm/ 2>/dev/null || :
