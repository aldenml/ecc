#!/usr/bin/env bash
set -x

rm -rf build

pushd deps/libsodium
[ -d "build-aux" ] && make clean
popd

export ECC_CFLAGS="-arch arm64 -mios-version-min=9.0.0"

cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_SYSTEM_NAME=iOS \
  -B build -G Xcode .

cmake --build build --config Release --parallel 2 \
  --target ecc_static -- -sdk iphonesimulator
