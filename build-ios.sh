#!/usr/bin/env bash
set -x

rm -rf build

pushd deps/libsodium
[ -d "build-aux" ] && make clean
popd

export ECC_CFLAGS="-arch arm64 -mmacosx-version-min=11"

cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 \
  -B build -G Xcode .

cmake --build build --config Release --parallel 2 \
  --target ecc_static -- -sdk iphonesimulator
