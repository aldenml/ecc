#!/usr/bin/env bash
set -x

rm -rf build

pushd deps/libsodium
[ -d "build-aux" ] && make clean
popd

export ECC_CFLAGS="-arch arm64 -mios-version-min=11.0"

#  -DPLATFORM=SIMULATORARM64 \
cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=cmake/ios.toolchain.cmake \
  -DENABLE_VISIBILITY=TRUE \
  -DDEPLOYMENT_TARGET=11.0 \
  -DPLATFORM=OS64 \
  -B build -G Xcode .

cmake --build build --config Release --parallel 2 --target ecc_static
