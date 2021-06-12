#!/usr/bin/env bash

rm -rf build

pushd libsodium
make clean
popd

cmake -DCMAKE_BUILD_TYPE=Release -B build -G "Ninja" .
cmake --build build --config Release --parallel 2 --target libsodium-external
cmake --build build --config Release --parallel 2
