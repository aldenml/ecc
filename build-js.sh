#!/usr/bin/env bash

rm -rf build

pushd libsodium
make clean
popd

emcmake cmake -DCMAKE_BUILD_TYPE=Release -B build -G "Ninja" .
cmake --build build --config Release --parallel 2

EMCC_FLAGS="-Oz -flto --no-entry \
  -Wl,--whole-archive build/libsodium/lib/libsodium.a -Wl,--no-whole-archive \
  -sWASM=1 \
  -sSTRICT=1 \
  -sSINGLE_FILE=1 \
  -sMINIMAL_RUNTIME=2 \
  -sSUPPORT_LONGJMP=0 \
  -sSUPPORT_ERRNO=0 \
  -sASSERTIONS=0 \
  -sDISABLE_EXCEPTION_CATCHING=1 \
  -sNODEJS_CATCH_EXIT=0 \
  -sNODEJS_CATCH_REJECTION=0 \
  -sMODULARIZE=1 \
  -sEXPORT_ES6=1 \
  -sFILESYSTEM=0 \
  -sUSES_DYNAMIC_ALLOC=0 \
  -sMALLOC=emmalloc \
  -sALLOW_MEMORY_GROWTH=0 \
  -sTOTAL_STACK=65536 \
  -sINITIAL_MEMORY=131072"

emcc -o js/hash/hash.js --post-js js/hash-post.js -sEXPORT_NAME=hash_module \
  -Wl,--whole-archive build/libhash.a -Wl,--no-whole-archive ${EMCC_FLAGS}
