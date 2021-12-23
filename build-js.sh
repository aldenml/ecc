#!/usr/bin/env bash
set -x

rm -rf build

pushd deps/libsodium
make clean
popd

emcmake cmake -DCMAKE_BUILD_TYPE=Release -B build -G "Ninja" .
cmake --build build --config Release --parallel 2

EMCC_FLAGS="-Oz -flto --no-entry \
  -Wl,--whole-archive build/libsodium/lib/libsodium.a -Wl,--no-whole-archive \
  -Wl,--whole-archive deps/blst/libblst.a -Wl,--no-whole-archive \
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
  -sUSES_DYNAMIC_ALLOC=1 \
  -sMALLOC=emmalloc \
  -sALLOW_MEMORY_GROWTH=0 \
  -sTOTAL_STACK=65536 \
  -sINITIAL_MEMORY=131072"

emcc -o bindings/js/libecc.js -sEXPORT_NAME=libecc_module \
  --pre-js bindings/js/libecc-pre.js --post-js bindings/js/libecc-post.js \
  -Wl,--whole-archive build/libecc.a -Wl,--no-whole-archive ${EMCC_FLAGS}
