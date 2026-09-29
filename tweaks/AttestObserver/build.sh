#!/bin/bash
# Build AttestObserver.dylib for a non-jailbroken environment with clang.
# Observe-only ObjC-swizzling dylib; no Theos, no Frida.
#
# Usage:  ./build.sh   ->  ./AttestObserver.dylib, copied to the project root
#         where instrument.py's attest_observe config injects it.
set -euo pipefail
cd "$(dirname "$0")"

SDK=$(xcrun --sdk iphoneos --show-sdk-path)

clang -arch arm64 -arch arm64e -dynamiclib \
  -isysroot "$SDK" -miphoneos-version-min=14.0 \
  -fobjc-arc \
  -framework Foundation \
  -install_name @rpath/AttestObserver.dylib \
  -o AttestObserver.dylib AttestObserver.m

cp AttestObserver.dylib ../../AttestObserver.dylib
echo "built AttestObserver.dylib ($(lipo -archs AttestObserver.dylib)) -> project root"
