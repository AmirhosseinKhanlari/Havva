#!/bin/bash
# Build StorageObserver.dylib with clang (no Theos). Mirrors EntitlementShim/build.sh.
# Usage: ./build.sh -> ./StorageObserver.dylib, copied to the project root where
#        instrument.py's catalog ("storageobs") injects it.
set -euo pipefail
cd "$(dirname "$0")"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
clang -arch arm64 -arch arm64e -dynamiclib \
  -isysroot "$SDK" -miphoneos-version-min=14.0 \
  -fobjc-arc \
  -framework Foundation -framework Security -framework UIKit \
  -install_name @rpath/StorageObserver.dylib \
  -o StorageObserver.dylib StorageObserver.m
cp StorageObserver.dylib ../../StorageObserver.dylib
echo "built StorageObserver.dylib ($(lipo -archs StorageObserver.dylib)) -> project root"
