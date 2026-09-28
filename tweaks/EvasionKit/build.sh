#!/bin/bash
# Build EvasionKit.dylib for a non-jailbroken environment with clang directly.
# (Theos refuses project paths containing spaces, which this repo has, so we
# bypass Theos and compile the fishhook dylib straight against the iOS SDK.)
#
# Usage:  ./build.sh   ->  produces ./EvasionKit.dylib and copies it to the
#         project root where instrument.py looks for it.
set -euo pipefail
cd "$(dirname "$0")"

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
FH=../../SideloadFix-main/Tweak/fishhook

clang -arch arm64 -arch arm64e -dynamiclib \
  -isysroot "$SDK" -miphoneos-version-min=14.0 \
  -I "$FH" \
  -install_name @rpath/EvasionKit.dylib \
  -o EvasionKit.dylib EvasionKit.c "$FH/fishhook.c"

cp EvasionKit.dylib ../../EvasionKit.dylib
echo "built EvasionKit.dylib ($(lipo -archs EvasionKit.dylib)) -> project root"
