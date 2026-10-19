#!/bin/bash
# Build EntitlementShim.dylib for a non-jailbroken environment with clang.
# Neutralizes re-sign entitlement-loss crashes (e.g. VideoSubscriberAccount SSO).
# No Theos, no Frida. Mirrors tweaks/AttestObserver/build.sh.
#
# Usage:  ./build.sh   ->  ./EntitlementShim.dylib, copied to the project root
#         where instrument.py's catalog ("entshim") injects it.
set -euo pipefail
cd "$(dirname "$0")"

SDK=$(xcrun --sdk iphoneos --show-sdk-path)

clang -arch arm64 -arch arm64e -dynamiclib \
  -isysroot "$SDK" -miphoneos-version-min=14.0 \
  -fobjc-arc \
  -framework Foundation \
  -install_name @rpath/EntitlementShim.dylib \
  -o EntitlementShim.dylib EntitlementShim.m

cp EntitlementShim.dylib ../../EntitlementShim.dylib
echo "built EntitlementShim.dylib ($(lipo -archs EntitlementShim.dylib)) -> project root"
