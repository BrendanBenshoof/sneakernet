#!/usr/bin/env bash
# Build the sneakernet mobile Go engine as an Android AAR.
# Requires: Go toolchain, Android NDK (pointed to by ANDROID_NDK_HOME).
#
# Usage: ./scripts/build-android-lib.sh
# Output: android/app/libs/mobile.aar

set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v gomobile &>/dev/null; then
    echo "Installing gomobile…"
    go install golang.org/x/mobile/cmd/gomobile@latest
    gomobile init
fi

mkdir -p android/app/libs

echo "Building mobile.aar…"
gomobile bind \
    -target android \
    -javapkg com.sneakernet.engine \
    -o android/app/libs/mobile.aar \
    ./mobile/

echo "Done → android/app/libs/mobile.aar"
echo "Open android/ in Android Studio and build."
