#!/usr/bin/env bash
# Build the sneakernet Android debug APK.
#
# Prerequisites:
#   - Go toolchain (go 1.25+)
#   - Android SDK at ~/Android/Sdk  (or set ANDROID_SDK_HOME)
#   - Android NDK 27 inside the SDK  (or set ANDROID_NDK_HOME)
#   - JAVA_HOME set, or java on PATH
#
# Usage:
#   ./scripts/build-android.sh          # build AAR + debug APK
#   ./scripts/build-android.sh --aar    # rebuild AAR only
#   ./scripts/build-android.sh --apk    # rebuild APK only (uses existing AAR)

set -euo pipefail
cd "$(dirname "$0")/.."

# ── Locate Android SDK / NDK ──────────────────────────────────────────────────
ANDROID_SDK_HOME="${ANDROID_SDK_HOME:-$HOME/Android/Sdk}"
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    NDK_DIR="$ANDROID_SDK_HOME/ndk"
    # Pick the highest installed NDK version.
    ANDROID_NDK_HOME="$NDK_DIR/$(ls "$NDK_DIR" | sort -V | tail -1)"
fi
export ANDROID_NDK_HOME

# ── Locate Java ───────────────────────────────────────────────────────────────
if [ -z "${JAVA_HOME:-}" ]; then
    JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(which java)")")")"
fi
export JAVA_HOME

# ── Locate gomobile ───────────────────────────────────────────────────────────
export PATH="$PATH:$(go env GOPATH)/bin"
if ! command -v gomobile &>/dev/null; then
    echo "gomobile not found — installing…"
    go install golang.org/x/mobile/cmd/gomobile@latest
    gomobile init
fi

# ── Parse flags ───────────────────────────────────────────────────────────────
BUILD_AAR=true
BUILD_APK=true
for arg in "$@"; do
    case "$arg" in
        --aar) BUILD_APK=false ;;
        --apk) BUILD_AAR=false ;;
    esac
done

# ── Build Go mobile AAR ───────────────────────────────────────────────────────
if $BUILD_AAR; then
    echo "Building mobile.aar (NDK: $ANDROID_NDK_HOME)…"
    mkdir -p android/app/libs
    GOTOOLCHAIN=go1.25.0 gomobile bind \
        -target android \
        -androidapi 21 \
        -javapkg com.sneakernet.engine \
        -o android/app/libs/mobile.aar \
        ./mobile/
    echo "  → android/app/libs/mobile.aar"
fi

# ── Build Android APK ─────────────────────────────────────────────────────────
if $BUILD_APK; then
    echo "Building debug APK…"
    cd android
    ./gradlew assembleDebug
    APK="$(find app/build/outputs/apk/debug -name '*.apk' | head -1)"
    echo "  → android/$APK"
fi
