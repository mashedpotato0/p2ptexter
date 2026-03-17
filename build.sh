#!/bin/bash
# build.sh: Helper to compile the app for production (Optimized)

# ── Selective Build ───────────────────────────────────────────────────────────
BUILD_APPIMAGE=false
BUILD_APK=false

if [ "$#" -eq 0 ]; then
    BUILD_APPIMAGE=true
    BUILD_APK=true
else
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --appimage|--linux) BUILD_APPIMAGE=true ;;
            --apk|--android) BUILD_APK=true ;;
            --all) BUILD_APPIMAGE=true; BUILD_APK=true ;;
            *) echo "Unknown flag: $1"; exit 1 ;;
        esac
        shift
    done
fi

echo "Compiling for production (AppImage: $BUILD_APPIMAGE, APK: $BUILD_APK)..."

# Check dependencies
if ! command -v cargo-tauri >/dev/null 2>&1; then
    echo "Installing tauri-cli..."
    cargo install tauri-cli
fi

# ── Paths & Config ───────────────────────────────────────────────────────────
ZIPALIGN="/home/mashedpotato/Android/Sdk/build-tools/35.0.0/zipalign"
APKSIGNER="/home/mashedpotato/Android/Sdk/build-tools/35.0.0/apksigner"
KEYSTORE="/tmp/p2p-dev.keystore"
ALIAS="p2p-dev"
PASS="password"

APK_UNSIGNED="src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk"
APK_SIGNED="src-tauri/gen/android/app/build/outputs/apk/universal/release/p2p-signed.apk"
APK_ALIGNED="src-tauri/gen/android/app/build/outputs/apk/universal/release/app-p2p-aligned.apk"

# ── Linux Build (.AppImage) ───────────────────────────────────────────────────
if [ "$BUILD_APPIMAGE" = true ]; then
    echo "Building Linux executable..."
    NO_STRIP=1 cargo tauri build || exit 1
fi

# ── Android Build (.apk) ─────────────────────────────────────────────────────
if [ "$BUILD_APK" = true ]; then
    echo "Building Android APK..."
    
    # Ensure Android NDK toolchain is in PATH
    NDK_ROOT="/home/mashedpotato/Android/Sdk/ndk/29.0.13846066"
    NDK_BIN="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin"
    export PATH="$NDK_BIN:$PATH"

    # Set explicit compilers for cross-compilation
    export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android29-clang"
    export AR_aarch64_linux_android="$NDK_BIN/llvm-ar"

    cargo tauri android build || exit 1

    # ── APK Signing ───────────────────────────────────────────────────────────
    echo "Aligning and signing APK..."
    if [ -f "$APK_UNSIGNED" ]; then
        if [ ! -f "$KEYSTORE" ]; then
            echo "Generating dev keystore..."
            keytool -genkey -v -keystore "$KEYSTORE" -alias "$ALIAS" -keyalg RSA -keysize 2048 -validity 10000 -storepass "$PASS" -keypass "$PASS" -dname "CN=P2PDev, OU=Dev, O=Dev, L=Dev, S=Dev, C=US"
        fi

        rm -f "$APK_SIGNED" "$APK_ALIGNED"
        echo "Aligning..."
        "$ZIPALIGN" -f -v 4 "$APK_UNSIGNED" "$APK_ALIGNED" > /dev/null
        echo "Signing..."
        "$APKSIGNER" sign --ks "$KEYSTORE" --ks-pass "pass:$PASS" --out "$APK_SIGNED" "$APK_ALIGNED"
        rm -f "$APK_ALIGNED"
    else
        echo "Warning: Unsigned APK not found, skipping signing."
    fi
fi

# ── Artifact Collection ───────────────────────────────────────────────────────
echo "Collecting artifacts into ./build..."

BUILD_DIR="./build"
mkdir -p "$BUILD_DIR" 

if [ "$BUILD_APPIMAGE" = true ]; then
    # Force remove old AppImage if busy/locked
    find "$BUILD_DIR" -name "*.AppImage" -delete
    find src-tauri/target/release/bundle -type f \( -name "*.deb" -o -name "*.rpm" -o -name "*.AppImage" \) -exec cp -f {} "$BUILD_DIR/" \;
fi

if [ "$BUILD_APK" = true ]; then
    if [ -f "$APK_SIGNED" ]; then
        rm -f "$BUILD_DIR/$(basename "$APK_SIGNED")"
        cp -f "$APK_SIGNED" "$BUILD_DIR/"
    fi
    find src-tauri/gen/android/app/build/outputs -type f -name "*.aab" -exec cp -f {} "$BUILD_DIR/" \;
fi

echo "Artifacts collected:"
ls -lh "$BUILD_DIR"
