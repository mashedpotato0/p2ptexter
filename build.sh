#!/bin/bash
# build.sh: Helper to compile the app for production

echo "Compiling for production..."

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
APK_ALIGNED="src-tauri/gen/android/app/build/outputs/apk/universal/release/app-p2p-aligned.apk"
APK_SIGNED="src-tauri/gen/android/app/build/outputs/apk/universal/release/p2p-signed.apk"

# ── Build ─────────────────────────────────────────────────────────────────────

# Run Linux build
echo "Building Linux executable..."
NO_STRIP=1 cargo tauri build || exit 1

# Run Android build
echo "Building Android APK..."
cargo tauri android build || exit 1

# ── APK Signing ───────────────────────────────────────────────────────────────
echo "Aligning and signing APK..."

if [ -f "$APK_UNSIGNED" ]; then
    # prep keystore
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

# ── Artifact Collection ───────────────────────────────────────────────────────
echo "Collecting artifacts into ./build..."

BUILD_DIR="./build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Copy Linux bundles
find src-tauri/target/release/bundle -type f \( -name "*.deb" -o -name "*.rpm" -o -name "*.AppImage" \) -exec cp {} "$BUILD_DIR/" \;

# Copy Android binaries
if [ -f "$APK_SIGNED" ]; then
    cp "$APK_SIGNED" "$BUILD_DIR/"
fi
find src-tauri/gen/android/app/build/outputs -type f -name "*.aab" -exec cp {} "$BUILD_DIR/" \;

echo "Artifacts collected:"
ls -lh "$BUILD_DIR"
