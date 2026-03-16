#!/bin/bash

# Configuration
APK_PATH="src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk"
ALIGNED_APK="src-tauri/gen/android/app/build/outputs/apk/universal/release/app-p2p-aligned.apk"
SIGNED_APK="src-tauri/gen/android/app/build/outputs/apk/universal/release/app-p2p-signed.apk"
KEYSTORE="/tmp/p2p-dev.keystore"
ALIAS="p2p-dev"
PASS="password"

# Tool Paths (detected from your system)
ZIPALIGN="/home/mashedpotato/Android/Sdk/build-tools/35.0.0/zipalign"
APKSIGNER="/home/mashedpotato/Android/Sdk/build-tools/35.0.0/apksigner"

echo "🚀 Starting P2P Texter Android Build..."

# 1. Run the Tauri Build
cargo tauri android build

# 2. Check if APK was generated
if [ ! -f "$APK_PATH" ]; then
    echo "❌ Build failed - Unsigned APK not found"
    exit 1
fi

# 3. Create a keystore if it doesn't exist
if [ ! -f "$KEYSTORE" ]; then
    echo "🔑 Generating temporary development keystore..."
    keytool -genkey -v -keystore "$KEYSTORE" -alias "$ALIAS" -keyalg RSA -keysize 2048 -validity 10000 -storepass "$PASS" -keypass "$PASS" -dname "CN=P2PDev, OU=Dev, O=Dev, L=Dev, S=Dev, C=US"
fi

# 4. Zipalign (required before apksigner)
echo "📦 Aligning the APK..."
rm -f "$ALIGNED_APK"
"$ZIPALIGN" -v 4 "$APK_PATH" "$ALIGNED_APK"

# 5. Sign with apksigner (V2/V3 signing)
echo "✍️ Signing with apksigner..."
rm -f "$SIGNED_APK"
"$APKSIGNER" sign --ks "$KEYSTORE" --ks-pass "pass:$PASS" --out "$SIGNED_APK" "$ALIGNED_APK"

echo "✅ Success! Your VALID installable APK is at:"
echo "$SIGNED_APK"
