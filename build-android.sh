#!/bin/bash

# config
APK_PATH="src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk"
ALIGNED_APK="src-tauri/gen/android/app/build/outputs/apk/universal/release/app-p2p-aligned.apk"
SIGNED_APK="src-tauri/gen/android/app/build/outputs/apk/universal/release/app-p2p-signed.apk"
KEYSTORE="/tmp/p2p-dev.keystore"
ALIAS="p2p-dev"
PASS="password"

# where the tools are
ZIPALIGN="/home/mashedpotato/Android/Sdk/build-tools/35.0.0/zipalign"
APKSIGNER="/home/mashedpotato/Android/Sdk/build-tools/35.0.0/apksigner"

echo "starting android build"

# build standard tauri stuff
cargo tauri android build

# make sure apk is there
if [ ! -f "$APK_PATH" ]; then
    echo "build failed apk not found"
    exit 1
fi

# prep keystore
if [ ! -f "$KEYSTORE" ]; then
    echo "generating dev keystore"
    keytool -genkey -v -keystore "$KEYSTORE" -alias "$ALIAS" -keyalg RSA -keysize 2048 -validity 10000 -storepass "$PASS" -keypass "$PASS" -dname "CN=P2PDev, OU=Dev, O=Dev, L=Dev, S=Dev, C=US"
fi

# align it
echo "aligning apk"
rm -f "$ALIGNED_APK"
"$ZIPALIGN" -v 4 "$APK_PATH" "$ALIGNED_APK"

# sign it
echo "signing with apksigner"
rm -f "$SIGNED_APK"
"$APKSIGNER" sign --ks "$KEYSTORE" --ks-pass "pass:$PASS" --out "$SIGNED_APK" "$ALIGNED_APK"

echo "done apk is ready at"
echo "$SIGNED_APK"
