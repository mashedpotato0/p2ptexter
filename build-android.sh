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

# set working directory to script location (project root)
cd "$(dirname "$0")"

echo "starting android build"

# cleanup old builds
echo "cleaning up old builds"
rm -f "$SIGNED_APK" "$ALIGNED_APK"
# optionally remove the unsigned one if you want a fresh build
# rm -f "$APK_PATH"

# build standard tauri stuff
cargo tauri android build

# make sure apk is there
if [ ! -f "$APK_PATH" ]; then
    echo "build failed: apk not found at $(pwd)/$APK_PATH"
    # debug: list what's actually there
    echo "contents of $(dirname "$APK_PATH"):"
    ls -l "$(dirname "$APK_PATH")"
    exit 1
fi

# prep keystore
if [ ! -f "$KEYSTORE" ]; then
    echo "generating dev keystore"
    keytool -genkey -v -keystore "$KEYSTORE" -alias "$ALIAS" -keyalg RSA -keysize 2048 -validity 10000 -storepass "$PASS" -keypass "$PASS" -dname "CN=P2PDev, OU=Dev, O=Dev, L=Dev, S=Dev, C=US"
fi

# align it
echo "aligning apk"
"$ZIPALIGN" -v 4 "$APK_PATH" "$ALIGNED_APK"

# sign it
echo "signing with apksigner"
"$APKSIGNER" sign --ks "$KEYSTORE" --ks-pass "pass:$PASS" --out "$SIGNED_APK" "$ALIGNED_APK"

echo "done apk is ready at"
echo "$(pwd)/$SIGNED_APK"
