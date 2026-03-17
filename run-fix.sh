#!/bin/bash
# run-fix.sh: Helper to run the app bypassing glycin-svg crash

# Create a temporary directory for our loader cache
LOADER_CACHE_DIR="/tmp/p2ptexter-loaders"
mkdir -p "$LOADER_CACHE_DIR"
LOADER_CACHE="$LOADER_CACHE_DIR/loaders.cache"

# Generate a clean cache excluding glycin
# We use gdk-pixbuf-query-loaders and filter out lines containing glycin
if command -v gdk-pixbuf-query-loaders >/dev/null 2>&1; then
    gdk-pixbuf-query-loaders | grep -v "glycin" > "$LOADER_CACHE"
else
    # Fallback to /usr/bin if not in path (common on Arch/Fedora)
    /usr/bin/gdk-pixbuf-query-loaders | grep -v "glycin" > "$LOADER_CACHE"
fi

# Run the app with the workaround
echo "Starting app with GDK_PIXBUF_MODULE_FILE workaround..."
export GDK_PIXBUF_MODULE_FILE="$LOADER_CACHE"

# Check if we should run tauri dev or raw cargo
if [ "$1" == "dev" ]; then
    cargo tauri dev
else
    cd src-tauri && cargo run --no-default-features --color always --
fi
