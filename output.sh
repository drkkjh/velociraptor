#!/bin/bash
set -euo pipefail

# Define source and destination
SRC="output/velociraptor-v0.74.3-linux-amd64"
DEST="../../build"

# Ensure the destination directory exists
mkdir -p "$DEST"

# Copy using a pipe
cat "$SRC" > "$DEST/velociraptor-v0.74.3-linux-amd64"

# Make sure it remains executable
chmod +x "$DEST/velociraptor-v0.74.3-linux-amd64"

echo "Executable copied to $DEST"
