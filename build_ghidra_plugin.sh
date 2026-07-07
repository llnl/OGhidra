#!/bin/bash
# Build script for GhidraMCP extension

echo "Building GhidraMCP extension..."
echo
which javac
javac --version
echo
echo "$JAVA_HOME"
echo
# If GHIDRA_INSTALL_DIR is not set, attempt to read from lastrun file
if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    if [ -n "$XDG_CONFIG_HOME" ]; then
        LASTRUN_FILE="$XDG_CONFIG_HOME/ghidra/lastrun"
    elif [ "$(uname)" = "Darwin" ]; then
        LASTRUN_FILE="$HOME/Library/ghidra/lastrun"
    else
        LASTRUN_FILE="$HOME/.config/ghidra/lastrun"
    fi

    if [ -f "$LASTRUN_FILE" ]; then
        GHIDRA_INSTALL_DIR=$(head -n 1 "$LASTRUN_FILE" | tr -d '[:space:]')
        echo "Found Ghidra at $GHIDRA_INSTALL_DIR using $LASTRUN_FILE"
    else
        echo "ERROR: GHIDRA_INSTALL_DIR environment variable not set."
        echo "Please set it to your Ghidra installation directory."
        echo "Example: export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0_PUBLIC"
        exit 1
    fi
fi

# Check if Ghidra installation exists
if [ ! -d "$GHIDRA_INSTALL_DIR" ]; then
    echo "ERROR: Ghidra installation not found at $GHIDRA_INSTALL_DIR"
    exit 1
fi

echo "$GHIDRA_INSTALL_DIR/support/gradle/gradlew"
"$GHIDRA_INSTALL_DIR/support/gradle/gradlew" --version || {
    echo "ERROR: Failed to run Ghidra Gradle wrapper."
    exit 1
}
echo

# Create gradle.properties with the correct GHIDRA_INSTALL_DIR
echo "# Path to your Ghidra installation directory" > OGhidraMCP/gradle.properties || {
    echo "ERROR: Failed to write OGhidraMCP/gradle.properties"
    exit 1
}
echo "GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR" >> OGhidraMCP/gradle.properties || {
    echo "ERROR: Failed to write OGhidraMCP/gradle.properties"
    exit 1
}

# Build the extension
cd OGhidraMCP || {
    echo "ERROR: Failed to enter OGhidraMCP"
    exit 1
}
"$GHIDRA_INSTALL_DIR/support/gradle/gradlew" buildExtension --info || {
    echo "ERROR: Build failed!"
    exit 1
}
cd .. || {
    echo "ERROR: Failed to return to project root"
    exit 1
}

echo
echo "Build completed successfully!"
echo
echo "The extension zip file is located in: OGhidraMCP/dist/"
