#!/bin/bash
# Build script for GhidraMCP extension

echo "Building GhidraMCP extension..."
echo
which gradle
gradle --version
echo
which javac
javac --version
echo
echo $JAVA_HOME
echo
# Check if GHIDRA_INSTALL_DIR environment variable is set
if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    echo "ERROR: GHIDRA_INSTALL_DIR environment variable not set."
    echo "Please set it to your Ghidra installation directory."
    echo "Example: export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0_PUBLIC"
    exit 1
fi

# Check if Ghidra installation exists
if [ ! -d "$GHIDRA_INSTALL_DIR" ]; then
    echo "ERROR: Ghidra installation not found at $GHIDRA_INSTALL_DIR"
    exit 1
fi

# Create gradle.properties with the correct GHIDRA_INSTALL_DIR
echo "# Path to your Ghidra installation directory" > OGhidraMCP/gradle.properties
echo "GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR" >> OGhidraMCP/gradle.properties

# Build the extension
cd OGhidraMCP
gradle buildExtension --info
if [ $? -ne 0 ]; then
    echo "ERROR: Build failed!"
    cd ..
    exit 1
fi
cd ..

echo
echo "Build completed successfully!"
echo
echo "The extension zip file is located in: OGhidraMCP/dist/"