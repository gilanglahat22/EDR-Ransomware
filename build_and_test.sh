#!/bin/bash

# Exit on error
set -e

echo "=== Building RWArmor ==="

# Check if build directory exists, create if not
if [ ! -d "build" ]; then
    mkdir build
fi

# Build the project
cd build
cmake ..
cmake --build .

echo "=== Build completed successfully ==="

# Check if the binary was created
if [ -f "./rwarmor" ]; then
    echo "=== RWArmor binary created successfully ==="
    echo "=== To run RWArmor, use: ./rwarmor ==="
else
    echo "ERROR: rwarmor binary not found!"
    exit 1
fi

# Return to the original directory
cd ..

echo "=== Build and verification completed ==="
echo "You can now run RWArmor from the build directory:"
echo "  cd build"
echo "  ./rwarmor" 