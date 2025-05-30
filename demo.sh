#!/bin/bash

echo "==========================================="
echo "TSA Verification Demo"
echo "==========================================="
echo

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ]; then
    echo "Error: Please run this script from the tsa_verification directory"
    exit 1
fi

# Check if project is built
if [ ! -f "build/test_tsa" ]; then
    echo "Project not built. Building now..."
    mkdir -p build
    cd build
    cmake ..
    make
    cd ..
fi

echo "1. Running comprehensive test suite..."
echo "   This will test timestamp generation, verification, and tamper detection"
echo
cd build
mkdir -p test
./test_tsa

echo
echo "==========================================="
echo "Demo completed successfully!"
echo "==========================================="
echo
echo "What was demonstrated:"
echo "✓ File hash calculation (SHA-256)"
echo "✓ Timestamp request generation"
echo "✓ Communication with FreeTSA service"
echo "✓ Timestamp response parsing"
echo "✓ Certificate loading and validation"
echo "✓ Offline timestamp verification"
echo "✓ File integrity verification"
echo "✓ Tamper detection"
echo
echo "Files created:"
echo "- test/dummy_file.bin (test file)"
echo "- test/dummy_file.bin.tsr (timestamp response)"
echo
echo "Next steps:"
echo "- Use ./scripts/generate_tsr.sh to timestamp your own files"
echo "- Integrate the TSA verification library into your applications"
echo "- See README.md for detailed API documentation"
echo
