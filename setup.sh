#!/bin/bash

# TSA Verification Setup Script for Ubuntu
# This script installs dependencies and sets up the TSA verification project

set -e  # Exit on any error

echo "=========================================="
echo "TSA Verification Setup Script"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on Ubuntu
if ! command -v apt &> /dev/null; then
    print_error "This script is designed for Ubuntu systems with apt package manager"
    exit 1
fi

print_status "Detected Ubuntu system"

# Update package lists
print_status "Updating package lists..."
sudo apt update

# Install basic dependencies
print_status "Installing basic dependencies..."
sudo apt install -y build-essential cmake pkg-config git python3 curl openssl

# Check mbedTLS version
print_status "Checking mbedTLS installation..."
MBEDTLS_VERSION=$(pkg-config --modversion mbedtls 2>/dev/null || echo "not found")

if [[ "$MBEDTLS_VERSION" == "3.6.0" ]]; then
    print_status "mbedTLS 3.6.0 is already installed ✓"
else
    print_warning "mbedTLS 3.6.0 not found (current: $MBEDTLS_VERSION)"
    
    if [[ -d "mbedtls-3.6.0" ]]; then
        print_status "Found existing mbedTLS 3.6.0 source, installing..."
        cd mbedtls-3.6.0/build
        sudo make install
        sudo ldconfig
        cd ../..
    else
        print_status "Downloading and building mbedTLS 3.6.0..."
        
        # Download mbedTLS 3.6.0
        wget -q https://github.com/Mbed-TLS/mbedtls/releases/download/v3.6.0/mbedtls-3.6.0.tar.bz2
        tar -xjf mbedtls-3.6.0.tar.bz2
        
        # Build and install
        cd mbedtls-3.6.0
        mkdir -p build
        cd build
        cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DUSE_SHARED_MBEDTLS_LIBRARY=On -DENABLE_PROGRAMS=Off -DENABLE_TESTING=Off ..
        make -j$(nproc)
        sudo make install
        sudo ldconfig
        cd ../..
    fi
    
    # Verify installation
    MBEDTLS_VERSION=$(pkg-config --modversion mbedtls 2>/dev/null || echo "not found")
    if [[ "$MBEDTLS_VERSION" == "3.6.0" ]]; then
        print_status "mbedTLS 3.6.0 successfully installed ✓"
    else
        print_error "Failed to install mbedTLS 3.6.0"
        exit 1
    fi
fi

# Verify all required tools
print_status "Verifying dependencies..."

MISSING_DEPS=()

if ! command -v cmake &> /dev/null; then
    MISSING_DEPS+=("cmake")
fi

if ! command -v gcc &> /dev/null; then
    MISSING_DEPS+=("gcc")
fi

if ! command -v g++ &> /dev/null; then
    MISSING_DEPS+=("g++")
fi

if ! command -v make &> /dev/null; then
    MISSING_DEPS+=("make")
fi

if ! command -v curl &> /dev/null; then
    MISSING_DEPS+=("curl")
fi

if ! command -v openssl &> /dev/null; then
    MISSING_DEPS+=("openssl")
fi

if ! pkg-config --exists mbedtls mbedcrypto mbedx509; then
    MISSING_DEPS+=("mbedtls-3.6.0")
fi

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    print_error "Missing dependencies: ${MISSING_DEPS[*]}"
    exit 1
fi

print_status "All dependencies verified ✓"

# Build the project
print_status "Building TSA verification project..."

# Clean previous build
if [[ -d "build" ]]; then
    rm -rf build
fi

mkdir build
cd build

# Configure with CMake
if ! cmake ..; then
    print_error "CMake configuration failed"
    exit 1
fi

# Build
if ! make; then
    print_error "Build failed"
    exit 1
fi

cd ..

print_status "Build completed successfully ✓"

# Make scripts executable
chmod +x scripts/generate_tsr.sh

print_status "Setup completed successfully!"
echo ""
echo "=========================================="
echo "Setup Summary:"
echo "=========================================="
echo "✓ Ubuntu dependencies installed"
echo "✓ mbedTLS 3.6.0 installed and configured"
echo "✓ TSA verification project built"
echo "✓ Scripts made executable"
echo ""
echo "Next steps:"
echo "1. Run tests: cd build && ./test_tsa"
echo "2. Generate TSR: ./scripts/generate_tsr.sh <file>"
echo "3. Verify offline: Use the built library"
echo ""
echo "Note: TSR generation requires internet access"
echo "      Verification works completely offline"
echo "=========================================="
