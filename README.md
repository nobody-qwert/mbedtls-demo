# TSA Verification with mbedTLS 3.6

[![TSA Verification Tests](https://github.com/nobody-qwert/mbedtls-demo/actions/workflows/tsa-verification-test.yml/badge.svg)](https://github.com/nobody-qwert/mbedtls-demo/actions/workflows/tsa-verification-test.yml)

This project implements Timestamp Authority (TSA) verification using mbedTLS 3.6 for offline verification of binary files according to RFC 3161.

## Overview

The implementation provides:
- TSR (Timestamp Response) parsing according to RFC 3161
- SHA-256 hash verification
- Offline verification against pre-downloaded TSR files
- Integration with FreeTSA service for testing
- File integrity verification and tamper detection

## Project Structure

```
tsa_verification/
├── include/
│   └── tsa_verifier.h          # TSA verification interface
├── src/
│   └── tsa_verifier.cpp        # TSA verification implementation
├── test/
│   └── test_tsa.cpp            # Test program
├── scripts/
│   ├── generate_tsr.sh         # Script to generate TSR from FreeTSA
│   └── freetsa_cert.pem        # FreeTSA certificate
├── build/                      # Build directory (created during build)
├── mbedtls-3.6.0/             # mbedTLS source (downloaded during setup)
├── CMakeLists.txt              # CMake build configuration
├── setup.sh                   # Automated setup script
└── README.md                   # This file
```

## System Requirements

- **Operating System**: Linux (tested on Ubuntu/Debian)
- **Compiler**: GCC with C++14 support
- **Build Tools**: CMake 3.10+, make, pkg-config
- **Dependencies**: OpenSSL CLI tools, curl, wget, tar, bzip2
- **Memory**: At least 1GB RAM for compilation
- **Disk Space**: ~500MB for mbedTLS source and build files

## Quick Setup

### Automated Setup (Recommended)

Run the provided setup script to automatically install all dependencies and build the project:

```bash
cd tsa_verification
chmod +x setup.sh
./setup.sh
```

The setup script will:
1. Install system dependencies (build-essential, cmake, openssl, curl, etc.)
2. Download and compile mbedTLS 3.6.0 from source
3. Configure the project build system
4. Build the TSA verification library and test program

### Manual Setup

If you prefer manual setup or the automated script fails:

#### 1. Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config openssl curl wget
```

**CentOS/RHEL/Fedora:**
```bash
sudo yum install -y gcc-c++ cmake pkgconfig openssl curl wget
# or for newer versions:
sudo dnf install -y gcc-c++ cmake pkgconfig openssl curl wget
```

#### 2. Download and Build mbedTLS 3.6.0

```bash
cd tsa_verification

# Download mbedTLS 3.6.0
wget https://github.com/Mbed-TLS/mbedtls/releases/download/v3.6.0/mbedtls-3.6.0.tar.bz2
tar -xjf mbedtls-3.6.0.tar.bz2

# Build and install mbedTLS
cd mbedtls-3.6.0
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DUSE_SHARED_MBEDTLS_LIBRARY=On
make -j$(nproc)
sudo make install
sudo ldconfig

# Return to project directory
cd ../..
```

#### 3. Build the Project

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## Usage

### Running the Test Program

After successful build, test the installation:

```bash
cd build
./test_tsa
```

**Expected Output:**
```
FreeTSA Timestamp Verification Test
===================================

1. Creating dummy binary file...
2. Calculating SHA-256 hash...
File SHA-256: [32-byte hex hash]

3. Generating timestamp from FreeTSA...
   [TSR generation details]

4. Loading TSA verifier...
5. Loading FreeTSA certificate...
6. Loading timestamp response...
7. Verifying timestamp...

✓ Timestamp verification SUCCESSFUL!

Timestamp Information:
=====================
Timestamp: 2025-05-30 07:43:33 UTC
Serial Number: 070B16CD
Policy OID: 1.2.3.4.1
Hash Algorithm: 2.16.840.1.101.3.4.2.1
TSA Name: FreeTSA
Message Imprint: [32-byte hex hash]

8. Testing with modified file...
✓ Correctly detected file modification!
Error: Hash mismatch
```

### Generating TSR Files

Use the provided script to generate TSR files from FreeTSA:

```bash
# From the build directory
./scripts/generate_tsr.sh <file_to_timestamp> [output.tsr]

# Example:
./scripts/generate_tsr.sh /path/to/myfile.bin myfile.bin.tsr
```

The script will:
1. Calculate SHA-256 hash of the input file
2. Create a timestamp request (TSQ)
3. Send the request to FreeTSA.org
4. Save the timestamp response (TSR)
5. Verify the response using OpenSSL

### Programming Interface

#### Basic Usage Example

```cpp
#include "tsa_verifier.h"
#include <iostream>

int main() {
    // Create verifier instance
    tsa::TSAVerifier verifier;

    // Load TSA certificate
    if (!verifier.loadTSACertificate("scripts/freetsa_cert.pem")) {
        std::cerr << "Failed to load certificate: " << verifier.getLastError() << std::endl;
        return 1;
    }

    // Load TSR file
    if (!verifier.loadTSR("myfile.bin.tsr")) {
        std::cerr << "Failed to load TSR: " << verifier.getLastError() << std::endl;
        return 1;
    }

    // Verify binary file
    auto result = verifier.verifyBinary("myfile.bin");

    if (result.isValid) {
        std::cout << "✓ Verification successful!" << std::endl;
        std::cout << "Timestamp: " << std::ctime(&result.timestampInfo.timestamp);
        std::cout << "Serial: " << result.timestampInfo.serialNumber << std::endl;
    } else {
        std::cout << "✗ Verification failed: " << result.error << std::endl;
    }

    return 0;
}
```

#### Hash-based Verification

```cpp
// Calculate hash manually
auto hash = tsa::calculateSHA256("myfile.bin");

// Verify against hash directly
auto result = verifier.verifyHash(hash.data(), hash.size());
```

## API Reference

### TSAVerifier Class

```cpp
namespace tsa {
    class TSAVerifier {
    public:
        // Certificate loading
        bool loadTSACertificate(const std::string& certPath);
        bool loadTSACertificateFromMemory(const uint8_t* certData, size_t certLen);

        // TSR loading
        bool loadTSR(const std::string& tsrPath);
        bool loadTSRFromMemory(const uint8_t* tsrData, size_t tsrLen);

        // Verification
        VerificationResult verifyBinary(const std::string& binaryPath);
        VerificationResult verifyHash(const uint8_t* hash, size_t hashLen);

        // Error handling
        std::string getLastError() const;
    };
}
```

### Data Structures

```cpp
struct TimestampInfo {
    std::time_t timestamp;                    // Unix timestamp
    std::string serialNumber;                 // TSR serial number (hex)
    std::string policyOID;                    // TSA policy OID
    std::string hashAlgorithm;                // Hash algorithm OID
    std::vector<uint8_t> messageImprint;      // Original file hash
    std::string tsaName;                      // TSA name
    bool certReq;                             // Certificate required flag
};

struct VerificationResult {
    bool isValid;                             // Verification success
    std::string error;                        // Error message (if failed)
    TimestampInfo timestampInfo;              // Timestamp details (if valid)
};
```

### Utility Functions

```cpp
namespace tsa {
    // Calculate SHA-256 hash of file
    std::vector<uint8_t> calculateSHA256(const std::string& filePath);
    
    // Calculate SHA-256 hash of data
    std::vector<uint8_t> calculateSHA256(const uint8_t* data, size_t len);
}
```

## Supported Features

- ✅ RFC 3161 compliant TSR parsing
- ✅ SHA-256 hash verification
- ✅ Offline verification
- ✅ FreeTSA integration
- ✅ File modification detection
- ✅ ASN.1 DER parsing
- ✅ Certificate loading (PEM format)
- ✅ Timestamp extraction and validation
- ⚠️  Basic signature verification (full PKI validation pending)

## Troubleshooting

### Build Issues

**mbedTLS not found:**
```bash
# Ensure mbedTLS is properly installed
sudo ldconfig
pkg-config --cflags --libs mbedtls

# If using custom installation path:
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
```

**C++14 compilation errors:**
```bash
# Ensure GCC supports C++14
gcc --version  # Should be 5.0+

# Update CMake if needed
cmake --version  # Should be 3.10+
```

### Runtime Issues

**Certificate loading fails:**
- Verify certificate file exists and is readable
- Check certificate format (must be PEM)
- Ensure certificate is valid and not expired

**TSR generation fails:**
- Check internet connectivity
- Verify OpenSSL is installed and in PATH
- Ensure curl is available

**Verification fails:**
- Ensure TSR was generated for the exact same file
- Check that file hasn't been modified since TSR generation
- Verify TSA certificate matches the TSR issuer

### Network Issues

**FreeTSA connection problems:**
```bash
# Test connectivity
curl -I https://freetsa.org/tsr

# Check if corporate firewall blocks the service
# Consider using alternative TSA services for production
```

## Security Considerations

1. **Certificate Validation**: Always verify TSA certificates from trusted sources
2. **Secure Storage**: Store TSR files securely alongside binaries
3. **Certificate Expiration**: Consider certificate expiration for long-term storage
4. **Production Use**: Implement proper certificate chain validation for production
5. **Network Security**: Use HTTPS for TSA communications
6. **File Integrity**: Protect both original files and TSR files from tampering

## Production Deployment

For production use, consider:

1. **Alternative TSA Services**: FreeTSA is for testing; use commercial TSA services for production
2. **Certificate Chain Validation**: Implement full PKI validation
3. **Batch Processing**: Optimize for multiple file verification
4. **Error Handling**: Implement robust error handling and logging
5. **Performance**: Consider caching certificates and optimizing hash calculations

## Limitations

- Currently supports SHA-256 only (most common)
- Signature verification is basic (certificate chain validation pending)
- TSA certificate must be provided separately
- Limited to RFC 3161 timestamp tokens
- No support for qualified timestamps (ETSI standards)

## Contributing

To contribute to this project:

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Ensure all tests pass
5. Submit a pull request

## License

This implementation is provided as-is for educational and testing purposes. For production use, ensure compliance with relevant security standards and regulations.

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Verify your setup matches the requirements
3. Test with the provided example files
4. Review the API documentation

## References

- [RFC 3161 - Time-Stamp Protocol (TSP)](https://tools.ietf.org/html/rfc3161)
- [mbedTLS Documentation](https://mbed-tls.readthedocs.io/)
- [FreeTSA Service](https://freetsa.org/)
- [ASN.1 Standards](https://www.itu.int/rec/T-REC-X.690/)
