#ifndef TSA_VERIFIER_H
#define TSA_VERIFIER_H

#include <string>
#include <vector>
#include <memory>
#include <ctime>

// Forward declarations for mbedTLS types
typedef struct mbedtls_x509_crt mbedtls_x509_crt;
typedef struct mbedtls_pk_context mbedtls_pk_context;
typedef struct mbedtls_pkcs7 mbedtls_pkcs7;

namespace tsa {

// Structure to hold timestamp information
struct TimestampInfo {
    std::time_t timestamp;
    std::string serialNumber;
    std::string policyOID;
    std::string hashAlgorithm;
    std::vector<uint8_t> messageImprint;
    bool certReq;
    std::string tsaName;
};

// Structure to hold verification result
struct VerificationResult {
    bool isValid;
    std::string error;
    TimestampInfo timestampInfo;
};

class TSAVerifier {
public:
    TSAVerifier();
    ~TSAVerifier();

    // Load TSA certificate for verification
    bool loadTSACertificate(const std::string& certPath);
    
    // Load TSA certificate from memory
    bool loadTSACertificateFromMemory(const uint8_t* certData, size_t certLen);

    // Load TSR from file
    bool loadTSR(const std::string& tsrPath);
    
    // Load TSR from memory
    bool loadTSRFromMemory(const uint8_t* tsrData, size_t tsrLen);

    // Verify TSR against binary file
    VerificationResult verifyBinary(const std::string& binaryPath);
    
    // Verify TSR against hash
    VerificationResult verifyHash(const uint8_t* hash, size_t hashLen);

    // Get last error
    std::string getLastError() const { return lastError_; }

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
    std::string lastError_;
};

// Utility functions
std::vector<uint8_t> calculateSHA256(const std::string& filePath);
std::vector<uint8_t> calculateSHA256(const uint8_t* data, size_t len);

} // namespace tsa

#endif // TSA_VERIFIER_H
