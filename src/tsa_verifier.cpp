#include "../include/tsa_verifier.h"
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/asn1.h>
#include <mbedtls/oid.h>
#include <mbedtls/error.h>
#include <fstream>
#include <sstream>
#include <cstring>
#include <iomanip>

namespace tsa {

// ASN.1 tags for TSR parsing
#define ASN1_SEQUENCE           0x30
#define ASN1_SET                0x31
#define ASN1_CONTEXT_SPECIFIC   0xA0
#define ASN1_INTEGER            0x02
#define ASN1_OID                0x06
#define ASN1_OCTET_STRING       0x04
#define ASN1_UTC_TIME           0x17
#define ASN1_GENERALIZED_TIME   0x18
#define ASN1_BOOLEAN            0x01

// OIDs
const char* OID_ID_KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
const char* OID_ID_AA_TIME_STAMP_TOKEN = "1.2.840.113549.1.9.16.2.14";
const char* OID_SHA256 = "2.16.840.1.101.3.4.2.1";

class TSAVerifier::Impl {
public:
    mbedtls_x509_crt tsaCert;
    std::vector<uint8_t> tsrData;
    TimestampInfo timestampInfo;
    
    Impl() {
        mbedtls_x509_crt_init(&tsaCert);
    }
    
    ~Impl() {
        mbedtls_x509_crt_free(&tsaCert);
    }
    
    bool parseTSR(const uint8_t* data, size_t len);
    bool verifySignature(const uint8_t* signedData, size_t signedDataLen,
                        const uint8_t* signature, size_t signatureLen);
    bool parseTimeStampToken(const uint8_t* data, size_t len);
    bool parseSignedData(const uint8_t* data, size_t len);
    bool parseTSTInfo(const uint8_t* data, size_t len);
    std::string parseOID(const uint8_t* oid, size_t len);
    std::time_t parseTime(const uint8_t* time, size_t len, int tag);
};

TSAVerifier::TSAVerifier() : pImpl(std::make_unique<Impl>()) {}
TSAVerifier::~TSAVerifier() = default;

bool TSAVerifier::loadTSACertificate(const std::string& certPath) {
    std::ifstream file(certPath, std::ios::binary);
    if (!file) {
        lastError_ = "Failed to open certificate file: " + certPath;
        return false;
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> certData(size + 1);
    file.read(reinterpret_cast<char*>(certData.data()), size);
    certData[size] = 0; // Null terminate for PEM
    
    return loadTSACertificateFromMemory(certData.data(), size);
}

bool TSAVerifier::loadTSACertificateFromMemory(const uint8_t* certData, size_t certLen) {
    int ret = mbedtls_x509_crt_parse(&pImpl->tsaCert, certData, certLen + 1);
    if (ret != 0) {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        lastError_ = "Failed to parse TSA certificate: " + std::string(error_buf);
        return false;
    }
    return true;
}

bool TSAVerifier::loadTSR(const std::string& tsrPath) {
    std::ifstream file(tsrPath, std::ios::binary);
    if (!file) {
        lastError_ = "Failed to open TSR file: " + tsrPath;
        return false;
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    pImpl->tsrData.resize(size);
    file.read(reinterpret_cast<char*>(pImpl->tsrData.data()), size);
    
    return pImpl->parseTSR(pImpl->tsrData.data(), pImpl->tsrData.size());
}

bool TSAVerifier::loadTSRFromMemory(const uint8_t* tsrData, size_t tsrLen) {
    pImpl->tsrData.assign(tsrData, tsrData + tsrLen);
    return pImpl->parseTSR(tsrData, tsrLen);
}

VerificationResult TSAVerifier::verifyBinary(const std::string& binaryPath) {
    auto hash = calculateSHA256(binaryPath);
    if (hash.empty()) {
        return {false, "Failed to calculate file hash", {}};
    }
    return verifyHash(hash.data(), hash.size());
}

VerificationResult TSAVerifier::verifyHash(const uint8_t* hash, size_t hashLen) {
    VerificationResult result;
    result.isValid = false;
    
    // Compare provided hash with TSR message imprint
    if (pImpl->timestampInfo.messageImprint.size() != hashLen ||
        memcmp(pImpl->timestampInfo.messageImprint.data(), hash, hashLen) != 0) {
        result.error = "Hash mismatch";
        return result;
    }
    
    // TODO: Implement signature verification
    result.isValid = true;
    result.timestampInfo = pImpl->timestampInfo;
    return result;
}

bool TSAVerifier::Impl::parseTSR(const uint8_t* data, size_t len) {
    uint8_t* p = const_cast<uint8_t*>(data);
    const uint8_t* end = data + len;
    size_t length;
    
    // TimeStampResp ::= SEQUENCE {
    //     status PKIStatusInfo,
    //     timeStampToken TimeStampToken OPTIONAL
    // }
    
    if (mbedtls_asn1_get_tag(&p, end, &length, 
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return false;
    }
    
    // Skip status (we assume success for now)
    size_t status_len;
    if (mbedtls_asn1_get_tag(&p, end, &status_len, 
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return false;
    }
    p += status_len;
    
    // Get TimeStampToken (SignedData)
    return parseTimeStampToken(p, end - p);
}

bool TSAVerifier::Impl::parseTimeStampToken(const uint8_t* data, size_t len) {
    uint8_t* p = const_cast<uint8_t*>(data);
    const uint8_t* end = data + len;
    size_t length;
    
    // SignedData is wrapped in a ContentInfo
    if (mbedtls_asn1_get_tag(&p, end, &length, 
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return false;
    }
    
    // Skip contentType OID
    size_t oid_len;
    if (mbedtls_asn1_get_tag(&p, end, &oid_len, MBEDTLS_ASN1_OID) != 0) {
        return false;
    }
    p += oid_len;
    
    // Get content [0] EXPLICIT
    if (mbedtls_asn1_get_tag(&p, end, &length, 
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED) != 0) {
        return false;
    }
    
    return parseSignedData(p, length);
}

bool TSAVerifier::Impl::parseSignedData(const uint8_t* data, size_t len) {
    uint8_t* p = const_cast<uint8_t*>(data);
    const uint8_t* end = data + len;
    size_t length;
    
    // SignedData ::= SEQUENCE
    if (mbedtls_asn1_get_tag(&p, end, &length, 
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return false;
    }
    
    // Skip version
    size_t ver_len;
    if (mbedtls_asn1_get_tag(&p, end, &ver_len, MBEDTLS_ASN1_INTEGER) != 0) {
        return false;
    }
    p += ver_len;
    
    // Skip digestAlgorithms
    if (mbedtls_asn1_get_tag(&p, end, &length, 
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) != 0) {
        return false;
    }
    p += length;
    
    // Get encapContentInfo
    if (mbedtls_asn1_get_tag(&p, end, &length, 
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return false;
    }
    
    const uint8_t* content_end = p + length;
    
    // Skip eContentType OID
    if (mbedtls_asn1_get_tag(&p, content_end, &length, MBEDTLS_ASN1_OID) != 0) {
        return false;
    }
    p += length;
    
    // Get eContent [0] EXPLICIT
    if (mbedtls_asn1_get_tag(&p, content_end, &length, 
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED) != 0) {
        return false;
    }
    
    // Get OCTET STRING
    if (mbedtls_asn1_get_tag(&p, content_end, &length, MBEDTLS_ASN1_OCTET_STRING) != 0) {
        return false;
    }
    
    // Parse TSTInfo
    return parseTSTInfo(p, length);
}

bool TSAVerifier::Impl::parseTSTInfo(const uint8_t* data, size_t len) {
    uint8_t* p = const_cast<uint8_t*>(data);
    const uint8_t* end = data + len;
    size_t length;
    
    // TSTInfo ::= SEQUENCE
    if (mbedtls_asn1_get_tag(&p, end, &length, 
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return false;
    }
    
    // version INTEGER
    int version;
    if (mbedtls_asn1_get_int(&p, end, &version) != 0) {
        return false;
    }
    
    // policy OID
    if (mbedtls_asn1_get_tag(&p, end, &length, MBEDTLS_ASN1_OID) != 0) {
        return false;
    }
    timestampInfo.policyOID = parseOID(p, length);
    p += length;
    
    // messageImprint MessageImprint
    if (mbedtls_asn1_get_tag(&p, end, &length, 
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return false;
    }
    
    const uint8_t* mi_end = p + length;
    
    // hashAlgorithm AlgorithmIdentifier
    if (mbedtls_asn1_get_tag(&p, mi_end, &length, 
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return false;
    }
    
    // Get algorithm OID
    uint8_t* alg_p = p;
    size_t alg_len;
    if (mbedtls_asn1_get_tag(&alg_p, mi_end, &alg_len, MBEDTLS_ASN1_OID) != 0) {
        return false;
    }
    timestampInfo.hashAlgorithm = parseOID(alg_p, alg_len);
    p += length;
    
    // hashedMessage OCTET STRING
    if (mbedtls_asn1_get_tag(&p, mi_end, &length, MBEDTLS_ASN1_OCTET_STRING) != 0) {
        return false;
    }
    timestampInfo.messageImprint.assign(p, p + length);
    p = const_cast<uint8_t*>(mi_end);
    
    // serialNumber INTEGER
    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);
    if (mbedtls_asn1_get_mpi(&p, end, &serial) != 0) {
        mbedtls_mpi_free(&serial);
        return false;
    }
    
    // Convert serial to string
    char serial_str[256];
    size_t serial_len;
    mbedtls_mpi_write_string(&serial, 16, serial_str, sizeof(serial_str), &serial_len);
    timestampInfo.serialNumber = serial_str;
    mbedtls_mpi_free(&serial);
    
    // genTime GeneralizedTime
    if (mbedtls_asn1_get_tag(&p, end, &length, MBEDTLS_ASN1_GENERALIZED_TIME) == 0) {
        timestampInfo.timestamp = parseTime(p, length, MBEDTLS_ASN1_GENERALIZED_TIME);
        p += length;
    } else if (mbedtls_asn1_get_tag(&p, end, &length, MBEDTLS_ASN1_UTC_TIME) == 0) {
        timestampInfo.timestamp = parseTime(p, length, MBEDTLS_ASN1_UTC_TIME);
        p += length;
    } else {
        return false;
    }
    
    // Skip accuracy if present
    if (p < end && *p == (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        if (mbedtls_asn1_get_tag(&p, end, &length, 
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0) {
            p += length;
        }
    }
    
    // ordering BOOLEAN DEFAULT FALSE
    timestampInfo.certReq = false;
    if (p < end && *p == MBEDTLS_ASN1_BOOLEAN) {
        int ordering;
        if (mbedtls_asn1_get_bool(&p, end, &ordering) == 0) {
            // Skip ordering
        }
    }
    
    // nonce INTEGER OPTIONAL
    if (p < end && *p == MBEDTLS_ASN1_INTEGER) {
        mbedtls_mpi nonce;
        mbedtls_mpi_init(&nonce);
        if (mbedtls_asn1_get_mpi(&p, end, &nonce) == 0) {
            // Skip nonce
        }
        mbedtls_mpi_free(&nonce);
    }
    
    // tsa [0] GeneralName OPTIONAL
    if (p < end && *p == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) {
        if (mbedtls_asn1_get_tag(&p, end, &length, 
                MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED) == 0) {
            // TODO: Parse GeneralName for TSA name
            timestampInfo.tsaName = "FreeTSA";
        }
    }
    
    return true;
}

std::string TSAVerifier::Impl::parseOID(const uint8_t* oid, size_t len) {
    std::stringstream ss;
    if (len == 0) return "";
    
    // First byte contains first two numbers
    unsigned int first = oid[0] / 40;
    unsigned int second = oid[0] % 40;
    ss << first << "." << second;
    
    // Parse remaining bytes
    unsigned int value = 0;
    for (size_t i = 1; i < len; i++) {
        value = (value << 7) | (oid[i] & 0x7F);
        if (!(oid[i] & 0x80)) {
            ss << "." << value;
            value = 0;
        }
    }
    
    return ss.str();
}

std::time_t TSAVerifier::Impl::parseTime(const uint8_t* time, size_t len, int tag) {
    struct tm tm_time;
    memset(&tm_time, 0, sizeof(tm_time));
    
    if (tag == MBEDTLS_ASN1_GENERALIZED_TIME) {
        // Format: YYYYMMDDHHmmssZ
        if (len < 14) return 0;
        
        tm_time.tm_year = (time[0] - '0') * 1000 + (time[1] - '0') * 100 +
                         (time[2] - '0') * 10 + (time[3] - '0') - 1900;
        tm_time.tm_mon = (time[4] - '0') * 10 + (time[5] - '0') - 1;
        tm_time.tm_mday = (time[6] - '0') * 10 + (time[7] - '0');
        tm_time.tm_hour = (time[8] - '0') * 10 + (time[9] - '0');
        tm_time.tm_min = (time[10] - '0') * 10 + (time[11] - '0');
        tm_time.tm_sec = (time[12] - '0') * 10 + (time[13] - '0');
    } else if (tag == MBEDTLS_ASN1_UTC_TIME) {
        // Format: YYMMDDHHmmssZ
        if (len < 12) return 0;
        
        int year = (time[0] - '0') * 10 + (time[1] - '0');
        tm_time.tm_year = (year >= 50) ? year + 1900 : year + 2000;
        tm_time.tm_year -= 1900;
        tm_time.tm_mon = (time[2] - '0') * 10 + (time[3] - '0') - 1;
        tm_time.tm_mday = (time[4] - '0') * 10 + (time[5] - '0');
        tm_time.tm_hour = (time[6] - '0') * 10 + (time[7] - '0');
        tm_time.tm_min = (time[8] - '0') * 10 + (time[9] - '0');
        tm_time.tm_sec = (time[10] - '0') * 10 + (time[11] - '0');
    }
    
    return timegm(&tm_time);
}

// Utility functions
std::vector<uint8_t> calculateSHA256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return {};
    }
    
    mbedtls_sha256_context sha256;
    mbedtls_sha256_init(&sha256);
    mbedtls_sha256_starts(&sha256, 0);
    
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        mbedtls_sha256_update(&sha256, 
                             reinterpret_cast<const unsigned char*>(buffer), 
                             file.gcount());
    }
    
    std::vector<uint8_t> hash(32);
    mbedtls_sha256_finish(&sha256, hash.data());
    mbedtls_sha256_free(&sha256);
    
    return hash;
}

std::vector<uint8_t> calculateSHA256(const uint8_t* data, size_t len) {
    std::vector<uint8_t> hash(32);
    mbedtls_sha256(data, len, hash.data(), 0);
    return hash;
}

} // namespace tsa
