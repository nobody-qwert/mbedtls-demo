# Technical Explanation: Why Manual ASN.1 Parsing Instead of mbedtls_pkcs7_parse_der()

## Executive Summary

The current TSA verification implementation uses manual ASN.1 parsing with `mbedtls_asn1_*` functions instead of the higher-level `mbedtls_pkcs7_parse_der()` function. This document explains the technical reasons behind this architectural decision.

## Background

Time Stamp Authority (TSA) verification involves parsing RFC 3161 Time-Stamp Response (TSR) structures, which contain PKCS#7 SignedData with embedded TSTInfo (Time-Stamp Token Info). There are two potential approaches:

1. **Manual ASN.1 parsing** (current implementation)
2. **mbedTLS PKCS#7 API** using `mbedtls_pkcs7_parse_der()`

## Why Manual ASN.1 Parsing Was Chosen

### 1. **mbedTLS PKCS#7 API Limitations**

The mbedTLS PKCS#7 implementation has several significant limitations documented in the official header file:

```c
/**
 * Note: For the time being, this implementation of the PKCS #7 cryptographic
 * message syntax is a partial implementation of RFC 2315.
 * Differences include:
 *  - The RFC specifies 6 different content types. The only type currently
 *    supported in Mbed TLS is the signed-data content type.
 *  - The only supported PKCS #7 Signed Data syntax version is version 1
 *  - The RFC specifies support for BER. This implementation is limited to
 *    DER only.
 *  - The RFC allows for the signed Data type to contain contentInfo. This
 *    implementation assumes the type is DATA and the content is empty.
 */
```

**Critical Issue**: The last point is particularly problematic for TSA verification. The mbedTLS PKCS#7 implementation "assumes the type is DATA and the content is empty," but TSA tokens contain TSTInfo as encapsulated content, not empty DATA.

### 2. **API Design Limitations**

The mbedTLS PKCS#7 structure uses private fields:

```c
typedef struct mbedtls_pkcs7 {
    mbedtls_pkcs7_buf MBEDTLS_PRIVATE(raw);
    mbedtls_pkcs7_signed_data MBEDTLS_PRIVATE(signed_data);
} mbedtls_pkcs7;
```

The `MBEDTLS_PRIVATE()` macro makes these fields inaccessible to application code, meaning we cannot extract the encapsulated TSTInfo content even if it were properly parsed.

### 3. **Availability Issues**

PKCS#7 support in mbedTLS is:
- Relatively new (introduced in recent versions)
- Not always enabled in default builds
- May not be available in older or embedded systems
- Often missing from package manager installations

### 4. **TSA-Specific Requirements**

TSA verification requires:
- Parsing the outer TimeStampResp structure
- Extracting the TimeStampToken (PKCS#7 SignedData)
- Accessing the encapsulated TSTInfo content
- Parsing TSTInfo fields (policy, messageImprint, timestamp, etc.)

The mbedTLS PKCS#7 API doesn't provide access to the encapsulated content, making it unsuitable for TSA verification.

## Current Implementation Benefits

### 1. **Complete Control**
- Full access to all ASN.1 structures
- Can parse TSA-specific extensions
- Handles all RFC 3161 requirements

### 2. **Reliability**
- Uses well-established `mbedtls_asn1_*` functions
- Available in all mbedTLS versions
- No dependency on experimental features

### 3. **Portability**
- Works with any mbedTLS installation
- No special build configuration required
- Compatible with embedded systems

### 4. **Maintainability**
- Clear, step-by-step parsing logic
- Easy to debug and extend
- Self-contained implementation

## Code Comparison

### Manual ASN.1 Approach (Current)
```cpp
bool parseTimeStampToken(const uint8_t* data, size_t len) {
    uint8_t* p = const_cast<uint8_t*>(data);
    const uint8_t* end = data + len;
    size_t length;
    
    // Parse ContentInfo
    if (mbedtls_asn1_get_tag(&p, end, &length, 
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return false;
    }
    
    // Skip contentType OID
    // ... detailed parsing logic
    
    // Extract and parse TSTInfo
    return parseTSTInfo(tstinfo_data, tstinfo_len);
}
```

### Attempted PKCS#7 Approach (Why it doesn't work)
```cpp
bool parseTimeStampTokenWithPKCS7(const uint8_t* data, size_t len) {
    int ret = mbedtls_pkcs7_parse_der(&pkcs7, data, len);
    if (ret != MBEDTLS_PKCS7_SIGNED_DATA) {
        return false;
    }
    
    // PROBLEM: Cannot access encapsulated content!
    // pkcs7.signed_data is PRIVATE
    // Even if accessible, mbedTLS assumes content is empty
    
    return false; // Cannot proceed
}
```

## Performance Considerations

The manual ASN.1 parsing approach is actually more efficient because:
- No intermediate data structure allocation
- Direct parsing without copying
- Minimal memory overhead
- Faster execution path

## Security Considerations

Both approaches use the same underlying mbedTLS cryptographic functions for:
- Certificate parsing and validation
- Signature verification
- Hash computation

The parsing method doesn't affect security - the cryptographic operations remain identical.

## Conclusion

The manual ASN.1 parsing approach was chosen because:

1. **Technical Necessity**: mbedTLS PKCS#7 API cannot access encapsulated content required for TSA verification
2. **Reliability**: Uses stable, well-tested ASN.1 parsing functions
3. **Portability**: Works across all mbedTLS versions and configurations
4. **Completeness**: Provides full access to all TSA-specific data structures

While `mbedtls_pkcs7_parse_der()` might seem like a more elegant solution, it is fundamentally incompatible with TSA verification requirements due to API limitations and design assumptions.

The current implementation is the correct technical choice for this use case.

## Future Considerations

If mbedTLS PKCS#7 API evolves to:
- Expose encapsulated content
- Support non-empty content types
- Provide access to parsed structures

Then migration to the PKCS#7 API could be considered. However, the current manual approach would still be preferred for maximum compatibility and control.
