#include "../include/tsa_verifier.h"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <ctime>
#include <chrono>
#include <cstring>

// Embedded FreeTSA certificate (from https://freetsa.org/files/cacert.pem)
const char* FREETSA_CERT = R"(-----BEGIN CERTIFICATE-----
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
Eg2MFJobz5g2jfqOgg==
-----END CERTIFICATE-----
)";

void printHex(const std::vector<uint8_t>& data, const std::string& label) {
    std::cout << label << ": ";
    for (size_t i = 0; i < data.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(data[i]);
        if ((i + 1) % 32 == 0) {
            std::cout << "\n" << std::string(label.length() + 2, ' ');
        }
    }
    std::cout << std::dec << std::endl;
}

void printTimestamp(const tsa::TimestampInfo& info) {
    std::cout << "\nTimestamp Information:" << std::endl;
    std::cout << "=====================" << std::endl;
    
    // Convert timestamp to readable format
    char timeStr[100];
    std::tm* tm = std::gmtime(&info.timestamp);
    std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S UTC", tm);
    std::cout << "Timestamp: " << timeStr << std::endl;
    
    std::cout << "Serial Number: " << info.serialNumber << std::endl;
    std::cout << "Policy OID: " << info.policyOID << std::endl;
    std::cout << "Hash Algorithm: " << info.hashAlgorithm << std::endl;
    std::cout << "TSA Name: " << info.tsaName << std::endl;
    printHex(info.messageImprint, "Message Imprint");
}

int main(int argc, char* argv[]) {
    std::cout << "FreeTSA Timestamp Verification Test" << std::endl;
    std::cout << "===================================" << std::endl;
    
    // Create a dummy binary file
    const std::string dummyFile = "test/dummy_file.bin";
    std::cout << "\n1. Creating dummy binary file..." << std::endl;
    {
        std::ofstream file(dummyFile, std::ios::binary);
        if (!file) {
            std::cerr << "Error: Failed to create dummy file" << std::endl;
            return 1;
        }
        
        // Write some random data
        const char* data = "This is a test binary file for timestamp verification. "
                          "Created at: " __DATE__ " " __TIME__ "\n"
                          "Random data follows:\n";
        file.write(data, strlen(data));
        
        // Add some binary data
        for (int i = 0; i < 256; ++i) {
            char byte = static_cast<char>(i);
            file.write(&byte, 1);
        }
    }
    
    // Calculate hash
    std::cout << "2. Calculating SHA-256 hash..." << std::endl;
    auto hash = tsa::calculateSHA256(dummyFile);
    printHex(hash, "File SHA-256");
    
    // Generate TSR using the script
    std::cout << "\n3. Generating timestamp from FreeTSA..." << std::endl;
    std::string tsrFile = dummyFile + ".tsr";
    std::string cmd = "../scripts/generate_tsr.sh " + dummyFile + " " + tsrFile;
    int ret = system(cmd.c_str());
    if (ret != 0) {
        std::cerr << "Error: Failed to generate TSR. Make sure you're in the tsa_verification directory." << std::endl;
        std::cerr << "Try running: cd tsa_verification && " << cmd << std::endl;
        return 1;
    }
    
    // Create TSA verifier
    std::cout << "\n4. Loading TSA verifier..." << std::endl;
    tsa::TSAVerifier verifier;
    
    // Load FreeTSA certificate
    std::cout << "5. Loading FreeTSA certificate..." << std::endl;
    if (!verifier.loadTSACertificate("../scripts/freetsa_cert.pem")) {
        std::cerr << "Error: Failed to load TSA certificate: " 
                  << verifier.getLastError() << std::endl;
        return 1;
    }
    
    // Load TSR
    std::cout << "6. Loading timestamp response..." << std::endl;
    if (!verifier.loadTSR(tsrFile)) {
        std::cerr << "Error: Failed to load TSR: " 
                  << verifier.getLastError() << std::endl;
        return 1;
    }
    
    // Verify the binary
    std::cout << "7. Verifying timestamp..." << std::endl;
    auto result = verifier.verifyBinary(dummyFile);
    
    if (result.isValid) {
        std::cout << "\n✓ Timestamp verification SUCCESSFUL!" << std::endl;
        printTimestamp(result.timestampInfo);
    } else {
        std::cout << "\n✗ Timestamp verification FAILED!" << std::endl;
        std::cout << "Error: " << result.error << std::endl;
    }
    
    // Test with modified file
    std::cout << "\n8. Testing with modified file..." << std::endl;
    {
        std::ofstream file(dummyFile, std::ios::binary | std::ios::app);
        file << "Modified!";
    }
    
    auto modifiedResult = verifier.verifyBinary(dummyFile);
    if (!modifiedResult.isValid) {
        std::cout << "✓ Correctly detected file modification!" << std::endl;
        std::cout << "Error: " << modifiedResult.error << std::endl;
    } else {
        std::cout << "✗ Failed to detect file modification!" << std::endl;
    }
    
    return 0;
}
