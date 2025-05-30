#!/bin/bash

# Script to generate a timestamp response (TSR) from FreeTSA
# Usage: ./generate_tsr.sh <file_to_timestamp> [output_tsr_file]

if [ $# -lt 1 ]; then
    echo "Usage: $0 <file_to_timestamp> [output_tsr_file]"
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_TSR="${2:-${INPUT_FILE}.tsr}"
TSQ_FILE="${INPUT_FILE}.tsq"
FREETSA_URL="https://freetsa.org/tsr"

# Check if input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' not found"
    exit 1
fi

echo "Generating timestamp for: $INPUT_FILE"

# Step 1: Generate SHA-256 hash of the file
echo "1. Calculating SHA-256 hash..."
HASH=$(openssl dgst -sha256 -binary "$INPUT_FILE" | xxd -p -c 256)
echo "   Hash: $HASH"

# Step 2: Create timestamp request (TSQ)
echo "2. Creating timestamp request..."
openssl ts -query -data "$INPUT_FILE" -sha256 -cert -out "$TSQ_FILE"

if [ ! -f "$TSQ_FILE" ]; then
    echo "Error: Failed to create timestamp request"
    exit 1
fi

# Step 3: Send request to FreeTSA
echo "3. Sending request to FreeTSA..."
curl -H "Content-Type: application/timestamp-query" \
     --data-binary "@$TSQ_FILE" \
     "$FREETSA_URL" \
     -o "$OUTPUT_TSR"

if [ $? -ne 0 ]; then
    echo "Error: Failed to get timestamp response from FreeTSA"
    rm -f "$TSQ_FILE"
    exit 1
fi

# Step 4: Verify the response (optional)
echo "4. Verifying timestamp response..."
openssl ts -reply -in "$OUTPUT_TSR" -text

# Clean up
rm -f "$TSQ_FILE"

echo ""
echo "Timestamp response saved to: $OUTPUT_TSR"
echo "You can verify it with: openssl ts -reply -in $OUTPUT_TSR -text"
