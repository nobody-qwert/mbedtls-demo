# GitHub Actions Workflow for TSA Verification Tests

This directory contains the GitHub Actions workflow for running TSA (Time Stamp Authority) verification tests.

## Workflow: `tsa-verification-test.yml`

### Purpose
Runs the TSA verification test suite in a clean Ubuntu environment to validate:
- File hash calculation (SHA-256)
- Timestamp request generation
- Communication with FreeTSA service
- Timestamp response parsing and verification
- File integrity verification
- Tamper detection

### Trigger
**Manual trigger only** (`workflow_dispatch`) - This prevents overwhelming the FreeTSA server with automated requests.

### How to Run

1. Go to your repository on GitHub
2. Click on the "Actions" tab
3. Select "TSA Verification Tests" from the workflow list
4. Click "Run workflow" button
5. Optionally enable debug output if you need detailed information
6. Click "Run workflow" to start

### What It Does

1. **Environment Setup**:
   - Uses Ubuntu latest (currently 22.04)
   - Installs build dependencies (gcc, cmake, pkg-config, etc.)
   - Downloads and builds mbedTLS 3.6.0 (cached for faster subsequent runs)

2. **Build Process**:
   - Configures the project with CMake
   - Builds the TSA verification library and test executable
   - Verifies build artifacts

3. **Test Execution**:
   - Runs the comprehensive test suite (`test_tsa`)
   - Creates a dummy file for testing
   - Generates timestamp from FreeTSA service
   - Verifies timestamp authenticity
   - Tests tamper detection

4. **Artifact Collection**:
   - Captures complete test output logs
   - Saves generated test files (dummy_file.bin, .tsr files)
   - Uploads build artifacts (executables, libraries)
   - Retains artifacts for 30 days

### Artifacts Generated

After each run, the following artifacts are uploaded:

#### `tsa-verification-test-results`
- `test_output.log` - Complete test execution log
- `test/` directory - Generated test files including:
  - `dummy_file.bin` - Test binary file
  - `dummy_file.bin.tsr` - Timestamp response from FreeTSA
- `test_tsa` - Test executable
- `libtsa_verifier.a` - Static library

#### `build-failure-logs` (only on failure)
- CMake configuration logs for debugging build issues

### Debug Mode

Enable debug output when running the workflow to get additional information:
- Directory listings
- Environment variables
- Detailed build artifact information

### Network Requirements

The test requires internet access to:
- Download mbedTLS source (if not cached)
- Connect to FreeTSA service (freetsa.org) for timestamp generation

### Expected Test Flow

1. ✅ Create test binary file
2. ✅ Calculate SHA-256 hash
3. ✅ Generate timestamp from FreeTSA
4. ✅ Load TSA certificate
5. ✅ Verify timestamp authenticity
6. ✅ Test tamper detection (modify file and verify detection)

### Troubleshooting

If tests fail:

1. **Check the test output log** in the artifacts
2. **Enable debug mode** for more detailed information
3. **Check build failure logs** if the build step fails
4. **Network issues**: FreeTSA service might be temporarily unavailable

Common issues:
- **mbedTLS build failure**: Usually resolved by cache invalidation
- **FreeTSA timeout**: Network connectivity or service availability
- **Certificate issues**: Embedded certificate might need updating

### Maintenance

- **mbedTLS version**: Update version in workflow if needed
- **FreeTSA certificate**: May need periodic updates
- **Ubuntu version**: Workflow uses `ubuntu-latest`
- **Cache invalidation**: Change cache key if mbedTLS build issues persist

### Security Considerations

- Workflow only runs on manual trigger
- No secrets or sensitive data are used
- All network requests are to public services
- Artifacts are automatically cleaned up after 30 days
