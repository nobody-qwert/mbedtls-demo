# GitHub Actions Setup for TSA Verification Tests

## What Was Created

✅ **GitHub Actions Workflow**: `.github/workflows/tsa-verification-test.yml`
✅ **Documentation**: `.github/workflows/README.md`
✅ **This Summary**: `GITHUB_ACTIONS_SETUP.md`

## Quick Start

1. **Push these files to your GitHub repository**:
   ```bash
   git add .github/
   git add GITHUB_ACTIONS_SETUP.md
   git commit -m "Add GitHub Actions workflow for TSA verification tests"
   git push
   ```

2. **Run the workflow**:
   - Go to your repository on GitHub
   - Click "Actions" tab
   - Select "TSA Verification Tests"
   - Click "Run workflow"
   - Optionally enable debug output
   - Click "Run workflow" to start

## What the Workflow Does

🔧 **Environment Setup**:
- Ubuntu latest (22.04)
- Installs build tools (gcc, cmake, pkg-config, etc.)
- Downloads and builds mbedTLS 3.6.0 (cached for speed)

🏗️ **Build Process**:
- Configures project with CMake
- Builds TSA verification library and test executable

🧪 **Test Execution**:
- Runs your `test_tsa` executable
- Creates dummy file for testing
- Generates timestamp from FreeTSA service
- Verifies timestamp authenticity
- Tests tamper detection

📦 **Artifact Collection**:
- Complete test output logs
- Generated test files (.bin, .tsr)
- Build artifacts (executables, libraries)
- Retained for 30 days

## Key Features

- ✅ **Manual trigger only** - Won't overwhelm FreeTSA server
- ✅ **Ubuntu latest** - Single, reliable environment
- ✅ **Comprehensive logging** - Full test output captured
- ✅ **Artifact upload** - All test files preserved
- ✅ **Debug mode** - Optional detailed output
- ✅ **Caching** - mbedTLS build cached for speed
- ✅ **Error handling** - Build logs on failure

## Expected Test Results

When successful, you'll see:
1. ✅ Dummy binary file created
2. ✅ SHA-256 hash calculated
3. ✅ Timestamp generated from FreeTSA
4. ✅ TSA certificate loaded
5. ✅ Timestamp verification successful
6. ✅ Tamper detection working

## Artifacts You'll Get

After each run, download:
- `tsa-verification-test-results.zip` containing:
  - `test_output.log` - Complete test log
  - `test/dummy_file.bin` - Test file
  - `test/dummy_file.bin.tsr` - Timestamp response
  - `test_tsa` - Test executable
  - `libtsa_verifier.a` - Your library

## Troubleshooting

If tests fail:
1. Check the `test_output.log` in artifacts
2. Enable debug mode for more details
3. Check if FreeTSA service is available
4. Verify mbedTLS installation in logs

## Next Steps

1. **Commit and push** the workflow files
2. **Test the workflow** by running it manually
3. **Review artifacts** to ensure everything works
4. **Use as needed** for testing your TSA verification

The workflow is designed to be respectful to the FreeTSA service (manual trigger only) while providing comprehensive testing and artifact collection for your TSA verification project.
