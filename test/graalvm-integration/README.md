# SM-PY-BC GraalVM Integration Tests

This directory contains comprehensive cross-language tests that validate the compatibility between the Python SM-BC library and Java Bouncy Castle cryptographic implementations using GraalVM Polyglot.

## Overview

The test suite validates cross-language compatibility between:
- **Python SM-BC**: Python cryptographic library implementation
- **Java Bouncy Castle**: Industry-standard Java cryptographic library

The test suite verifies:

1. **Cross-Language Compatibility**: Python ↔ Java signature verification, encryption/decryption
2. **Algorithm Correctness**: SM2, SM3, SM4 implementations
3. **Performance Characteristics**: Comparative performance analysis
4. **Integration Scenarios**: End-to-end secure communication workflows
5. **Error Handling**: Edge cases and invalid input handling

## Prerequisites

### Required Software

1. **GraalVM 23.1.1+**: JDK with Python support
   - Download from: https://www.graalvm.org/downloads/
   - Install Python component: `gu install python`
2. **Java 17+**: Required for Bouncy Castle
3. **Maven 3.6+**: For build and dependency management
4. **Python 3.9+**: For SM-BC Python library development

### Install GraalVM Python

```bash
# After installing GraalVM, add Python support
gu install python

# Verify installation
graalpy --version
```

### Install SM-BC Python Library

```bash
# From the sm-py-bc directory
pip install -e .
# or
python setup.py develop
```

## Test Structure

### Test Classes

1. **`BaseGraalVMTest`**: Base class providing GraalVM setup and utility methods
2. **`SM2SignatureInteropTest`**: Cross-language signature verification tests
3. **`SM2EncryptionInteropTest`**: Cross-language encryption/decryption tests
4. **`SM3DigestInteropTest`**: Cross-language digest algorithm tests
5. **`SM4CipherInteropTest`**: Comprehensive SM4 cipher mode tests
6. **`ParameterizedInteropTest`**: Parameterized and property-based tests

### Test Coverage

#### SM2 Tests
- Java sign → Python verify
- Python sign → Java verify
- Key format compatibility
- Edge cases and error handling

#### SM3 Tests
- Standard test vector verification
- Cross-implementation verification
- Various input sizes and Unicode
- Binary data handling

#### SM4 Tests
- ECB/CBC/CTR/GCM modes
- Cross-platform verification
- Padding schemes
- AAD and MAC verification

## Running Tests

### Quick Start

```bash
cd test/graalvm-integration
mvn clean test
```

### Test Profiles

#### Quick Tests (~10 seconds)
```bash
mvn test -P quick
```

#### Standard Tests (~1 minute) - Default
```bash
mvn test
# or explicitly:
mvn test -P standard
```

#### Full Tests (~5 minutes)
```bash
mvn test -P full
```

### Running Specific Tests

```bash
# SM2 signature tests
mvn test -Dtest=SM2SignatureInteropTest

# SM3 digest tests
mvn test -Dtest=SM3DigestInteropTest

# SM4 cipher tests
mvn test -Dtest=SM4CipherInteropTest

# Parameterized tests
mvn test -Dtest=ParameterizedInteropTest
```

### Parallel Execution

```bash
mvn test -P parallel
```

## Expected Output

```
[INFO] Running com.sm.bc.graalvm.SM2SignatureInteropTest

=== Testing Java Sign → Python Verify ===
Java signature length: 64 bytes
✓ Java signature successfully verified by Python

=== Testing Python Sign → Java Verify ===
Python signature length: 64 bytes
✓ Python signature successfully verified by Java

[INFO] Tests run: 4, Failures: 0, Errors: 0, Skipped: 0
```

## Troubleshooting

### GraalVM Python Not Found

```
Error: No language for id python found
```

**Solution**: Install Python component:
```bash
gu install python
```

### SM-BC Python Library Not Found

```
ModuleNotFoundError: No module named 'sm_bc'
```

**Solution**: Install the library:
```bash
cd ../../
pip install -e .
```

### Memory Issues

```
OutOfMemoryError during tests
```

**Solution**: Increase JVM heap size:
```bash
export MAVEN_OPTS="-Xmx2G"
mvn test
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: GraalVM Python Integration Tests
on: [push, pull_request]

jobs:
  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup GraalVM
        uses: graalvm/setup-graalvm@v1
        with:
          version: '23.1.1'
          java-version: '17'
          components: 'python'
          
      - name: Install SM-BC Python Library
        run: |
          cd sm-py-bc
          pip install -e .
          
      - name: Run Integration Tests
        run: |
          cd sm-py-bc/test/graalvm-integration
          mvn clean test
```

## Dependencies

- **JUnit 5**: Test framework
- **Bouncy Castle 1.77**: Java cryptographic library
- **GraalVM Polyglot 23.1.1**: Python execution engine
- **Jackson 2.15.2**: JSON processing
- **SLF4J**: Logging framework

## Contributing

When adding new tests:

1. Extend appropriate base test class
2. Follow existing naming conventions
3. Include both success and failure scenarios
4. Add performance considerations
5. Update this README if needed
