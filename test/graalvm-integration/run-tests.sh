#!/bin/bash
# SM-PY-BC GraalVM Integration Tests Runner (Unix/Linux/Mac)
# Requires: GraalVM with Python support, Maven

set -e

echo "========================================"
echo "SM-PY-BC GraalVM Integration Tests"
echo "========================================"
echo ""

# Check if GraalVM Python is available
if ! command -v graalpy &> /dev/null; then
    echo "ERROR: GraalVM Python not found!"
    echo "Please install GraalVM and run: gu install python"
    exit 1
fi

# Check if Maven is available
if ! command -v mvn &> /dev/null; then
    echo "ERROR: Maven not found!"
    echo "Please install Maven 3.6+"
    exit 1
fi

# Parse command line arguments
PROFILE="standard"
TEST_CLASS=""
VERBOSE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        quick)
            PROFILE="quick"
            shift
            ;;
        standard)
            PROFILE="standard"
            shift
            ;;
        full)
            PROFILE="full"
            shift
            ;;
        parallel)
            PROFILE="parallel"
            shift
            ;;
        -v|--verbose)
            VERBOSE="-Dorg.slf4j.simpleLogger.defaultLogLevel=DEBUG"
            shift
            ;;
        sm2)
            TEST_CLASS="-Dtest=SM2SignatureInteropTest"
            shift
            ;;
        sm3)
            TEST_CLASS="-Dtest=SM3DigestInteropTest"
            shift
            ;;
        sm4)
            TEST_CLASS="-Dtest=SM4CipherInteropTest"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [quick|standard|full|parallel] [sm2|sm3|sm4] [-v|--verbose]"
            exit 1
            ;;
    esac
done

echo "Profile: $PROFILE"
if [ -n "$TEST_CLASS" ]; then
    echo "Test Class: $TEST_CLASS"
fi
echo ""

# Run tests
echo "Running tests..."
echo ""
mvn clean test -P $PROFILE $TEST_CLASS $VERBOSE

if [ $? -eq 0 ]; then
    echo ""
    echo "========================================"
    echo "Tests PASSED"
    echo "========================================"
else
    echo ""
    echo "========================================"
    echo "Tests FAILED"
    echo "========================================"
    exit 1
fi
