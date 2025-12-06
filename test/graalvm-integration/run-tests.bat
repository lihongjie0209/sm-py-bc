@echo off
REM SM-PY-BC GraalVM Integration Tests Runner (Windows)
REM Requires: GraalVM with Python support, Maven

echo ========================================
echo SM-PY-BC GraalVM Integration Tests
echo ========================================
echo.

REM Check if GraalVM is available
where graalpy >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: GraalVM Python not found!
    echo Please install GraalVM and run: gu install python
    exit /b 1
)

REM Check if Maven is available
where mvn >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Maven not found!
    echo Please install Maven 3.6+
    exit /b 1
)

REM Parse command line arguments
set PROFILE=standard
set TEST_CLASS=
set VERBOSE=

:parse_args
if "%~1"=="" goto end_parse
if /i "%~1"=="quick" set PROFILE=quick
if /i "%~1"=="standard" set PROFILE=standard
if /i "%~1"=="full" set PROFILE=full
if /i "%~1"=="parallel" set PROFILE=parallel
if /i "%~1"=="-v" set VERBOSE=-Dorg.slf4j.simpleLogger.defaultLogLevel=DEBUG
if /i "%~1"=="--verbose" set VERBOSE=-Dorg.slf4j.simpleLogger.defaultLogLevel=DEBUG
if /i "%~1"=="sm2" set TEST_CLASS=-Dtest=SM2SignatureInteropTest
if /i "%~1"=="sm3" set TEST_CLASS=-Dtest=SM3DigestInteropTest
if /i "%~1"=="sm4" set TEST_CLASS=-Dtest=SM4CipherInteropTest
shift
goto parse_args
:end_parse

echo Profile: %PROFILE%
if not "%TEST_CLASS%"=="" echo Test Class: %TEST_CLASS%
echo.

REM Run tests
echo Running tests...
echo.
mvn clean test -P %PROFILE% %TEST_CLASS% %VERBOSE%

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Tests PASSED
    echo ========================================
) else (
    echo.
    echo ========================================
    echo Tests FAILED
    echo ========================================
    exit /b 1
)
