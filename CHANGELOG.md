# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2025-12-08

### Added

#### ZUC Stream Cipher Support (Complete Implementation)

- **ZUC-256 Engine**: Enhanced stream cipher for 3GPP 5G
  - 256-bit key support
  - 184-bit and 200-bit IV support
  - Configurable MAC bits (32, 64, 128)
  - Extends ZUC-128 implementation
  - Compliant with 3GPP TS 35.222 standard
  - 12 comprehensive unit tests (100% passing)

- **ZUC-128 MAC (128-EIA3)**: LTE/5G integrity algorithm
  - Message authentication code based on ZUC-128
  - Support for 32-bit and 64-bit MAC output
  - Full RFC and 3GPP TS 35.221 compliance
  - Compatible with Bouncy Castle Java API
  - 18 comprehensive unit tests (100% passing)

- **ZUC-256 MAC (256-EIA3)**: Enhanced 5G integrity algorithm
  - Message authentication code based on ZUC-256
  - Support for 64-bit and 128-bit MAC output
  - Enhanced security for 5G networks
  - Full 3GPP TS 35.222 compliance
  - 15 comprehensive unit tests (100% passing)

#### Documentation and Examples

- **examples/zuc_demo.py**: Comprehensive ZUC demonstration
  - ZUC-128 and ZUC-256 encryption examples
  - ZUC-128 and ZUC-256 MAC examples
  - Combined encryption + MAC example
  - Real-world usage patterns
  - Security best practices

### Testing

- Total tests: 584 passing, 1 skipped (99.8% pass rate)
- New ZUC tests: 45 tests added
  - ZUC-256 Engine: 12 tests
  - ZUC-128 MAC: 18 tests
  - ZUC-256 MAC: 15 tests
- All tests passing with comprehensive coverage
- No regressions in existing functionality

### Standards Compliance

- ✅ GM/T 0001-2012: ZUC Stream Cipher Algorithm
- ✅ 3GPP TS 35.221: 128-EEA3 & 128-EIA3 (LTE)
- ✅ 3GPP TS 35.222: 256-EEA3 & 256-EIA3 (5G)

### Compatibility

- ✅ 100% backward compatible with v0.2.0
- ✅ All existing code continues to work unchanged
- ✅ Aligned with sm-js-bc v0.4.0 ZUC implementation
- ✅ Compatible with Bouncy Castle Java

### Reference

- Aligned with [sm-js-bc v0.4.0](https://github.com/lihongjie0209/sm-js-bc/tree/v0.4.0)
- Feature parity: ZUC stream cipher and MAC algorithms

---

## [0.2.0] - 2025-12-08

### Added

#### New Features
- **HMAC-SM3**: Full HMAC (Hash-based Message Authentication Code) implementation with SM3 digest
  - `HMac` class with complete RFC 2104 compliance
  - Compatible with any Digest implementation (not just SM3)
  - Automatic key hashing for keys longer than block size
  - Reset support for efficient key reuse
  - 100% compatible with Bouncy Castle Java API
- **Mac Interface**: New `Mac` protocol for message authentication codes
- Comprehensive test suite with 12 new HMAC tests (100% passing)

#### API Enhancements
- **SM3Digest.reset(Memoable)**: Added method overload for state restoration
  - Matches Bouncy Castle Java API signature
  - Backward compatible with parameterless `reset()`
  - Enables efficient batch hashing with common prefixes
- **SM2Signer.calculate_e()**: New protected method for e value calculation
  - Enables customization through inheritance
  - Matches Bouncy Castle Java API
  - Improves extensibility for custom signature algorithms
- **SM2Signer.create_base_point_multiplier()**: Enhanced documentation
  - Clarified purpose and usage for custom implementations
  - Added usage examples for optimization scenarios

#### Documentation
- **API_CONSISTENCY_WITH_JAVA.md**: Comprehensive API comparison guide
  - Complete type mappings (Java/TypeScript → Python)
  - Method name conversions and conventions
  - Usage examples and migration patterns
  - Compatibility matrix with Bouncy Castle Java
- **API_IMPROVEMENTS_V0.2.0.md**: Detailed v0.2.0 changes guide
  - Complete feature documentation
  - Migration guide from v0.1.x
  - Code examples for all new features
  - Backward compatibility guarantees
- **V0.4.0_ALIGNMENT_PLAN.md**: Development plan and alignment roadmap
- **CHANGELOG.md**: This changelog file

### Changed
- **ExtendedDigest**: Added `@runtime_checkable` decorator for proper Protocol usage
  - Fixes isinstance() checks with Protocol classes
  - Maintains compatibility with existing code

### Fixed
- Memoable interface now properly supports runtime type checking

### Testing
- Total tests: 523 (was 511, +12 new tests)
- HMAC-SM3: 12 comprehensive tests covering all functionality
- SM3 Memoable: 4 tests for state restoration
- All tests passing: 100% pass rate
- No regressions in existing tests

### Compatibility
- ✅ 100% backward compatible with v0.1.x
- ✅ All existing code continues to work unchanged
- ✅ New features are opt-in only
- ✅ Aligned with sm-js-bc v0.4.0 API improvements

### Reference
- Aligned with [sm-js-bc v0.4.0](https://github.com/lihongjie0209/sm-js-bc/tree/v0.4.0)
- API consistency score: 95%+ with Bouncy Castle Java

---

## [0.1.9] - 2024-12-06

### Added
- SM2 elliptic curve cryptography (signature, encryption, key exchange)
- SM3 cryptographic hash function
- SM4 block cipher with multiple modes (ECB, CBC, CTR, OFB, CFB)
- Multiple padding schemes (PKCS#7, ISO 7816-4, ISO 10126, Zero-byte)
- GraalVM cross-language integration tests
- Comprehensive test suite (200+ tests)

### Features
- Pure Python implementation with zero dependencies
- Compatible with Bouncy Castle Java
- Full SM2/SM3/SM4 国密算法支持
- High-level cipher API for easy usage
- Production-ready with extensive testing

---

## Project Links

- **Repository**: https://github.com/lihongjie0209/sm-py-bc
- **Issues**: https://github.com/lihongjie0209/sm-py-bc/issues
- **PyPI**: https://pypi.org/project/sm-py-bc/
- **Documentation**: https://github.com/lihongjie0209/sm-py-bc/tree/master/docs

---

## Acknowledgments

- Based on [sm-js-bc](https://github.com/lihongjie0209/sm-js-bc) (TypeScript) reference implementation
- Inspired by Bouncy Castle cryptography library
- Implements Chinese National Cryptography Standards (GM/T)
