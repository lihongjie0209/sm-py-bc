# Blocked Tests

This directory contains tests that are ready but blocked by missing implementations.

## crypto_params/

**Tests**: 21 tests (10 + 11)
**Status**: ❌ BLOCKED - Classes not implemented
**Reason**: Missing `sm_py_bc.crypto.params` package

### Required Classes
- `ECDomainParameters` - Encapsulates curve parameters
- `ECPublicKeyParameters` - Encapsulates public key
- `ECPrivateKeyParameters` - Encapsulates private key
- `AsymmetricKeyParameter` - Base class

### Files
- `test_ec_domain_parameters.py` - 10 tests for ECDomainParameters
- `test_ec_key_parameters.py` - 11 tests for key parameters

### How to Unblock
1. Implement the classes in `sm_py_bc/crypto/params/`
2. Move these test files back to `tests/unit/crypto/params/`
3. Run: `pytest tests/unit/crypto/params/ -v`
4. All tests should pass

### Reference
See `docs/DEV_HANDOFF_ISSUES_20251206.md` Issue #3 for implementation details.

---

**Note**: These tests are aligned with sm-js-bc and will work as soon as the classes are implemented.
