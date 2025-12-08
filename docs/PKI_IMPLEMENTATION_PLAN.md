# PKI Implementation Plan for sm-py-bc

## Overview

Implement Public Key Infrastructure (PKI) support for sm-py-bc to align with sm-js-bc v0.4.0, providing ASN.1 encoding/decoding, PKCS standards, and X.509 certificate management.

## Status

**Created**: 2025-12-08  
**Target Version**: v0.3.0 (or v0.4.0)  
**Reference**: sm-js-bc v0.4.0 PKI implementation

## Components from sm-js-bc v0.4.0

### ASN.1 Support (Foundation)
```
src/asn1/
├── ASN1Encodable.ts          - Base interface for ASN.1 objects
├── ASN1Tags.ts               - ASN.1 tag constants
├── ASN1Integer.ts            - Integer encoding
├── ASN1OctetString.ts        - Octet string encoding
├── ASN1BitString.ts          - Bit string encoding
├── ASN1Sequence.ts           - Sequence encoding
├── ASN1ObjectIdentifier.ts   - OID encoding
├── AlgorithmIdentifier.ts    - Algorithm identifier
├── GMObjectIdentifiers.ts    - Chinese GM algorithm OIDs
├── DEREncoder.ts             - DER encoding utilities
└── DERDecoder.ts             - DER decoding utilities
```

### PKCS Standards
```
src/pkcs/
├── PrivateKeyInfo.ts         - PKCS#8 private key container
├── SubjectPublicKeyInfo.ts   - Public key container
├── SM2PrivateKeyEncoder.ts   - SM2-specific private key encoding
├── SM2PublicKeyEncoder.ts    - SM2-specific public key encoding
├── PKCS10CertificationRequest.ts         - CSR structure
└── PKCS10CertificationRequestBuilder.ts  - CSR builder
```

### X.509 Certificates
```
src/x509/
├── X509Name.ts               - Distinguished Name
├── X509Extensions.ts         - Certificate extensions
├── SubjectAlternativeName.ts - SAN extension
├── Validity.ts               - Validity period
├── TBSCertificate.ts         - To-Be-Signed certificate
├── X509Certificate.ts        - X.509 certificate
├── X509CertificateBuilder.ts - Certificate builder
├── CertificateList.ts        - CRL structure
└── CertPathValidator.ts      - Certificate chain validation
```

## Implementation Phases

### Phase 1: ASN.1 Foundation (Priority: High, ~8-10 hours)

Goal: Basic ASN.1 encoding/decoding for DER format

#### 1.1 Core ASN.1 Types
- [ ] Create `src/sm_bc/asn1/__init__.py`
- [ ] Implement `ASN1Encodable` protocol (base interface)
- [ ] Implement `ASN1Tags` constants
- [ ] Implement `ASN1Integer`
- [ ] Implement `ASN1OctetString`
- [ ] Implement `ASN1BitString`
- [ ] Implement `ASN1Sequence`
- [ ] Implement `ASN1ObjectIdentifier` (OID)

#### 1.2 DER Encoding/Decoding
- [ ] Implement `DEREncoder` utility
- [ ] Implement `DERDecoder` utility
- [ ] Add comprehensive unit tests for each type

#### 1.3 Algorithm Identifiers
- [ ] Implement `AlgorithmIdentifier`
- [ ] Implement `GMObjectIdentifiers` (SM2, SM3, SM4 OIDs)

**Estimated Time**: 8-10 hours  
**Dependencies**: None  
**Tests**: ~30-40 unit tests

### Phase 2: PKCS#8 Key Encoding (Priority: High, ~4-6 hours)

Goal: Encode/decode SM2 keys in standard PKCS#8 format

#### 2.1 Key Information Structures
- [ ] Implement `PrivateKeyInfo` (PKCS#8 private key wrapper)
- [ ] Implement `SubjectPublicKeyInfo` (public key wrapper)

#### 2.2 SM2-Specific Encoding
- [ ] Implement `SM2PrivateKeyEncoder`
  - Encode EC private key to PKCS#8 DER
  - Encode EC private key to PEM
  - Decode PKCS#8 to EC private key
- [ ] Implement `SM2PublicKeyEncoder`
  - Encode EC public key to SubjectPublicKeyInfo
  - Encode EC public key to PEM
  - Decode to EC public key

#### 2.3 Integration with Existing Code
- [ ] Add `to_pkcs8_der()` method to SM2 key classes
- [ ] Add `to_pkcs8_pem()` method to SM2 key classes
- [ ] Add `from_pkcs8_der()` class method
- [ ] Add `from_pkcs8_pem()` class method

**Estimated Time**: 4-6 hours  
**Dependencies**: Phase 1 (ASN.1)  
**Tests**: ~15-20 unit tests

### Phase 3: PKCS#10 CSR Support (Priority: Medium, ~4-5 hours)

Goal: Generate and parse certificate signing requests

#### 3.1 CSR Structure
- [ ] Implement `PKCS10CertificationRequest`
  - Parse existing CSRs
  - Verify CSR signature
  - Extract subject and public key

#### 3.2 CSR Builder
- [ ] Implement `PKCS10CertificationRequestBuilder`
  - Set subject distinguished name
  - Set public key
  - Add attributes
  - Sign with private key
  - Export to DER/PEM

#### 3.3 Integration
- [ ] Add CSR generation examples
- [ ] Add CSR verification utilities

**Estimated Time**: 4-5 hours  
**Dependencies**: Phase 1 (ASN.1), Phase 2 (PKCS#8)  
**Tests**: ~10-15 unit tests

### Phase 4: X.509 Certificates (Priority: Medium, ~8-10 hours)

Goal: Generate, parse, and validate X.509 certificates

#### 4.1 Certificate Components
- [ ] Implement `X509Name` (Distinguished Name)
  - Common Name (CN)
  - Organization (O)
  - Organizational Unit (OU)
  - Country (C)
  - State/Province (ST)
  - Locality (L)

- [ ] Implement `Validity` (Not Before / Not After)

- [ ] Implement `X509Extensions`
  - Basic Constraints
  - Key Usage
  - Extended Key Usage
  - Subject Key Identifier
  - Authority Key Identifier

- [ ] Implement `SubjectAlternativeName`
  - DNS names
  - IP addresses
  - Email addresses

#### 4.2 Certificate Structure
- [ ] Implement `TBSCertificate` (To-Be-Signed)
  - Version
  - Serial number
  - Signature algorithm
  - Issuer
  - Validity
  - Subject
  - Subject public key info
  - Extensions

- [ ] Implement `X509Certificate`
  - Parse DER/PEM certificates
  - Verify certificate signature
  - Extract all fields
  - Export to DER/PEM

#### 4.3 Certificate Builder
- [ ] Implement `X509CertificateBuilder`
  - Set issuer and subject
  - Set validity period
  - Set serial number
  - Set public key
  - Add extensions
  - Sign with CA private key
  - Generate self-signed certificates

**Estimated Time**: 8-10 hours  
**Dependencies**: Phase 1 (ASN.1), Phase 2 (PKCS#8)  
**Tests**: ~25-30 unit tests

### Phase 5: Advanced Features (Priority: Low, ~6-8 hours)

Goal: Certificate chains, CRLs, and validation

#### 5.1 Certificate Revocation Lists
- [ ] Implement `CertificateList` (CRL structure)
  - Parse CRLs
  - Check if certificate is revoked
  - Generate CRLs

#### 5.2 Certificate Path Validation
- [ ] Implement `CertPathValidator`
  - Build certificate chains
  - Verify chain signatures
  - Check validity periods
  - Check revocation status
  - Validate certificate purposes

#### 5.3 Additional Utilities
- [ ] Certificate fingerprint calculation
- [ ] Certificate comparison utilities
- [ ] PEM file parsing (multiple certificates)

**Estimated Time**: 6-8 hours  
**Dependencies**: Phase 4 (X.509)  
**Tests**: ~20-25 unit tests

## Total Estimates

| Phase | Estimated Hours | Priority | Dependencies |
|-------|----------------|----------|--------------|
| Phase 1: ASN.1 | 8-10 | High | None |
| Phase 2: PKCS#8 | 4-6 | High | Phase 1 |
| Phase 3: PKCS#10 | 4-5 | Medium | Phases 1, 2 |
| Phase 4: X.509 | 8-10 | Medium | Phases 1, 2 |
| Phase 5: Advanced | 6-8 | Low | Phase 4 |
| **Total** | **30-39 hours** | | |

## Incremental Delivery Strategy

### Milestone 1: Basic Key Export (Phases 1-2, ~14 hours)
**Deliverable**: Export SM2 keys to PKCS#8 PEM/DER format
- Users can export keys for interoperability
- Foundation for all other features

### Milestone 2: CSR Generation (Phase 3, ~5 hours)
**Deliverable**: Generate certificate signing requests
- Users can request certificates from CAs
- Common PKI workflow enabled

### Milestone 3: Certificate Management (Phase 4, ~10 hours)
**Deliverable**: Generate and parse X.509 certificates
- Self-signed certificates for testing
- Certificate parsing for validation
- Complete basic PKI functionality

### Milestone 4: Production PKI (Phase 5, ~8 hours)
**Deliverable**: Full PKI with chain validation and CRLs
- Production-ready certificate management
- Enterprise PKI features

## Python-Specific Considerations

### Library Dependencies

Consider using existing Python libraries where appropriate:
- **cryptography**: Well-tested ASN.1 and X.509 implementation
- **pyasn1**: Pure Python ASN.1 library
- **Option**: Implement from scratch for full control and learning

**Recommendation**: Implement from scratch initially for:
1. Full compatibility with sm-js-bc API
2. No external dependencies beyond existing ones
3. Educational value
4. Tight integration with SM algorithms

Can always add cryptography interop later.

### Code Organization

```
src/sm_bc/
├── asn1/              # ASN.1 encoding/decoding
│   ├── __init__.py
│   ├── encodable.py   # Base protocol
│   ├── tags.py        # Tag constants
│   ├── types.py       # Basic types
│   ├── oid.py         # Object identifiers
│   ├── der.py         # DER encoding/decoding
│   └── gm_oids.py     # GM algorithm OIDs
├── pkcs/              # PKCS standards
│   ├── __init__.py
│   ├── pkcs8.py       # PKCS#8 key encoding
│   ├── pkcs10.py      # PKCS#10 CSR
│   └── sm2_keys.py    # SM2-specific encoders
└── x509/              # X.509 certificates
    ├── __init__.py
    ├── name.py        # Distinguished names
    ├── extensions.py  # Certificate extensions
    ├── certificate.py # X.509 certificate
    ├── builder.py     # Certificate builder
    ├── crl.py         # Certificate revocation lists
    └── validator.py   # Path validation
```

## Testing Strategy

### Unit Tests
- Test each ASN.1 type independently
- Test encoding/decoding round-trips
- Test edge cases (empty, maximum values, etc.)

### Integration Tests
- Generate keys → Export to PKCS#8 → Import back → Verify
- Generate CSR → Parse CSR → Verify signature
- Generate certificate → Parse → Verify → Use for signing

### Cross-Compatibility Tests
- Export from sm-py-bc, import in OpenSSL
- Export from OpenSSL, import in sm-py-bc
- Verify with GmSSL
- Compare with sm-js-bc outputs

### Test Vectors
- Use standard test vectors where available
- Generate test vectors from Bouncy Castle Java
- Create sm-specific test vectors

## Documentation Requirements

### API Documentation
- Complete docstrings for all public APIs
- Type hints for all functions
- Usage examples in docstrings

### User Guides
- "Getting Started with PKI"
- "Exporting SM2 Keys to PEM"
- "Generating CSRs"
- "Creating Self-Signed Certificates"
- "Certificate Chain Validation"

### Migration Guides
- From existing key storage formats
- From/to OpenSSL formats
- From/to sm-js-bc formats

## Success Criteria

### Phase 1-2 Success (Minimal PKI)
- [ ] Can export SM2 private/public keys to PKCS#8 PEM
- [ ] Can import SM2 keys from PKCS#8 PEM
- [ ] Keys work with OpenSSL
- [ ] 100% test coverage for implemented features

### Phase 3-4 Success (Complete Basic PKI)
- [ ] Can generate CSRs with SM2 keys
- [ ] Can generate self-signed certificates
- [ ] Can parse existing certificates
- [ ] Certificates work with OpenSSL/GmSSL

### Phase 5 Success (Production PKI)
- [ ] Can validate certificate chains
- [ ] Can check CRLs
- [ ] Production-ready error handling
- [ ] Comprehensive documentation

## Risk Assessment

### High Risk
- **ASN.1 complexity**: DER encoding is complex and error-prone
  - Mitigation: Extensive testing, cross-validation with existing tools
  
- **Interoperability**: Must work with OpenSSL, GmSSL, etc.
  - Mitigation: Test with multiple tools, use standard test vectors

### Medium Risk
- **Time estimate**: PKI is a large surface area
  - Mitigation: Incremental delivery, prioritize core features

### Low Risk
- **API stability**: Based on stable sm-js-bc API
- **Algorithm correctness**: SM algorithms already implemented

## Future Enhancements (Beyond v0.4.0)

- PKCS#12 support (key stores)
- Online Certificate Status Protocol (OCSP)
- Certificate Transparency support
- Hardware Security Module (HSM) integration
- Certificate Templates
- Policy constraints and name constraints

## References

- RFC 5280: X.509 Certificate and CRL Profile
- RFC 5208: PKCS#8 Private Key Information Syntax
- RFC 2986: PKCS#10 Certificate Request Syntax
- ITU-T X.690: ASN.1 encoding rules (DER)
- GM/T 0006: Cryptographic Application Identifier Specification
- sm-js-bc v0.4.0 implementation
- Bouncy Castle Java PKI implementation
