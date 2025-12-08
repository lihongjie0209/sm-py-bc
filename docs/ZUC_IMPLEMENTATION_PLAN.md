# ZUC Stream Cipher Implementation Plan

**Created:** 2025-12-08  
**Target Version:** 0.3.0  
**Reference:** sm-js-bc v0.4.0, Bouncy Castle Java  
**Standards:** GM/T 0001-2012, 3GPP TS 35.221, 3GPP TS 35.222

---

## 📋 Overview

ZUC (祖冲之算法) is a stream cipher algorithm designed by Chinese Academy of Sciences for use in 3GPP LTE and 5G mobile communications. Named after the ancient Chinese mathematician Zu Chongzhi.

### Variants

1. **ZUC-128**: Original version with 128-bit key and 128-bit IV
2. **ZUC-256**: Enhanced version with 256-bit key and 184/200-bit IV

### Applications

- **128-EEA3**: 3GPP confidentiality algorithm (encryption)
- **128-EIA3**: 3GPP integrity algorithm (MAC)
- **256-EEA3**: Enhanced 3GPP confidentiality 
- **256-EIA3**: Enhanced 3GPP integrity

---

## 🎯 Implementation Checklist

### Phase 1: Core ZUC-128 Engine (4-5 hours)

#### 1.1 StreamCipher Interface
- [ ] Create `src/sm_bc/crypto/stream_cipher.py`
  - Base interface for stream ciphers
  - Methods: `init()`, `process_byte()`, `process_bytes()`, `reset()`
  - Similar to Digest interface pattern

#### 1.2 ZUC-128 Engine
- [ ] Create `src/sm_bc/crypto/engines/zuc_engine.py`
  - S-boxes S0 and S1 (256 bytes each)
  - LFSR (Linear Feedback Shift Register) - 16 cells of 31 bits
  - Bit-reorganization (BR)
  - Non-linear function F
  - Initialization mode (32 rounds)
  - Working mode (keystream generation)
  - Key and IV loading

**Key Components:**
- **LFSR**: 16 registers, each 31 bits
- **S-boxes**: S0 and S1 for non-linear transformation
- **F function**: Uses R1, R2 registers
- **Initialization**: 32 rounds with feedback
- **Working**: Generate 32-bit keystream words

#### 1.3 Unit Tests
- [ ] Create `tests/unit/crypto/engines/test_zuc_engine.py`
  - Test initialization
  - Test keystream generation
  - Test encryption/decryption equivalence
  - Test with known test vectors from standards
  - Test edge cases (empty data, long data)

### Phase 2: ZUC-256 Engine (1-2 hours)

#### 2.1 ZUC-256 Engine
- [ ] Create `src/sm_bc/crypto/engines/zuc256_engine.py`
  - Extends ZUC-128 Engine
  - Key derivation for 256-bit key
  - IV derivation for 184/200-bit IV
  - Modified constants (d values)

#### 2.2 Unit Tests
- [ ] Add tests to `tests/unit/crypto/engines/test_zuc_engine.py`
  - Test ZUC-256 with 184-bit IV
  - Test ZUC-256 with 200-bit IV
  - Test key/IV derivation
  - Test compatibility with ZUC-128

### Phase 3: ZUC-128 MAC (2-3 hours)

#### 3.1 ZUC-128 MAC
- [ ] Create `src/sm_bc/crypto/macs/zuc128_mac.py`
  - Implements Mac interface
  - Uses ZUC-128 for keystream generation
  - 32-bit or 64-bit MAC output
  - Initialization with key and IV
  - Update mechanism
  - Final MAC calculation

**Algorithm:**
- Initialize ZUC with key and IV
- Process message blocks with keystream
- Apply final transformation
- Output 32 or 64-bit MAC

#### 3.2 Unit Tests
- [ ] Create `tests/unit/crypto/macs/test_zuc_mac.py`
  - Test MAC generation
  - Test MAC verification
  - Test with various message lengths
  - Test 32-bit and 64-bit MAC sizes
  - Test with known test vectors

### Phase 4: ZUC-256 MAC (1-2 hours)

#### 4.1 ZUC-256 MAC
- [ ] Create `src/sm_bc/crypto/macs/zuc256_mac.py`
  - Extends ZUC-128 MAC concept
  - Uses ZUC-256 for enhanced security
  - Supports 64-bit, 128-bit MAC output
  - Key and IV derivation

#### 4.2 Unit Tests
- [ ] Add tests to `tests/unit/crypto/macs/test_zuc_mac.py`
  - Test ZUC-256 MAC generation
  - Test various MAC sizes
  - Test with known vectors

### Phase 5: Documentation & Examples (1 hour)

#### 5.1 Documentation
- [ ] Update README.md
  - Add ZUC section
  - Usage examples
  - Performance notes
  - Standards compliance

- [ ] Create `docs/ZUC_SPECIFICATION.md`
  - Algorithm description
  - Standards references
  - Implementation notes
  - Test vectors

- [ ] Update CHANGELOG.md
  - v0.3.0 release notes
  - ZUC features

#### 5.2 Examples
- [ ] Create `examples/zuc_demo.py`
  - ZUC-128 encryption example
  - ZUC-256 encryption example
  - ZUC-128 MAC example
  - ZUC-256 MAC example

---

## 📊 Technical Details

### ZUC-128 Algorithm Structure

```
Initialization:
  Key (128 bits) + IV (128 bits) → LFSR[0..15]
  Run 32 rounds with feedback
  
Working Mode:
  Each clock:
    1. Bit-reorganization: Extract bits from LFSR → X0, X1, X2, X3
    2. F function: F(X0, X1, X2) → W
    3. Output: W ⊕ X3 → 32-bit keystream
    4. LFSR clock
```

### S-Box Operations

```python
def s0(x: int) -> int:
    """S0 substitution - 8-bit input to 8-bit output"""
    return S0_TABLE[x & 0xFF]

def s1(x: int) -> int:
    """S1 substitution - 8-bit input to 8-bit output"""
    return S1_TABLE[x & 0xFF]
```

### LFSR Update

```python
def lfsr_with_init_mode(u: int):
    """LFSR update in initialization mode with feedback"""
    v = lfsr_with_work_mode()
    s16 = v ^ u  # Feedback
    lfsr_rotate(s16)

def lfsr_with_work_mode() -> int:
    """LFSR update in working mode"""
    f = lfsr[0]
    v = mul_by_pow_2(lfsr[0], 8)
    v ^= mul_by_pow_2(lfsr[4], 20)
    v ^= mul_by_pow_2(lfsr[10], 21)
    v ^= mul_by_pow_2(lfsr[13], 17)
    v ^= mul_by_pow_2(lfsr[15], 15)
    return v
```

---

## 🧪 Test Vectors

### ZUC-128 Test Vector 1

```
Key:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
IV:   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Output (first 2 words):
  z[0] = 0x27BEDE74
  z[1] = 0x018082DA
```

### ZUC-128 Test Vector 2

```
Key:  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
IV:   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
Output (first 2 words):
  z[0] = 0x0657CFA0
  z[1] = 0x7096398B
```

---

## 📅 Timeline

| Phase | Estimated Time | Complexity |
|-------|---------------|------------|
| Phase 1: ZUC-128 Engine | 4-5 hours | High |
| Phase 2: ZUC-256 Engine | 1-2 hours | Medium |
| Phase 3: ZUC-128 MAC | 2-3 hours | Medium |
| Phase 4: ZUC-256 MAC | 1-2 hours | Low |
| Phase 5: Documentation | 1 hour | Low |
| **Total** | **9-13 hours** | |

### Milestones

- **Milestone 1** (5 hours): ZUC-128 Engine working
- **Milestone 2** (7 hours): ZUC-256 Engine working
- **Milestone 3** (10 hours): Both MACs working
- **Milestone 4** (11 hours): Documentation complete

---

## ✅ Success Criteria

1. ✅ ZUC-128 produces correct test vector outputs
2. ✅ ZUC-256 produces correct test vector outputs  
3. ✅ ZUC-128 MAC generates correct MACs
4. ✅ ZUC-256 MAC generates correct MACs
5. ✅ All tests passing (expect 30+ new tests)
6. ✅ Compatible with Bouncy Castle Java
7. ✅ Documentation complete

---

## 🔗 References

### Standards
- GM/T 0001-2012: ZUC Stream Cipher Algorithm
- 3GPP TS 35.221: Specification of the 3GPP Confidentiality and Integrity Algorithms 128-EEA3 & 128-EIA3
- 3GPP TS 35.222: Specification of the 3GPP Confidentiality and Integrity Algorithms 256-EEA3 & 256-EIA3

### Implementation References
- [sm-js-bc ZUC Implementation](https://github.com/lihongjie0209/sm-js-bc/tree/v0.4.0/src/crypto/engines)
- [Bouncy Castle Java ZUC](https://github.com/bcgit/bc-java)

### Academic Papers
- "The ZUC Stream Cipher" (2012)
- "Design and Analysis of ZUC-256" (2018)

---

**Status**: 📝 Planning Complete - Ready to Implement  
**Next Step**: Begin Phase 1 - ZUC-128 Engine Implementation
