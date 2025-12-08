# Issue: ZUC-128 Implementation Differs from Bouncy Castle Java Standard

## Summary

The ZUC-128 stream cipher implementation in sm-js-bc appears to use a simplified LFSR (Linear Feedback Shift Register) feedback polynomial that differs from the official implementation in Bouncy Castle Java and the ZUC specification.

## Details

### Current sm-js-bc Implementation

The LFSR feedback computation in sm-js-bc uses only two LFSR cells:
- `LFSR[0]` and `LFSR[15]`

**Reference**: Based on analysis of sm-js-bc v0.4.0 ZUC implementation

### Bouncy Castle Java (Standard Implementation)

The official Bouncy Castle Java implementation (`org.bouncycastle.crypto.engines.Zuc128CoreEngine`) uses the complete ZUC specification with five LFSR cells:
- `LFSR[0]`, `LFSR[4]`, `LFSR[10]`, `LFSR[13]`, and `LFSR[15]`

**Code from Bouncy Castle Java**:
```java
private void LFSRWithWorkMode()
{
    int f, v;
    f = LFSR[0];
    v = MulByPow2(LFSR[0], 8);
    f = AddM(f, v);
    v = MulByPow2(LFSR[4], 20);
    f = AddM(f, v);
    v = MulByPow2(LFSR[10], 21);
    f = AddM(f, v);
    v = MulByPow2(LFSR[13], 17);
    f = AddM(f, v);
    v = MulByPow2(LFSR[15], 15);
    f = AddM(f, v);
    
    /* update the state */
    // ... shift LFSR cells ...
    LFSR[15] = f;
}
```

**Reference**: 
- Repository: https://github.com/bcgit/bc-java
- File: `core/src/main/java/org/bouncycastle/crypto/engines/Zuc128CoreEngine.java`

### ZUC Specification

According to the official ZUC specification (GM/T 0001.1-2012 and 3GPP TS 35.222), the LFSR feedback polynomial is:

```
s[16] = (2^8 * s[0]) ⊕ (2^20 * s[4]) ⊕ (2^21 * s[10]) ⊕ (2^17 * s[13]) ⊕ (2^15 * s[15])
```

where operations are performed in GF(2^31-1).

This clearly specifies five LFSR cells: 0, 4, 10, 13, and 15.

## Impact

The simplified implementation may:
1. Not produce outputs compatible with standard ZUC implementations
2. Not pass official ZUC test vectors
3. Cause interoperability issues with other ZUC implementations
4. Potentially have different security properties than the standardized algorithm

## Test Vector Example

Using the standard test vector:
- **Key**: `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00` (16 zero bytes)
- **IV**: `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00` (16 zero bytes)

**Expected output** (from ZUC specification):
- First keystream word: `0x27BEDE74`
- Second keystream word: `0x018082DA`

Does the sm-js-bc implementation produce these values?

## Recommendation

Consider updating the ZUC-128 implementation to match the official Bouncy Castle Java implementation and ZUC specification by:

1. Using the complete LFSR feedback polynomial with all five taps (indices 0, 4, 10, 13, 15)
2. Verifying against official ZUC test vectors
3. Ensuring compatibility with other standard implementations

## Additional Information

### Other Potential Differences

During implementation of sm-py-bc aligned with Bouncy Castle Java, I also noticed:

1. **EK_d Constants**: The d constants for LFSR initialization should be:
   ```
   [0x44, 0x26, 0x62, 0x13, 0x57, 0x35, 0x71, 0x09,
    0x4D, 0x2F, 0x6B, 0x1A, 0x5E, 0x3C, 0x78, 0x47]
   ```

2. **F Function W Calculation**: Should use addition (not XOR) between (BRC[0] ^ F[0]) and F[1]:
   ```java
   W = (BRC[0] ^ F[0]) + F[1];  // Note: + not ^
   ```

3. **GF(2^31-1) Addition**: Should be implemented as:
   ```java
   private int AddM(final int a, final int b) {
       final int c = a + b;
       return (c & 0x7FFFFFFF) + (c >>> 31);
   }
   ```

### References

1. **ZUC Specification**: GM/T 0001.1-2012 (Chinese Cryptographic Standard)
2. **3GPP Specification**: 3GPP TS 35.222 - ZUC stream cipher for 3GPP confidentiality and integrity algorithms
3. **Bouncy Castle Java**: https://github.com/bcgit/bc-java (trusted reference implementation)
4. **IETF Draft**: draft-irtf-cfrg-zuc (ZUC Stream Cipher Algorithm)

### Context

This issue was discovered while implementing ZUC-128 for sm-py-bc (Python implementation) and comparing with both sm-js-bc and Bouncy Castle Java. The goal is to ensure all implementations are compatible and follow the official specification.

## Verification Steps

To verify if this is an issue:

1. Run the official ZUC test vectors through sm-js-bc
2. Compare with expected outputs from the specification
3. Compare with outputs from Bouncy Castle Java implementation

Would appreciate clarification on whether:
- Is this a known simplification for a specific use case?
- Are there plans to align with the standard specification?
- Should developers using sm-js-bc be aware of this difference?

Thank you for your work on sm-js-bc!
