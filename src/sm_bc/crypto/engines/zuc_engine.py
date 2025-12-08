"""
ZUC-128 Stream Cipher Engine.

ZUC (祖冲之算法) is a stream cipher algorithm designed for use in 3GPP 
confidentiality and integrity algorithms 128-EEA3 and 128-EIA3.

Named after the ancient Chinese mathematician Zu Chongzhi (429-500 AD).

Standards: GM/T 0001-2012, 3GPP TS 35.221
Reference: 
- org.bouncycastle.crypto.engines.ZucEngine (Bouncy Castle Java)
- src/crypto/engines/ZUCEngine.ts (sm-js-bc)
"""

from typing import Union, List, Optional
from sm_bc.crypto.stream_cipher import StreamCipher
from sm_bc.crypto.cipher_parameters import CipherParameters
from sm_bc.crypto.params.key_parameter import KeyParameter
from sm_bc.crypto.params.parameters_with_iv import ParametersWithIV
from sm_bc.exceptions import DataLengthException


class ZUCEngine(StreamCipher):
    """
    ZUC-128 stream cipher implementation.
    
    ZUC uses:
    - 128-bit key
    - 128-bit IV
    - 16-cell LFSR (Linear Feedback Shift Register)
    - Non-linear function F with two 32-bit registers R1, R2
    - S-boxes S0 and S1 for non-linear transformation
    
    Example usage:
        >>> from sm_bc.crypto.engines import ZUCEngine
        >>> from sm_bc.crypto.params import KeyParameter, ParametersWithIV
        >>> import secrets
        >>> 
        >>> key = secrets.token_bytes(16)  # 128-bit key
        >>> iv = secrets.token_bytes(16)   # 128-bit IV
        >>> 
        >>> cipher = ZUCEngine()
        >>> cipher.init(True, ParametersWithIV(KeyParameter(key), iv))
        >>> 
        >>> plaintext = b"Hello, ZUC!"
        >>> ciphertext = bytearray(len(plaintext))
        >>> cipher.process_bytes(plaintext, 0, len(plaintext), ciphertext, 0)
    """
    
    # S-Box S0 (256 bytes)
    S0 = bytes([
        0x3e, 0x72, 0x5b, 0x47, 0xca, 0xe0, 0x00, 0x33, 0x04, 0xd1, 0x54, 0x98, 0x09, 0xb9, 0x6d, 0xcb,
        0x7b, 0x1b, 0xf9, 0x32, 0xaf, 0x9d, 0x6a, 0xa5, 0xb8, 0x2d, 0xfc, 0x1d, 0x08, 0x53, 0x03, 0x90,
        0x4d, 0x4e, 0x84, 0x99, 0xe4, 0xce, 0xd9, 0x91, 0xdd, 0xb6, 0x85, 0x48, 0x8b, 0x29, 0x6e, 0xac,
        0xcd, 0xc1, 0xf8, 0x1e, 0x73, 0x43, 0x69, 0xc6, 0xb5, 0xbd, 0xfd, 0x39, 0x63, 0x20, 0xd4, 0x38,
        0x76, 0x7d, 0xb2, 0xa7, 0xcf, 0xed, 0x57, 0xc5, 0xf3, 0x2c, 0xbb, 0x14, 0x21, 0x06, 0x55, 0x9b,
        0xe3, 0xef, 0x5e, 0x31, 0x4f, 0x7f, 0x5a, 0xa4, 0x0d, 0x82, 0x51, 0x49, 0x5f, 0xba, 0x58, 0x1c,
        0x4a, 0x16, 0xd5, 0x17, 0xa8, 0x92, 0x24, 0x1f, 0x8c, 0xff, 0xd8, 0xae, 0x2e, 0x01, 0xd3, 0xad,
        0x3b, 0x4b, 0xda, 0x46, 0xeb, 0xc9, 0xde, 0x9a, 0x8f, 0x87, 0xd7, 0x3a, 0x80, 0x6f, 0x2f, 0xc8,
        0xb1, 0xb4, 0x37, 0xf7, 0x0a, 0x22, 0x13, 0x28, 0x7c, 0xcc, 0x3c, 0x89, 0xc7, 0xc3, 0x96, 0x56,
        0x07, 0xbf, 0x7e, 0xf0, 0x0b, 0x2b, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xa6, 0x4c, 0x10, 0xfe,
        0xbc, 0x26, 0x95, 0x88, 0x8a, 0xb0, 0xa3, 0xfb, 0xc0, 0x18, 0x94, 0xf2, 0xe1, 0xe5, 0xe9, 0x5d,
        0xd0, 0xdc, 0x11, 0x66, 0x64, 0x5c, 0xec, 0x59, 0x42, 0x75, 0x12, 0xf5, 0x74, 0x9c, 0xaa, 0x23,
        0x0e, 0x86, 0xab, 0xbe, 0x2a, 0x02, 0xe7, 0x67, 0xe6, 0x44, 0xa2, 0x6c, 0xc2, 0x93, 0x9f, 0xf1,
        0xf6, 0xfa, 0x36, 0xd2, 0x50, 0x68, 0x9e, 0x62, 0x71, 0x15, 0x3d, 0xd6, 0x40, 0xc4, 0xe2, 0x0f,
        0x8e, 0x83, 0x77, 0x6b, 0x25, 0x05, 0x3f, 0x0c, 0x30, 0xea, 0x70, 0xb7, 0xa1, 0xe8, 0xa9, 0x65,
        0x8d, 0x27, 0x1a, 0xdb, 0x81, 0xb3, 0xa0, 0xf4, 0x45, 0x7a, 0x19, 0xdf, 0xee, 0x78, 0x34, 0x60
    ])
    
    # S-Box S1 (256 bytes)
    S1 = bytes([
        0x55, 0xc2, 0x63, 0x71, 0x3b, 0xc8, 0x47, 0x86, 0x9f, 0x3c, 0xda, 0x5b, 0x29, 0xaa, 0xfd, 0x77,
        0x8c, 0xc5, 0x94, 0x0c, 0xa6, 0x1a, 0x13, 0x00, 0xe3, 0xa8, 0x16, 0x72, 0x40, 0xf9, 0xf8, 0x42,
        0x44, 0x26, 0x68, 0x96, 0x81, 0xd9, 0x45, 0x3e, 0x10, 0x76, 0xc6, 0xa7, 0x8b, 0x39, 0x43, 0xe1,
        0x3a, 0xb5, 0x56, 0x2a, 0xc0, 0x6d, 0xb3, 0x05, 0x22, 0x66, 0xbf, 0xdc, 0x0b, 0xfa, 0x62, 0x48,
        0xdd, 0x20, 0x11, 0x06, 0x36, 0xc9, 0xc1, 0xcf, 0xf6, 0x27, 0x52, 0xbb, 0x69, 0xf5, 0xd4, 0x87,
        0x7f, 0x84, 0x4c, 0xd2, 0x9c, 0x57, 0xa4, 0xbc, 0x4f, 0x9a, 0xdf, 0xfe, 0xd6, 0x8d, 0x7a, 0xeb,
        0x2b, 0x53, 0xd8, 0x5c, 0xa1, 0x14, 0x17, 0xfb, 0x23, 0xd5, 0x7d, 0x30, 0x67, 0x73, 0x08, 0x09,
        0xee, 0xb7, 0x70, 0x3f, 0x61, 0xb2, 0x19, 0x8e, 0x4e, 0xe5, 0x4b, 0x93, 0x8f, 0x5d, 0xdb, 0xa9,
        0xad, 0xf1, 0xae, 0x2e, 0xcb, 0x0d, 0xfc, 0xf4, 0x2d, 0x46, 0x6e, 0x1d, 0x97, 0xe8, 0xd1, 0xe9,
        0x4d, 0x37, 0xa5, 0x75, 0x5e, 0x83, 0x9e, 0xab, 0x82, 0x9d, 0xb9, 0x1c, 0xe0, 0xcd, 0x49, 0x89,
        0x01, 0xb6, 0xbd, 0x58, 0x24, 0xa2, 0x5f, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xb8, 0x95, 0xe4,
        0xd0, 0x91, 0xc7, 0xce, 0xed, 0x0f, 0xb4, 0x6f, 0xa0, 0xcc, 0xf0, 0x02, 0x4a, 0x79, 0xc3, 0xde,
        0xa3, 0xef, 0xea, 0x51, 0xe6, 0x6b, 0x18, 0xec, 0x1b, 0x2c, 0x80, 0xf7, 0x74, 0xe7, 0xff, 0x21,
        0x5a, 0x6a, 0x54, 0x1e, 0x41, 0x31, 0x92, 0x35, 0xc4, 0x33, 0x07, 0x0a, 0xba, 0x7e, 0x0e, 0x34,
        0x88, 0xb1, 0x98, 0x7c, 0xf3, 0x3d, 0x60, 0x6c, 0x7b, 0xca, 0xd3, 0x1f, 0x32, 0x65, 0x04, 0x28,
        0x64, 0xbe, 0x85, 0x9b, 0x2f, 0x59, 0x8a, 0xd7, 0xb0, 0x25, 0xac, 0xaf, 0x12, 0x03, 0xe2, 0xf2
    ])
    
    def __init__(self):
        """Initialize ZUC engine."""
        # LFSR - 16 cells of 31 bits each
        self.lfsr: List[int] = [0] * 16
        
        # Registers R1 and R2 (32-bit)
        self.r1: int = 0
        self.r2: int = 0
        
        # Key stream buffer (two 32-bit words = 8 bytes)
        self.key_stream: List[int] = [0, 0]
        self.key_stream_index: int = 0
        
        # Initialization state
        self.initialized: bool = False
        self.working_key: Optional[bytes] = None
        self.working_iv: Optional[bytes] = None
    
    def get_algorithm_name(self) -> str:
        """Return the algorithm name."""
        return 'ZUC-128'
    
    def init(self, for_encryption: bool, params: CipherParameters) -> None:
        """
        Initialize the cipher.
        
        Args:
            for_encryption: Ignored (stream ciphers are symmetric)
            params: Must be ParametersWithIV containing a KeyParameter
            
        Raises:
            ValueError: If parameters are invalid
        """
        if not isinstance(params, ParametersWithIV):
            raise ValueError('ZUC init parameters must include an IV (use ParametersWithIV)')
        
        iv = params.iv
        key_param = params.parameters
        
        if not isinstance(key_param, KeyParameter):
            raise ValueError('ZUC init parameters must include a key (KeyParameter)')
        
        key = key_param.key
        
        if len(key) != 16:
            raise ValueError('ZUC requires a 128-bit key')
        
        if len(iv) != 16:
            raise ValueError('ZUC requires a 128-bit IV')
        
        self.working_key = bytes(key)
        self.working_iv = bytes(iv)
        
        self._set_key_and_iv(self.working_key, self.working_iv)
        self.initialized = True
    
    def return_byte(self, input_byte: int) -> int:
        """
        Encrypt/decrypt a single byte.
        
        Args:
            input_byte: The byte to process (0-255)
            
        Returns:
            The processed byte (0-255)
        """
        if not self.initialized:
            raise RuntimeError('ZUC not initialized')
        
        if self.key_stream_index == 0:
            self._generate_key_stream()
        
        out = (input_byte ^ self._get_key_stream_byte()) & 0xFF
        return out
    
    def process_bytes(self, input_data: Union[bytes, bytearray, List[int]], 
                      in_off: int, length: int,
                      output: Union[bytearray, List[int]], out_off: int) -> int:
        """
        Process a block of bytes.
        
        Args:
            input_data: The input data
            in_off: The offset into the input data
            length: The number of bytes to process
            output: The output buffer
            out_off: The offset into the output buffer
            
        Returns:
            The number of bytes written
        """
        if not self.initialized:
            raise RuntimeError('ZUC not initialized')
        
        if in_off + length > len(input_data):
            raise DataLengthException('input buffer too short')
        
        if out_off + length > len(output):
            raise DataLengthException('output buffer too short')
        
        for i in range(length):
            if self.key_stream_index == 0:
                self._generate_key_stream()
            
            output[out_off + i] = (input_data[in_off + i] ^ self._get_key_stream_byte()) & 0xFF
        
        return length
    
    def reset(self) -> None:
        """Reset the cipher to its initialized state."""
        if self.working_key is not None and self.working_iv is not None:
            self._set_key_and_iv(self.working_key, self.working_iv)
        self.initialized = self.working_key is not None
    
    def _set_key_and_iv(self, key: bytes, iv: bytes) -> None:
        """
        Set key and IV, initialize LFSR and run initialization mode.
        
        Args:
            key: 128-bit key
            iv: 128-bit IV
        """
        # EK_d constants from Bouncy Castle Java (16-bit values)
        # Used in LFSR initialization: (key[i] << 23) | (EK_d[i] << 8) | iv[i]
        EK_d = [
            0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
            0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC
        ]
        
        # Load key and IV into LFSR
        for i in range(16):
            self.lfsr[i] = self._make_u31((key[i] << 23) | (EK_d[i] << 8) | iv[i])
        
        self.r1 = 0
        self.r2 = 0
        self.key_stream_index = 0
        
        # Run 32 iterations in initialization mode
        for _ in range(32):
            x0, x1, x2, _ = self._bit_reorganization()
            w = self._f(x0, x1, x2)
            self._lfsr_with_init_mode(w >> 1)
        
        # Generate first keystream word (discard)
        x0, x1, x2, _ = self._bit_reorganization()
        self._f(x0, x1, x2)
        self._lfsr_with_work_mode()
    
    def _make_u31(self, value: int) -> int:
        """
        Make a 31-bit value from input, handling GF(2^31-1) arithmetic.
        
        In GF(2^31-1), the modulus is 2^31-1 (0x7FFFFFFF).
        Simple masking: value & 0x7FFFFFFF gives us a value in [0, 2^31-1).
        """
        return value & 0x7FFFFFFF
    
    def _add_m(self, a: int, b: int) -> int:
        """
        Addition in GF(2^31-1).
        
        In GF(2^31-1), if a + b >= 2^31, we need to add 1 (since 2^31 ≡ 1 mod 2^31-1).
        This is implemented as: (c & 0x7FFFFFFF) + (c >> 31)
        
        Args:
            a: First operand (31-bit)
            b: Second operand (31-bit)
            
        Returns:
            Sum in GF(2^31-1)
        """
        c = a + b
        return (c & 0x7FFFFFFF) + (c >> 31)
    
    def _lfsr_with_init_mode(self, u: int) -> None:
        """
        LFSR update in initialization mode with feedback.
        
        Based on Bouncy Castle Java Zuc128CoreEngine.
        Uses LFSR cells at indices 0, 4, 10, 13, 15.
        
        Args:
            u: Feedback value from F function
        """
        # Compute feedback using correct LFSR polynomial
        f = self.lfsr[0]
        v = self._mul_by_pow2(self.lfsr[0], 8)
        f = self._add_m(f, v)
        v = self._mul_by_pow2(self.lfsr[4], 20)
        f = self._add_m(f, v)
        v = self._mul_by_pow2(self.lfsr[10], 21)
        f = self._add_m(f, v)
        v = self._mul_by_pow2(self.lfsr[13], 17)
        f = self._add_m(f, v)
        v = self._mul_by_pow2(self.lfsr[15], 15)
        f = self._add_m(f, v)
        f = self._add_m(f, u)
        
        # Shift LFSR
        for i in range(15):
            self.lfsr[i] = self.lfsr[i + 1]
        
        self.lfsr[15] = f
    
    def _lfsr_with_work_mode(self) -> None:
        """
        LFSR update in working mode (no external feedback).
        
        Based on Bouncy Castle Java Zuc128CoreEngine.
        Uses LFSR cells at indices 0, 4, 10, 13, 15.
        """
        # Compute feedback using correct LFSR polynomial
        f = self.lfsr[0]
        v = self._mul_by_pow2(self.lfsr[0], 8)
        f = self._add_m(f, v)
        v = self._mul_by_pow2(self.lfsr[4], 20)
        f = self._add_m(f, v)
        v = self._mul_by_pow2(self.lfsr[10], 21)
        f = self._add_m(f, v)
        v = self._mul_by_pow2(self.lfsr[13], 17)
        f = self._add_m(f, v)
        v = self._mul_by_pow2(self.lfsr[15], 15)
        f = self._add_m(f, v)
        
        # Shift LFSR
        for i in range(15):
            self.lfsr[i] = self.lfsr[i + 1]
        
        self.lfsr[15] = f
    
    def _mul_by_pow2(self, x: int, k: int) -> int:
        """
        Multiplication by 2^k in GF(2^31-1).
        
        Args:
            x: Value to multiply
            k: Power of 2
            
        Returns:
            Result of multiplication
        """
        return ((x << k) | (x >> (31 - k))) & 0x7FFFFFFF
    
    def _bit_reorganization(self) -> List[int]:
        """
        Bit reorganization - extract bits from LFSR to form X0, X1, X2, X3.
        
        Returns:
            List of [X0, X1, X2, X3] (32-bit words)
        """
        # Use logical shifts (ensure positive values)
        x0 = ((self.lfsr[15] & 0x7FFF8000) << 1) | (self.lfsr[14] & 0xFFFF)
        x1 = ((self.lfsr[11] & 0xFFFF) << 16) | ((self.lfsr[9] & 0x7FFFFFFF) >> 15)
        x2 = ((self.lfsr[7] & 0xFFFF) << 16) | ((self.lfsr[5] & 0x7FFFFFFF) >> 15)
        x3 = ((self.lfsr[2] & 0xFFFF) << 16) | ((self.lfsr[0] & 0x7FFFFFFF) >> 15)
        
        return [x0 & 0xFFFFFFFF, x1 & 0xFFFFFFFF, x2 & 0xFFFFFFFF, x3 & 0xFFFFFFFF]
    
    def _s(self, x: int) -> int:
        """
        S-box lookup (combining S0 and S1).
        
        Args:
            x: 32-bit input
            
        Returns:
            32-bit output after S-box transformation
        """
        result = (
            (self.S0[(x >> 24) & 0xFF] << 24) |
            (self.S1[(x >> 16) & 0xFF] << 16) |
            (self.S0[(x >> 8) & 0xFF] << 8) |
            (self.S1[x & 0xFF])
        )
        return result & 0xFFFFFFFF
    
    def _l1(self, x: int) -> int:
        """
        Linear transformation L1.
        
        Args:
            x: 32-bit input
            
        Returns:
            32-bit output after L1 transformation
        """
        return (x ^ self._rot(x, 2) ^ self._rot(x, 10) ^ self._rot(x, 18) ^ self._rot(x, 24)) & 0xFFFFFFFF
    
    def _l2(self, x: int) -> int:
        """
        Linear transformation L2.
        
        Args:
            x: 32-bit input
            
        Returns:
            32-bit output after L2 transformation
        """
        return (x ^ self._rot(x, 8) ^ self._rot(x, 14) ^ self._rot(x, 22) ^ self._rot(x, 30)) & 0xFFFFFFFF
    
    def _rot(self, x: int, n: int) -> int:
        """
        32-bit rotation.
        
        Args:
            x: Value to rotate
            n: Number of bits to rotate
            
        Returns:
            Rotated value
        """
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    
    def _f(self, x0: int, x1: int, x2: int) -> int:
        """
        Nonlinear function F.
        
        Args:
            x0, x1, x2: Values from bit reorganization (BRC[0], BRC[1], BRC[2])
        
        Returns:
            32-bit output word W
        """
        # Note: BC Java uses addition, not XOR, for W calculation
        w = ((x0 ^ self.r1) + self.r2) & 0xFFFFFFFF
        w1 = (self.r1 + x1) & 0xFFFFFFFF
        w2 = (self.r2 ^ x2) & 0xFFFFFFFF
        
        u = self._l1(((w1 << 16) | (w2 >> 16)) & 0xFFFFFFFF)
        v = self._l2(((w2 << 16) | (w1 >> 16)) & 0xFFFFFFFF)
        
        self.r1 = self._s(u)
        self.r2 = self._s(v)
        
        return w
    
    def _generate_key_stream(self) -> None:
        """Generate two keystream words (8 bytes total)."""
        # Generate first word
        x0, x1, x2, x3 = self._bit_reorganization()
        self.key_stream[0] = self._f(x0, x1, x2) ^ x3
        self._lfsr_with_work_mode()
        
        # Generate second word
        x0, x1, x2, x3 = self._bit_reorganization()
        self.key_stream[1] = self._f(x0, x1, x2) ^ x3
        self._lfsr_with_work_mode()
        
        self.key_stream_index = 0
    
    def _get_key_stream_byte(self) -> int:
        """
        Get one byte from the key stream buffer.
        
        Returns:
            Next keystream byte
        """
        word = self.key_stream[self.key_stream_index >> 2]
        byte_index = 3 - (self.key_stream_index & 3)
        self.key_stream_index = (self.key_stream_index + 1) & 7
        return (word >> (byte_index * 8)) & 0xFF
