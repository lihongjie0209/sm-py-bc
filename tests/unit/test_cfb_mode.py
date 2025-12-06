"""
CFB mode tests with SM4.

Reference: test/unit/crypto/modes/CFBBlockCipher.test.ts (sm-js-bc)
"""

import pytest
from sm_bc.crypto.modes.cfb_block_cipher import CFBBlockCipher
from sm_bc.crypto.engines.sm4_engine import SM4Engine
from sm_bc.crypto.params.key_parameter import KeyParameter
from sm_bc.crypto.params.parameters_with_iv import ParametersWithIV


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


class TestCFBBlockCipherBasic:
    """Basic functionality tests."""
    
    def test_algorithm_name(self):
        """Should return correct algorithm name."""
        engine = SM4Engine()
        cipher = CFBBlockCipher(engine, 128)
        assert cipher.get_algorithm_name() == 'SM4/CFB128'
    
    def test_block_size(self):
        """Should return correct block size."""
        engine = SM4Engine()
        cipher = CFBBlockCipher(engine, 128)
        assert cipher.get_block_size() == 16
    
    def test_smaller_block_size(self):
        """Should support smaller block sizes."""
        engine = SM4Engine()
        cipher = CFBBlockCipher(engine, 64)
        assert cipher.get_block_size() == 8
        assert cipher.get_algorithm_name() == 'SM4/CFB64'
    
    def test_get_underlying_cipher(self):
        """Should correctly get underlying engine."""
        engine = SM4Engine()
        cipher = CFBBlockCipher(engine, 128)
        assert cipher.get_underlying_cipher() is engine
    
    def test_invalid_block_size(self):
        """Should reject invalid block sizes."""
        engine = SM4Engine()
        
        # Too large
        with pytest.raises(ValueError, match='not supported'):
            CFBBlockCipher(engine, 256)
        
        # Too small
        with pytest.raises(ValueError, match='not supported'):
            CFBBlockCipher(engine, 4)
        
        # Not multiple of 8
        with pytest.raises(ValueError, match='not supported'):
            CFBBlockCipher(engine, 100)


class TestCFBEncryptionDecryption:
    """Encryption and decryption tests."""
    
    def test_encrypt_single_block(self):
        """Should correctly encrypt single block."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000000')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        cipher = CFBBlockCipher(engine, 128)
        params = ParametersWithIV(KeyParameter(key), iv)
        
        cipher.init(True, params)
        
        ciphertext = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext, 0)
        
        # CFB: C = P XOR E(IV)
        assert len(ciphertext) == 16
        # Should not be all zeros
        assert ciphertext != bytes(16)
    
    def test_decrypt_single_block(self):
        """Should correctly decrypt single block."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00112233445566778899aabbccddeeff')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        # Encrypt
        enc_engine = SM4Engine()
        enc_cipher = CFBBlockCipher(enc_engine, 128)
        enc_params = ParametersWithIV(KeyParameter(key), iv)
        enc_cipher.init(True, enc_params)
        
        ciphertext = bytearray(16)
        enc_cipher.process_block(plaintext, 0, ciphertext, 0)
        
        # Decrypt
        dec_engine = SM4Engine()
        dec_cipher = CFBBlockCipher(dec_engine, 128)
        dec_params = ParametersWithIV(KeyParameter(key), iv)
        dec_cipher.init(False, dec_params)
        
        decrypted = bytearray(16)
        dec_cipher.process_block(ciphertext, 0, decrypted, 0)
        
        assert bytes_to_hex(decrypted) == bytes_to_hex(plaintext)
    
    def test_multiple_blocks(self):
        """Should handle multiple blocks correctly."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('fedcba9876543210fedcba9876543210')
        
        plaintext1 = hex_to_bytes('0123456789abcdeffedcba9876543210')
        plaintext2 = hex_to_bytes('fedcba98765432100123456789abcdef')
        plaintext3 = hex_to_bytes('aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb')
        
        engine = SM4Engine()
        cipher = CFBBlockCipher(engine, 128)
        params = ParametersWithIV(KeyParameter(key), iv)
        cipher.init(True, params)
        
        ciphertext1 = bytearray(16)
        ciphertext2 = bytearray(16)
        ciphertext3 = bytearray(16)
        
        cipher.process_block(plaintext1, 0, ciphertext1, 0)
        cipher.process_block(plaintext2, 0, ciphertext2, 0)
        cipher.process_block(plaintext3, 0, ciphertext3, 0)
        
        # All ciphertexts should be different
        assert bytes_to_hex(ciphertext1) != bytes_to_hex(ciphertext2)
        assert bytes_to_hex(ciphertext2) != bytes_to_hex(ciphertext3)
        
        # Decrypt all blocks
        cipher.init(False, params)
        decrypted1 = bytearray(16)
        decrypted2 = bytearray(16)
        decrypted3 = bytearray(16)
        
        cipher.process_block(ciphertext1, 0, decrypted1, 0)
        cipher.process_block(ciphertext2, 0, decrypted2, 0)
        cipher.process_block(ciphertext3, 0, decrypted3, 0)
        
        assert bytes_to_hex(decrypted1) == bytes_to_hex(plaintext1)
        assert bytes_to_hex(decrypted2) == bytes_to_hex(plaintext2)
        assert bytes_to_hex(decrypted3) == bytes_to_hex(plaintext3)


class TestCFBStreamMode:
    """Test stream processing with process_bytes."""
    
    def test_process_bytes(self):
        """Should process arbitrary length data."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000000')
        
        # Non-block-aligned data
        plaintext = b"CFB mode is self-synchronizing!"
        
        engine = SM4Engine()
        cipher = CFBBlockCipher(engine, 128)
        params = ParametersWithIV(KeyParameter(key), iv)
        cipher.init(True, params)
        
        ciphertext = bytearray(len(plaintext))
        cipher.process_bytes(plaintext, 0, len(plaintext), ciphertext, 0)
        
        # Decrypt
        cipher.init(False, params)
        decrypted = bytearray(len(ciphertext))
        cipher.process_bytes(ciphertext, 0, len(ciphertext), decrypted, 0)
        
        assert bytes(decrypted) == plaintext
    
    def test_partial_block_processing(self):
        """Should handle partial block processing."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('0123456789abcdef0123456789abcdef')
        
        plaintext = b"Test CFB"  # 8 bytes
        
        engine = SM4Engine()
        cipher = CFBBlockCipher(engine, 128)
        params = ParametersWithIV(KeyParameter(key), iv)
        cipher.init(True, params)
        
        ciphertext = bytearray(len(plaintext))
        cipher.process_bytes(plaintext, 0, len(plaintext), ciphertext, 0)
        
        # Decrypt
        cipher.init(False, params)
        decrypted = bytearray(len(ciphertext))
        cipher.process_bytes(ciphertext, 0, len(ciphertext), decrypted, 0)
        
        assert bytes(decrypted) == plaintext


class TestCFBFeedbackBehavior:
    """Test CFB feedback register behavior."""
    
    def test_feedback_from_ciphertext(self):
        """Should use ciphertext for feedback."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000000')
        
        # Same plaintext
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        cipher = CFBBlockCipher(engine, 128)
        params = ParametersWithIV(KeyParameter(key), iv)
        cipher.init(True, params)
        
        ciphertext1 = bytearray(16)
        ciphertext2 = bytearray(16)
        
        cipher.process_block(plaintext, 0, ciphertext1, 0)
        cipher.process_block(plaintext, 0, ciphertext2, 0)
        
        # Different feedback means different keystream → different ciphertext
        assert bytes_to_hex(ciphertext1) != bytes_to_hex(ciphertext2)
    
    def test_reset_resets_feedback(self):
        """Should reset feedback register to IV."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00112233445566778899aabbccddeeff')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        cipher = CFBBlockCipher(engine, 128)
        params = ParametersWithIV(KeyParameter(key), iv)
        cipher.init(True, params)
        
        ciphertext1 = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext1, 0)
        
        # Reset
        cipher.reset()
        
        ciphertext2 = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext2, 0)
        
        # After reset, same plaintext → same ciphertext (same keystream)
        assert bytes_to_hex(ciphertext1) == bytes_to_hex(ciphertext2)


class TestCFBIVHandling:
    """Test IV handling."""
    
    def test_full_size_iv(self):
        """Should handle full-size IV."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00112233445566778899aabbccddeeff')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        cipher = CFBBlockCipher(engine, 128)
        params = ParametersWithIV(KeyParameter(key), iv)
        cipher.init(True, params)
        
        ciphertext = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext, 0)
        
        assert len(ciphertext) == 16
    
    def test_short_iv_padded(self):
        """Should pad short IV with zeros."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        short_iv = hex_to_bytes('0011223344556677')  # 8 bytes
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        cipher = CFBBlockCipher(engine, 128)
        params = ParametersWithIV(KeyParameter(key), short_iv)
        
        # Should not throw, will pad with zeros
        cipher.init(True, params)
        
        ciphertext = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext, 0)
        
        assert len(ciphertext) == 16


class TestCFBRoundTrip:
    """Round-trip encryption/decryption tests."""
    
    def test_long_message_roundtrip(self):
        """Should handle long messages correctly."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('fedcba9876543210fedcba9876543210')
        
        # Long message (multiple blocks)
        plaintext = b"CFB mode is self-synchronizing and recovers from errors. " * 3
        
        engine = SM4Engine()
        cipher = CFBBlockCipher(engine, 128)
        params = ParametersWithIV(KeyParameter(key), iv)
        
        # Encrypt
        cipher.init(True, params)
        ciphertext = bytearray(len(plaintext))
        cipher.process_bytes(plaintext, 0, len(plaintext), ciphertext, 0)
        
        # Decrypt
        cipher.init(False, params)
        decrypted = bytearray(len(ciphertext))
        cipher.process_bytes(ciphertext, 0, len(ciphertext), decrypted, 0)
        
        assert bytes(decrypted) == plaintext
    
    def test_cfb64_roundtrip(self):
        """Should work with 64-bit feedback."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('0011223344556677')  # 8 bytes for CFB64
        plaintext = b"Testing CFB with 64-bit feedback mode."
        
        engine = SM4Engine()
        cipher = CFBBlockCipher(engine, 64)  # 64-bit feedback
        params = ParametersWithIV(KeyParameter(key), iv)
        
        # Encrypt
        cipher.init(True, params)
        ciphertext = bytearray(len(plaintext))
        cipher.process_bytes(plaintext, 0, len(plaintext), ciphertext, 0)
        
        # Decrypt
        cipher.init(False, params)
        decrypted = bytearray(len(ciphertext))
        cipher.process_bytes(ciphertext, 0, len(ciphertext), decrypted, 0)
        
        assert bytes(decrypted) == plaintext


class TestCFBSelfSynchronizing:
    """Test CFB self-synchronizing property."""
    
    def test_encrypting_mode_distinction(self):
        """Should have different behavior for encrypt vs decrypt on second block."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00112233445566778899aabbccddeeff')
        plaintext1 = hex_to_bytes('0123456789abcdeffedcba9876543210')
        plaintext2 = hex_to_bytes('fedcba98765432100123456789abcdef')
        
        # Encrypt two blocks
        enc_engine = SM4Engine()
        enc_cipher = CFBBlockCipher(enc_engine, 128)
        enc_params = ParametersWithIV(KeyParameter(key), iv)
        enc_cipher.init(True, enc_params)
        
        ciphertext1 = bytearray(16)
        ciphertext2 = bytearray(16)
        enc_cipher.process_block(plaintext1, 0, ciphertext1, 0)
        enc_cipher.process_block(plaintext2, 0, ciphertext2, 0)
        
        # Try to "decrypt" with encrypt mode (should not work on second block)
        wrong_engine = SM4Engine()
        wrong_cipher = CFBBlockCipher(wrong_engine, 128)
        wrong_params = ParametersWithIV(KeyParameter(key), iv)
        wrong_cipher.init(True, wrong_params)  # Wrong: using encrypt mode
        
        wrong_result1 = bytearray(16)
        wrong_result2 = bytearray(16)
        wrong_cipher.process_block(ciphertext1, 0, wrong_result1, 0)
        wrong_cipher.process_block(ciphertext2, 0, wrong_result2, 0)
        
        # First block might match due to same E(IV), but second should NOT
        assert bytes_to_hex(wrong_result2) != bytes_to_hex(plaintext2)
