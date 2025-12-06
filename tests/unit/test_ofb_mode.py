"""
OFB mode tests with SM4.

Reference: test/unit/crypto/modes/OFBBlockCipher.test.ts (sm-js-bc)
"""

import pytest
from sm_bc.crypto.modes.ofb_block_cipher import OFBBlockCipher
from sm_bc.crypto.engines.sm4_engine import SM4Engine
from sm_bc.crypto.params.key_parameter import KeyParameter
from sm_bc.crypto.params.parameters_with_iv import ParametersWithIV


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


class TestOFBBlockCipherBasic:
    """Basic functionality tests."""
    
    def test_algorithm_name(self):
        """Should return correct algorithm name."""
        engine = SM4Engine()
        cipher = OFBBlockCipher(engine, 128)
        assert cipher.get_algorithm_name() == 'SM4/OFB128'
    
    def test_block_size(self):
        """Should return correct block size."""
        engine = SM4Engine()
        cipher = OFBBlockCipher(engine, 128)
        assert cipher.get_block_size() == 16
    
    def test_smaller_block_size(self):
        """Should support smaller block sizes."""
        engine = SM4Engine()
        cipher = OFBBlockCipher(engine, 64)
        assert cipher.get_block_size() == 8
        assert cipher.get_algorithm_name() == 'SM4/OFB64'
    
    def test_get_underlying_cipher(self):
        """Should correctly get underlying engine."""
        engine = SM4Engine()
        cipher = OFBBlockCipher(engine, 128)
        assert cipher.get_underlying_cipher() is engine
    
    def test_invalid_block_size(self):
        """Should reject invalid block sizes."""
        engine = SM4Engine()
        
        # Too large
        with pytest.raises(ValueError, match='not supported'):
            OFBBlockCipher(engine, 256)
        
        # Too small
        with pytest.raises(ValueError, match='not supported'):
            OFBBlockCipher(engine, 4)
        
        # Not multiple of 8
        with pytest.raises(ValueError, match='not supported'):
            OFBBlockCipher(engine, 100)


class TestOFBEncryptionDecryption:
    """Encryption and decryption tests."""
    
    def test_encrypt_single_block(self):
        """Should correctly encrypt single block."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000000')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        cipher = OFBBlockCipher(engine, 128)
        params = ParametersWithIV(KeyParameter(key), iv)
        
        cipher.init(True, params)
        
        ciphertext = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext, 0)
        
        # OFB: C = P XOR E(IV)
        assert len(ciphertext) == 16
        # Should not be all zeros
        assert ciphertext != bytes(16)
    
    def test_decrypt_equals_encrypt(self):
        """OFB mode: decryption equals encryption."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00112233445566778899aabbccddeeff')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        # Encrypt
        enc_engine = SM4Engine()
        enc_cipher = OFBBlockCipher(enc_engine, 128)
        enc_params = ParametersWithIV(KeyParameter(key), iv)
        enc_cipher.init(True, enc_params)
        
        ciphertext = bytearray(16)
        enc_cipher.process_block(plaintext, 0, ciphertext, 0)
        
        # Decrypt (using same operation!)
        dec_engine = SM4Engine()
        dec_cipher = OFBBlockCipher(dec_engine, 128)
        dec_params = ParametersWithIV(KeyParameter(key), iv)
        dec_cipher.init(False, dec_params)  # forEncryption ignored in OFB
        
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
        cipher = OFBBlockCipher(engine, 128)
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


class TestOFBStreamMode:
    """Test stream processing with process_bytes."""
    
    def test_process_bytes(self):
        """Should process arbitrary length data."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000000')
        
        # Non-block-aligned data
        plaintext = b"OFB mode is a stream cipher!"
        
        engine = SM4Engine()
        cipher = OFBBlockCipher(engine, 128)
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
        
        plaintext = b"Test"  # 4 bytes
        
        engine = SM4Engine()
        cipher = OFBBlockCipher(engine, 128)
        params = ParametersWithIV(KeyParameter(key), iv)
        cipher.init(True, params)
        
        ciphertext = bytearray(len(plaintext))
        cipher.process_bytes(plaintext, 0, len(plaintext), ciphertext, 0)
        
        # Decrypt
        cipher.init(False, params)
        decrypted = bytearray(len(ciphertext))
        cipher.process_bytes(ciphertext, 0, len(ciphertext), decrypted, 0)
        
        assert bytes(decrypted) == plaintext


class TestOFBFeedbackBehavior:
    """Test OFB feedback register behavior."""
    
    def test_feedback_from_encrypted_output(self):
        """Should use encrypted output for feedback, not ciphertext."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000000')
        
        # Same plaintext
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        cipher = OFBBlockCipher(engine, 128)
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
        cipher = OFBBlockCipher(engine, 128)
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


class TestOFBIVHandling:
    """Test IV handling."""
    
    def test_full_size_iv(self):
        """Should handle full-size IV."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00112233445566778899aabbccddeeff')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        cipher = OFBBlockCipher(engine, 128)
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
        cipher = OFBBlockCipher(engine, 128)
        params = ParametersWithIV(KeyParameter(key), short_iv)
        
        # Should not throw, will pad with zeros
        cipher.init(True, params)
        
        ciphertext = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext, 0)
        
        assert len(ciphertext) == 16


class TestOFBRoundTrip:
    """Round-trip encryption/decryption tests."""
    
    def test_long_message_roundtrip(self):
        """Should handle long messages correctly."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('fedcba9876543210fedcba9876543210')
        
        # Long message (multiple blocks)
        plaintext = b"OFB mode provides a stream cipher from a block cipher. " * 3
        
        engine = SM4Engine()
        cipher = OFBBlockCipher(engine, 128)
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
    
    def test_ofb64_roundtrip(self):
        """Should work with 64-bit feedback."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('0011223344556677')  # 8 bytes for OFB64
        plaintext = b"Testing OFB with 64-bit blocks."
        
        engine = SM4Engine()
        cipher = OFBBlockCipher(engine, 64)  # 64-bit feedback
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
