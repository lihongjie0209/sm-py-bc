"""
SM4Engine unit tests.

Reference: test/unit/crypto/engines/SM4Engine.test.ts (sm-js-bc)
"""

import pytest
from sm_bc.crypto.engines.sm4_engine import SM4Engine
from sm_bc.crypto.params.key_parameter import KeyParameter
from sm_bc.exceptions import DataLengthException


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


class TestSM4EngineBasic:
    """Basic functionality tests."""
    
    def test_algorithm_name(self):
        """Should return correct algorithm name."""
        engine = SM4Engine()
        assert engine.get_algorithm_name() == 'SM4'
    
    def test_block_size(self):
        """Should return correct block size."""
        engine = SM4Engine()
        assert engine.get_block_size() == 16
    
    def test_uninitialised_error(self):
        """Should throw error when not initialised."""
        engine = SM4Engine()
        input_data = bytearray(16)
        output = bytearray(16)
        
        with pytest.raises(ValueError, match='not initialised'):
            engine.process_block(input_data, 0, output, 0)
    
    def test_wrong_key_length_error(self):
        """Should throw error for wrong key length."""
        engine = SM4Engine()
        wrong_key = bytes(15)  # Wrong key length
        
        with pytest.raises(ValueError, match='128 bit key'):
            engine.init(True, KeyParameter(wrong_key))


class TestSM4EngineStandardVectors:
    """Standard test vectors."""
    
    def test_encrypt_single_block_vector1(self):
        """Should correctly encrypt single block (test vector 1)."""
        # From SM4Test.java
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        expected = hex_to_bytes('681edf34d206965e86b3e94f536e4246')
        
        engine = SM4Engine()
        engine.init(True, KeyParameter(key))
        
        output = bytearray(16)
        engine.process_block(plaintext, 0, output, 0)
        
        assert bytes_to_hex(output) == bytes_to_hex(expected)
    
    def test_decrypt_single_block_vector1(self):
        """Should correctly decrypt single block (test vector 1)."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        ciphertext = hex_to_bytes('681edf34d206965e86b3e94f536e4246')
        expected = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        engine.init(False, KeyParameter(key))
        
        output = bytearray(16)
        engine.process_block(ciphertext, 0, output, 0)
        
        assert bytes_to_hex(output) == bytes_to_hex(expected)


class TestSM4EngineMillionIterations:
    """Million iteration tests."""
    
    @pytest.mark.slow
    def test_million_encrypt_iterations(self):
        """Should pass 1 million encryption iteration test."""
        # From SM4Test.java test1000000()
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        plain = hex_to_bytes('0123456789abcdeffedcba9876543210')
        expected = hex_to_bytes('595298c7c6fd271f0402f804c33d3f66')
        
        engine = SM4Engine()
        engine.init(True, KeyParameter(key))
        
        buf = bytearray(plain)
        
        # 1 million iterations
        for i in range(1000000):
            engine.process_block(buf, 0, buf, 0)
        
        assert bytes_to_hex(buf) == bytes_to_hex(expected)
    
    @pytest.mark.slow
    def test_million_decrypt_iterations(self):
        """Should pass 1 million decryption iteration test."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        cipher = hex_to_bytes('595298c7c6fd271f0402f804c33d3f66')
        expected = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        engine.init(False, KeyParameter(key))
        
        buf = bytearray(cipher)
        
        # 1 million iterations
        for i in range(1000000):
            engine.process_block(buf, 0, buf, 0)
        
        assert bytes_to_hex(buf) == bytes_to_hex(expected)


class TestSM4EngineRoundTrip:
    """Encryption/decryption round-trip tests."""
    
    def test_encrypt_decrypt_roundtrip(self):
        """Should encrypt and decrypt back to original."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        # Encrypt
        enc_engine = SM4Engine()
        enc_engine.init(True, KeyParameter(key))
        ciphertext = bytearray(16)
        enc_engine.process_block(plaintext, 0, ciphertext, 0)
        
        # Decrypt
        dec_engine = SM4Engine()
        dec_engine.init(False, KeyParameter(key))
        decrypted = bytearray(16)
        dec_engine.process_block(ciphertext, 0, decrypted, 0)
        
        assert bytes_to_hex(decrypted) == bytes_to_hex(plaintext)
    
    def test_different_plaintexts_different_ciphertexts(self):
        """Should produce different ciphertexts for different plaintexts."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        plaintext1 = hex_to_bytes('0123456789abcdeffedcba9876543210')
        plaintext2 = hex_to_bytes('0123456789abcdeffedcba9876543211')  # Last bit different
        
        engine = SM4Engine()
        engine.init(True, KeyParameter(key))
        
        ciphertext1 = bytearray(16)
        ciphertext2 = bytearray(16)
        
        engine.process_block(plaintext1, 0, ciphertext1, 0)
        
        # Re-initialize to process second block
        engine.init(True, KeyParameter(key))
        engine.process_block(plaintext2, 0, ciphertext2, 0)
        
        assert bytes_to_hex(ciphertext1) != bytes_to_hex(ciphertext2)


class TestSM4EngineBoundaryConditions:
    """Boundary condition tests."""
    
    def test_all_zero_key_and_plaintext(self):
        """Should handle all-zero key and plaintext."""
        key = bytes(16)  # All zeros
        plaintext = bytes(16)  # All zeros
        
        engine = SM4Engine()
        engine.init(True, KeyParameter(key))
        
        output = bytearray(16)
        engine.process_block(plaintext, 0, output, 0)
        
        # Should produce non-zero ciphertext
        assert output != bytes(16)
    
    def test_all_ff_key_and_plaintext(self):
        """Should handle all-0xFF key and plaintext."""
        key = bytes([0xFF] * 16)
        plaintext = bytes([0xFF] * 16)
        
        engine = SM4Engine()
        engine.init(True, KeyParameter(key))
        
        output = bytearray(16)
        engine.process_block(plaintext, 0, output, 0)
        
        # Should produce some ciphertext
        assert len(output) == 16
    
    def test_input_buffer_too_short(self):
        """Should throw DataLengthException for short input."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        engine.init(True, KeyParameter(key))
        
        short_input = bytearray(10)  # Too short
        output = bytearray(16)
        
        with pytest.raises(DataLengthException):
            engine.process_block(short_input, 0, output, 0)
    
    def test_output_buffer_too_short(self):
        """Should throw DataLengthException for short output."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        engine.init(True, KeyParameter(key))
        
        input_data = bytearray(16)
        short_output = bytearray(10)  # Too short
        
        with pytest.raises(DataLengthException):
            engine.process_block(input_data, 0, short_output, 0)


class TestSM4EngineReusability:
    """Test engine reusability."""
    
    def test_multiple_encryptions_same_engine(self):
        """Should allow multiple encryptions with same engine."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        engine.init(True, KeyParameter(key))
        
        plaintexts = [
            hex_to_bytes('0123456789abcdeffedcba9876543210'),
            hex_to_bytes('fedcba98765432100123456789abcdef'),
            hex_to_bytes('aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb')
        ]
        
        for plaintext in plaintexts:
            ciphertext = bytearray(16)
            result = engine.process_block(plaintext, 0, ciphertext, 0)
            
            assert result == 16
            assert len(ciphertext) == 16
            # Verify encryption worked
            assert ciphertext != plaintext
    
    def test_multiple_decryptions_same_engine(self):
        """Should allow multiple decryptions with same engine."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        # First encrypt some plaintexts
        enc_engine = SM4Engine()
        enc_engine.init(True, KeyParameter(key))
        
        plaintexts = [
            hex_to_bytes('0123456789abcdeffedcba9876543210'),
            hex_to_bytes('fedcba98765432100123456789abcdef'),
        ]
        
        ciphertexts = []
        for plaintext in plaintexts:
            ciphertext = bytearray(16)
            enc_engine.process_block(plaintext, 0, ciphertext, 0)
            ciphertexts.append(bytes(ciphertext))
        
        # Now decrypt with single engine
        dec_engine = SM4Engine()
        dec_engine.init(False, KeyParameter(key))
        
        for i, ciphertext in enumerate(ciphertexts):
            decrypted = bytearray(16)
            dec_engine.process_block(ciphertext, 0, decrypted, 0)
            
            assert bytes_to_hex(decrypted) == bytes_to_hex(plaintexts[i])


class TestSM4EngineOffsets:
    """Test with non-zero offsets."""
    
    def test_non_zero_input_offset(self):
        """Should handle non-zero input offset."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        expected = hex_to_bytes('681edf34d206965e86b3e94f536e4246')
        
        # Create buffer with offset
        input_buffer = bytearray(20)
        input_buffer[4:20] = plaintext
        
        engine = SM4Engine()
        engine.init(True, KeyParameter(key))
        
        output = bytearray(16)
        engine.process_block(input_buffer, 4, output, 0)
        
        assert bytes_to_hex(output) == bytes_to_hex(expected)
    
    def test_non_zero_output_offset(self):
        """Should handle non-zero output offset."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        expected = hex_to_bytes('681edf34d206965e86b3e94f536e4246')
        
        engine = SM4Engine()
        engine.init(True, KeyParameter(key))
        
        # Create output buffer with offset
        output_buffer = bytearray(20)
        engine.process_block(plaintext, 0, output_buffer, 4)
        
        assert bytes_to_hex(output_buffer[4:20]) == bytes_to_hex(expected)
