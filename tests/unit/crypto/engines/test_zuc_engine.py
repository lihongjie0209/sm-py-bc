"""
Tests for ZUC-128 Stream Cipher Engine.

Test vectors from GM/T 0001-2012 and 3GPP TS 35.221.
"""

import pytest
from sm_bc.crypto.engines.zuc_engine import ZUCEngine
from sm_bc.crypto.params.key_parameter import KeyParameter
from sm_bc.crypto.params.parameters_with_iv import ParametersWithIV


class TestZUCEngine:
    """Test cases for ZUC-128 engine."""
    
    def test_algorithm_name(self):
        """Test that algorithm name is correct."""
        cipher = ZUCEngine()
        assert cipher.get_algorithm_name() == 'ZUC-128'
    
    def test_initialization_requires_iv(self):
        """Test that initialization requires IV."""
        cipher = ZUCEngine()
        key = bytes(16)
        
        with pytest.raises(ValueError, match="must include an IV"):
            cipher.init(True, KeyParameter(key))
    
    def test_initialization_requires_128bit_key(self):
        """Test that initialization requires 128-bit key."""
        cipher = ZUCEngine()
        key = bytes(8)  # Wrong size
        iv = bytes(16)
        
        with pytest.raises(ValueError, match="128-bit key"):
            cipher.init(True, ParametersWithIV(KeyParameter(key), iv))
    
    def test_initialization_requires_128bit_iv(self):
        """Test that initialization requires 128-bit IV."""
        cipher = ZUCEngine()
        key = bytes(16)
        iv = bytes(8)  # Wrong size
        
        with pytest.raises(ValueError, match="128-bit IV"):
            cipher.init(True, ParametersWithIV(KeyParameter(key), iv))
    
    def test_zuc_test_vector_1(self):
        """
        Test vector 1 from standards.
        
        Key:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        IV:   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        Output (first 2 words):
          z[0] = 0x27BEDE74
          z[1] = 0x018082DA
        """
        cipher = ZUCEngine()
        key = bytes(16)  # All zeros
        iv = bytes(16)   # All zeros
        
        cipher.init(True, ParametersWithIV(KeyParameter(key), iv))
        
        # Generate 8 bytes of keystream
        output = bytearray(8)
        input_data = bytes(8)  # All zeros
        cipher.process_bytes(input_data, 0, 8, output, 0)
        
        # Expected: 0x27BEDE74 018082DA
        expected = bytes.fromhex("27BEDE74018082DA")
        assert bytes(output) == expected
    
    def test_zuc_test_vector_2(self):
        """
        Test vector 2 from standards.
        
        Key:  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
        IV:   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
        Output (first 2 words):
          z[0] = 0x0657CFA0
          z[1] = 0x7096398B
        """
        cipher = ZUCEngine()
        key = bytes([0xFF] * 16)
        iv = bytes([0xFF] * 16)
        
        cipher.init(True, ParametersWithIV(KeyParameter(key), iv))
        
        # Generate 8 bytes of keystream
        output = bytearray(8)
        input_data = bytes(8)  # All zeros
        cipher.process_bytes(input_data, 0, 8, output, 0)
        
        # Expected: 0x0657CFA0 7096398B
        expected = bytes.fromhex("0657CFA07096398B")
        assert bytes(output) == expected
    
    def test_encryption_decryption_equivalence(self):
        """Test that encryption and decryption are equivalent (stream cipher property)."""
        key = bytes([0x12, 0x34, 0x56, 0x78] * 4)
        iv = bytes([0xAB, 0xCD, 0xEF, 0x01] * 4)
        plaintext = b"Hello, ZUC stream cipher!"
        
        # Encrypt
        cipher1 = ZUCEngine()
        cipher1.init(True, ParametersWithIV(KeyParameter(key), iv))
        ciphertext = bytearray(len(plaintext))
        cipher1.process_bytes(plaintext, 0, len(plaintext), ciphertext, 0)
        
        # Decrypt
        cipher2 = ZUCEngine()
        cipher2.init(False, ParametersWithIV(KeyParameter(key), iv))
        decrypted = bytearray(len(ciphertext))
        cipher2.process_bytes(ciphertext, 0, len(ciphertext), decrypted, 0)
        
        assert bytes(decrypted) == plaintext
    
    def test_return_byte(self):
        """Test processing single bytes."""
        cipher = ZUCEngine()
        key = bytes(16)
        iv = bytes(16)
        
        cipher.init(True, ParametersWithIV(KeyParameter(key), iv))
        
        # Process individual bytes
        output_bytes = []
        for b in b"Test":
            output_bytes.append(cipher.return_byte(b))
        
        # Should produce same result as process_bytes
        cipher2 = ZUCEngine()
        cipher2.init(True, ParametersWithIV(KeyParameter(key), iv))
        output = bytearray(4)
        cipher2.process_bytes(b"Test", 0, 4, output, 0)
        
        assert output_bytes == list(output)
    
    def test_reset(self):
        """Test that reset restores cipher to initial state."""
        cipher = ZUCEngine()
        key = bytes([0x11] * 16)
        iv = bytes([0x22] * 16)
        plaintext = b"Test message"
        
        cipher.init(True, ParametersWithIV(KeyParameter(key), iv))
        
        # First encryption
        output1 = bytearray(len(plaintext))
        cipher.process_bytes(plaintext, 0, len(plaintext), output1, 0)
        
        # Reset and encrypt again
        cipher.reset()
        output2 = bytearray(len(plaintext))
        cipher.process_bytes(plaintext, 0, len(plaintext), output2, 0)
        
        # Should produce same result
        assert bytes(output1) == bytes(output2)
    
    def test_empty_input(self):
        """Test processing empty input."""
        cipher = ZUCEngine()
        key = bytes(16)
        iv = bytes(16)
        
        cipher.init(True, ParametersWithIV(KeyParameter(key), iv))
        
        output = bytearray(0)
        result = cipher.process_bytes(bytes(0), 0, 0, output, 0)
        
        assert result == 0
        assert len(output) == 0
    
    def test_long_message(self):
        """Test processing a longer message."""
        cipher = ZUCEngine()
        key = bytes([0xAA] * 16)
        iv = bytes([0x55] * 16)
        
        # 1000 byte message
        plaintext = bytes(range(256)) * 3 + bytes(range(232))
        
        cipher.init(True, ParametersWithIV(KeyParameter(key), iv))
        ciphertext = bytearray(len(plaintext))
        cipher.process_bytes(plaintext, 0, len(plaintext), ciphertext, 0)
        
        # Decrypt
        cipher.reset()
        decrypted = bytearray(len(ciphertext))
        cipher.process_bytes(ciphertext, 0, len(ciphertext), decrypted, 0)
        
        assert bytes(decrypted) == plaintext
    
    def test_different_keys_produce_different_output(self):
        """Test that different keys produce different keystreams."""
        plaintext = b"Same message"
        
        # Key 1
        cipher1 = ZUCEngine()
        key1 = bytes([0x01] * 16)
        iv = bytes(16)
        cipher1.init(True, ParametersWithIV(KeyParameter(key1), iv))
        output1 = bytearray(len(plaintext))
        cipher1.process_bytes(plaintext, 0, len(plaintext), output1, 0)
        
        # Key 2
        cipher2 = ZUCEngine()
        key2 = bytes([0x02] * 16)
        cipher2.init(True, ParametersWithIV(KeyParameter(key2), iv))
        output2 = bytearray(len(plaintext))
        cipher2.process_bytes(plaintext, 0, len(plaintext), output2, 0)
        
        # Different keys should produce different outputs
        assert bytes(output1) != bytes(output2)
    
    def test_different_ivs_produce_different_output(self):
        """Test that different IVs produce different keystreams."""
        plaintext = b"Same message"
        key = bytes([0xFF] * 16)
        
        # IV 1
        cipher1 = ZUCEngine()
        iv1 = bytes([0x01] * 16)
        cipher1.init(True, ParametersWithIV(KeyParameter(key), iv1))
        output1 = bytearray(len(plaintext))
        cipher1.process_bytes(plaintext, 0, len(plaintext), output1, 0)
        
        # IV 2
        cipher2 = ZUCEngine()
        iv2 = bytes([0x02] * 16)
        cipher2.init(True, ParametersWithIV(KeyParameter(key), iv2))
        output2 = bytearray(len(plaintext))
        cipher2.process_bytes(plaintext, 0, len(plaintext), output2, 0)
        
        # Different IVs should produce different outputs
        assert bytes(output1) != bytes(output2)
