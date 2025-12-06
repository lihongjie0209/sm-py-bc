"""
PKCS#7 padding tests.

Reference: RFC 5652 Section 6.3
"""

import pytest
from sm_bc.crypto.paddings.pkcs7_padding import PKCS7Padding


class TestPKCS7PaddingBasic:
    """Basic functionality tests."""
    
    def test_add_padding_partial_block(self):
        """Should add padding to make data a multiple of block size."""
        padding = PKCS7Padding()
        data = b"Hello"  # 5 bytes
        block_size = 8
        
        padded = padding.add_padding(data, block_size)
        
        # Should pad to 8 bytes: 5 data + 3 padding
        assert len(padded) == 8
        # Last 3 bytes should be 0x03
        assert padded[-3:] == bytearray([0x03, 0x03, 0x03])
        # Original data should be intact
        assert padded[:5] == b"Hello"
    
    def test_add_padding_full_block(self):
        """Should add full block of padding when data is block-aligned."""
        padding = PKCS7Padding()
        data = b"12345678"  # 8 bytes (exactly one block)
        block_size = 8
        
        padded = padding.add_padding(data, block_size)
        
        # Should add full block of padding: 8 data + 8 padding
        assert len(padded) == 16
        # Last 8 bytes should be 0x08
        assert padded[-8:] == bytearray([0x08] * 8)
        # Original data should be intact
        assert padded[:8] == data
    
    def test_add_padding_single_byte(self):
        """Should handle single byte padding."""
        padding = PKCS7Padding()
        data = b"1234567"  # 7 bytes
        block_size = 8
        
        padded = padding.add_padding(data, block_size)
        
        # Should pad to 8 bytes: 7 data + 1 padding
        assert len(padded) == 8
        # Last byte should be 0x01
        assert padded[-1] == 0x01
        assert padded[:7] == data
    
    def test_add_padding_16_byte_block(self):
        """Should work with 16-byte block size."""
        padding = PKCS7Padding()
        data = b"Hello World!"  # 12 bytes
        block_size = 16
        
        padded = padding.add_padding(data, block_size)
        
        # Should pad to 16 bytes: 12 data + 4 padding
        assert len(padded) == 16
        # Last 4 bytes should be 0x04
        assert padded[-4:] == bytearray([0x04] * 4)
        assert padded[:12] == data


class TestPKCS7PaddingRemoval:
    """Padding removal tests."""
    
    def test_remove_padding_valid(self):
        """Should correctly remove valid padding."""
        padding = PKCS7Padding()
        # Manually create padded data
        padded = bytearray(b"Hello")
        padded.extend([0x03, 0x03, 0x03])  # 3 bytes of padding
        block_size = 8
        
        unpadded = padding.remove_padding(padded, block_size)
        
        assert bytes(unpadded) == b"Hello"
    
    def test_remove_padding_full_block(self):
        """Should handle removal of full block padding."""
        padding = PKCS7Padding()
        # Data with full block of padding
        padded = bytearray(b"12345678")
        padded.extend([0x08] * 8)
        block_size = 8
        
        unpadded = padding.remove_padding(padded, block_size)
        
        assert bytes(unpadded) == b"12345678"
    
    def test_remove_padding_single_byte(self):
        """Should handle single byte padding removal."""
        padding = PKCS7Padding()
        padded = bytearray(b"1234567")
        padded.extend([0x01])
        block_size = 8
        
        unpadded = padding.remove_padding(padded, block_size)
        
        assert bytes(unpadded) == b"1234567"
    
    def test_remove_padding_invalid_length(self):
        """Should reject padding with invalid length byte."""
        padding = PKCS7Padding()
        # Invalid: padding length (9) exceeds block size (8)
        padded = bytearray(b"1234567")
        padded.extend([0x09])
        block_size = 8
        
        with pytest.raises(ValueError, match='Invalid padding length'):
            padding.remove_padding(padded, block_size)
    
    def test_remove_padding_zero_length(self):
        """Should reject zero padding length."""
        padding = PKCS7Padding()
        padded = bytearray(b"1234567")
        padded.extend([0x00])
        block_size = 8
        
        with pytest.raises(ValueError, match='Invalid padding length'):
            padding.remove_padding(padded, block_size)
    
    def test_remove_padding_inconsistent_bytes(self):
        """Should reject padding with inconsistent bytes."""
        padding = PKCS7Padding()
        # Invalid: padding bytes don't match
        padded = bytearray(b"Hello")
        padded.extend([0x03, 0x02, 0x03])  # Inconsistent
        block_size = 8
        
        with pytest.raises(ValueError, match='Invalid padding bytes'):
            padding.remove_padding(padded, block_size)
    
    def test_remove_padding_not_block_aligned(self):
        """Should reject data not aligned to block size."""
        padding = PKCS7Padding()
        padded = bytearray(b"Hello")  # 5 bytes, not multiple of 8
        block_size = 8
        
        with pytest.raises(ValueError, match='not a multiple of block size'):
            padding.remove_padding(padded, block_size)
    
    def test_remove_padding_empty_data(self):
        """Should reject empty data."""
        padding = PKCS7Padding()
        padded = bytearray()
        block_size = 8
        
        with pytest.raises(ValueError, match='empty data'):
            padding.remove_padding(padded, block_size)


class TestPKCS7PaddingRoundTrip:
    """Round-trip tests."""
    
    def test_roundtrip_various_lengths(self):
        """Should correctly round-trip data of various lengths."""
        padding = PKCS7Padding()
        block_size = 16
        
        test_data = [
            b"",
            b"A",
            b"Hello",
            b"Hello World!",
            b"Exactly16Bytes!!" ,  # 16 bytes
            b"This is a longer message that spans multiple blocks!",
            b"X" * 100,
        ]
        
        for data in test_data:
            padded = padding.add_padding(data, block_size)
            unpadded = padding.remove_padding(padded, block_size)
            assert bytes(unpadded) == data
    
    def test_roundtrip_different_block_sizes(self):
        """Should work with different block sizes."""
        padding = PKCS7Padding()
        data = b"Test message for padding"
        
        block_sizes = [8, 16, 32, 64]
        
        for block_size in block_sizes:
            padded = padding.add_padding(data, block_size)
            assert len(padded) % block_size == 0
            unpadded = padding.remove_padding(padded, block_size)
            assert bytes(unpadded) == data


class TestPKCS7PaddingValidation:
    """Input validation tests."""
    
    def test_invalid_block_size_too_small(self):
        """Should reject block size less than 1."""
        padding = PKCS7Padding()
        data = b"Hello"
        
        with pytest.raises(ValueError, match='Invalid block size'):
            padding.add_padding(data, 0)
    
    def test_invalid_block_size_too_large(self):
        """Should reject block size greater than 255."""
        padding = PKCS7Padding()
        data = b"Hello"
        
        with pytest.raises(ValueError, match='Invalid block size'):
            padding.add_padding(data, 256)
    
    def test_valid_block_size_boundary(self):
        """Should accept block size of 255."""
        padding = PKCS7Padding()
        data = b"Hello"
        
        # Should not raise
        padded = padding.add_padding(data, 255)
        assert len(padded) == 255


class TestPKCS7PaddingUtilities:
    """Utility function tests."""
    
    def test_get_padded_length(self):
        """Should correctly calculate padded length."""
        padding = PKCS7Padding()
        block_size = 16
        
        # Test various lengths
        assert padding.get_padded_length(0, block_size) == 16
        assert padding.get_padded_length(1, block_size) == 16
        assert padding.get_padded_length(15, block_size) == 16
        assert padding.get_padded_length(16, block_size) == 32
        assert padding.get_padded_length(17, block_size) == 32
        assert padding.get_padded_length(31, block_size) == 32
        assert padding.get_padded_length(32, block_size) == 48


class TestPKCS7PaddingWithCipher:
    """Integration tests with cipher modes."""
    
    def test_cbc_with_padding(self):
        """Should work correctly with CBC mode."""
        from sm_bc.crypto.modes.cbc_block_cipher import CBCBlockCipher
        from sm_bc.crypto.engines.sm4_engine import SM4Engine
        from sm_bc.crypto.params.key_parameter import KeyParameter
        from sm_bc.crypto.params.parameters_with_iv import ParametersWithIV
        
        padding = PKCS7Padding()
        key = bytes.fromhex('0123456789abcdeffedcba9876543210')
        iv = bytes.fromhex('00112233445566778899aabbccddeeff')
        plaintext = b"This message is not block-aligned!"
        block_size = 16
        
        # Add padding
        padded_plaintext = padding.add_padding(plaintext, block_size)
        
        # Encrypt
        engine = SM4Engine()
        cipher = CBCBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), iv)
        cipher.init(True, params)
        
        ciphertext = bytearray(len(padded_plaintext))
        offset = 0
        while offset < len(padded_plaintext):
            cipher.process_block(padded_plaintext, offset, ciphertext, offset)
            offset += block_size
        
        # Decrypt
        cipher.init(False, params)
        decrypted_padded = bytearray(len(ciphertext))
        offset = 0
        while offset < len(ciphertext):
            cipher.process_block(ciphertext, offset, decrypted_padded, offset)
            offset += block_size
        
        # Remove padding
        decrypted = padding.remove_padding(decrypted_padded, block_size)
        
        assert bytes(decrypted) == plaintext
