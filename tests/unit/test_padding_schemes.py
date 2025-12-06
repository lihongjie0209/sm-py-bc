"""
Comprehensive tests for all padding schemes.
"""

import pytest
from sm_bc.crypto.paddings import (
    PKCS7Padding,
    ZeroBytePadding,
    ISO10126Padding,
    ISO7816d4Padding
)


class TestZeroBytePadding:
    """Zero Byte Padding tests."""
    
    def test_add_padding_partial_block(self):
        """Should add zero bytes to reach block size."""
        padding = ZeroBytePadding()
        data = b"Hello"  # 5 bytes
        block_size = 8
        
        padded = padding.add_padding(data, block_size)
        
        assert len(padded) == 8
        assert padded[:5] == b"Hello"
        assert padded[5:] == bytearray([0x00, 0x00, 0x00])
    
    def test_add_padding_block_aligned(self):
        """Should not add padding when already block-aligned."""
        padding = ZeroBytePadding()
        data = b"12345678"  # 8 bytes
        block_size = 8
        
        padded = padding.add_padding(data, block_size)
        
        # Should not add any padding
        assert len(padded) == 8
        assert padded == data
    
    def test_get_padded_length(self):
        """Should correctly calculate padded length."""
        padding = ZeroBytePadding()
        block_size = 16
        
        assert padding.get_padded_length(0, block_size) == 0
        assert padding.get_padded_length(1, block_size) == 16
        assert padding.get_padded_length(15, block_size) == 16
        assert padding.get_padded_length(16, block_size) == 16
        assert padding.get_padded_length(17, block_size) == 32


class TestISO10126Padding:
    """ISO 10126 Padding tests."""
    
    def test_add_padding_structure(self):
        """Should add random bytes with length in last byte."""
        padding = ISO10126Padding()
        data = b"Hello"  # 5 bytes
        block_size = 8
        
        padded = padding.add_padding(data, block_size)
        
        # Should pad to 8 bytes
        assert len(padded) == 8
        # Original data intact
        assert padded[:5] == b"Hello"
        # Last byte is padding length (3)
        assert padded[-1] == 3
        # Middle bytes are random (cannot predict)
        assert len(padded[5:8]) == 3
    
    def test_roundtrip(self):
        """Should correctly round-trip."""
        padding = ISO10126Padding()
        data = b"Test message"
        block_size = 16
        
        padded = padding.add_padding(data, block_size)
        unpadded = padding.remove_padding(padded, block_size)
        
        assert bytes(unpadded) == data
    
    def test_random_bytes_differ(self):
        """Padding bytes should be random (different each time)."""
        padding = ISO10126Padding()
        data = b"Test"
        block_size = 16
        
        padded1 = padding.add_padding(data, block_size)
        padded2 = padding.add_padding(data, block_size)
        
        # Same length
        assert len(padded1) == len(padded2) == 16
        # Same original data
        assert padded1[:4] == padded2[:4]
        # Same padding length in last byte
        assert padded1[-1] == padded2[-1]
        # But random middle bytes should differ (very high probability)
        # Note: There's a tiny chance they could be same, but extremely unlikely
        assert padded1[4:-1] != padded2[4:-1]
    
    def test_remove_padding_validation(self):
        """Should validate padding length."""
        padding = ISO10126Padding()
        
        # Invalid: padding length exceeds block size
        invalid_data = bytearray(b"1234567" + bytes([9]))
        with pytest.raises(ValueError, match='Invalid padding length'):
            padding.remove_padding(invalid_data, 8)
    
    def test_full_block_padding(self):
        """Should add full block when data is block-aligned."""
        padding = ISO10126Padding()
        data = b"Exactly16Bytes!!"  # 16 bytes
        block_size = 16
        
        padded = padding.add_padding(data, block_size)
        
        # Should add full block
        assert len(padded) == 32
        assert padded[:16] == data
        assert padded[-1] == 16  # Full block padding


class TestISO7816d4Padding:
    """ISO 7816-4 Padding tests."""
    
    def test_add_padding_structure(self):
        """Should add 0x80 followed by zeros."""
        padding = ISO7816d4Padding()
        data = b"Hello"  # 5 bytes
        block_size = 8
        
        padded = padding.add_padding(data, block_size)
        
        assert len(padded) == 8
        assert padded[:5] == b"Hello"
        assert padded[5] == 0x80  # Mandatory 0x80
        assert padded[6:] == bytearray([0x00, 0x00])
    
    def test_single_byte_padding(self):
        """Should add only 0x80 when one byte needed."""
        padding = ISO7816d4Padding()
        data = b"1234567"  # 7 bytes
        block_size = 8
        
        padded = padding.add_padding(data, block_size)
        
        assert len(padded) == 8
        assert padded[:7] == data
        assert padded[7] == 0x80
    
    def test_roundtrip(self):
        """Should correctly round-trip."""
        padding = ISO7816d4Padding()
        test_data = [
            b"A",
            b"Hello",
            b"Hello World!",
            b"Exactly16Bytes!!",
            b"X" * 100,
        ]
        block_size = 16
        
        for data in test_data:
            padded = padding.add_padding(data, block_size)
            unpadded = padding.remove_padding(padded, block_size)
            assert bytes(unpadded) == data
    
    def test_remove_padding_finds_marker(self):
        """Should find and remove from 0x80 marker."""
        padding = ISO7816d4Padding()
        
        # Manually construct padded data
        padded = bytearray(b"Test")
        padded.extend([0x80, 0x00, 0x00, 0x00])
        block_size = 8
        
        unpadded = padding.remove_padding(padded, block_size)
        
        assert bytes(unpadded) == b"Test"
    
    def test_invalid_padding_no_marker(self):
        """Should reject padding without 0x80 marker."""
        padding = ISO7816d4Padding()
        
        # Invalid: last block has all zeros, no 0x80 marker
        invalid_data = bytearray([0x00] * 16)
        
        with pytest.raises(ValueError, match='no 0x80 byte found'):
            padding.remove_padding(invalid_data, 8)
    
    def test_invalid_padding_non_zero_in_area(self):
        """Should reject if non-zero bytes appear in padding area."""
        padding = ISO7816d4Padding()
        
        # Invalid: non-zero byte in padding area (scanned backward)
        # Create data with valid first block, then invalid padding
        invalid_data = bytearray([0x01] * 8)  # First block
        invalid_data.extend([0x80, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # Second block with invalid padding
        
        with pytest.raises(ValueError, match='non-zero byte in padding area'):
            padding.remove_padding(invalid_data, 8)
    
    def test_full_block_padding(self):
        """Should add full block with 0x80 followed by zeros."""
        padding = ISO7816d4Padding()
        data = b"Exactly16Bytes!!"  # 16 bytes
        block_size = 16
        
        padded = padding.add_padding(data, block_size)
        
        assert len(padded) == 32
        assert padded[:16] == data
        assert padded[16] == 0x80
        assert all(b == 0x00 for b in padded[17:])


class TestPaddingComparison:
    """Compare different padding schemes."""
    
    def test_all_schemes_roundtrip(self):
        """All schemes should correctly round-trip."""
        schemes = [
            ('PKCS7', PKCS7Padding()),
            ('ISO10126', ISO10126Padding()),
            ('ISO7816-4', ISO7816d4Padding()),
        ]
        
        data = b"Test message for padding comparison"
        block_size = 16
        
        for name, scheme in schemes:
            if hasattr(scheme, 'remove_padding'):
                padded = scheme.add_padding(data, block_size)
                unpadded = scheme.remove_padding(padded, block_size)
                assert bytes(unpadded) == data, f"{name} failed round-trip"
    
    def test_padding_lengths(self):
        """All schemes should produce same padded length."""
        schemes = [
            PKCS7Padding(),
            ZeroBytePadding(),
            ISO10126Padding(),
            ISO7816d4Padding(),
        ]
        
        data = b"Hello"
        block_size = 16
        
        lengths = set()
        for scheme in schemes:
            padded = scheme.add_padding(data, block_size)
            lengths.add(len(padded))
        
        # All should produce 16 bytes for this input
        assert len(lengths) == 1
        assert lengths.pop() == 16
    
    def test_different_padding_bytes(self):
        """Different schemes produce different padding patterns."""
        data = b"Hello"
        block_size = 16
        
        pkcs7 = PKCS7Padding().add_padding(data, block_size)
        zero = ZeroBytePadding().add_padding(data, block_size)
        iso7816 = ISO7816d4Padding().add_padding(data, block_size)
        
        # All start with same original data
        assert pkcs7[:5] == zero[:5] == iso7816[:5] == b"Hello"
        
        # But padding bytes differ
        # PKCS7: all bytes are 0x0B (11 in decimal)
        assert all(b == 11 for b in pkcs7[5:])
        
        # Zero: all bytes are 0x00
        assert all(b == 0 for b in zero[5:])
        
        # ISO7816-4: starts with 0x80, rest are 0x00
        assert iso7816[5] == 0x80
        assert all(b == 0 for b in iso7816[6:])


class TestPaddingEdgeCases:
    """Edge case tests for all padding schemes."""
    
    def test_empty_data(self):
        """Should handle empty data."""
        block_size = 16
        
        # PKCS7: adds full block
        pkcs7 = PKCS7Padding()
        padded = pkcs7.add_padding(b"", block_size)
        assert len(padded) == 16
        assert all(b == 16 for b in padded)
        
        # Zero: returns empty (already aligned)
        zero = ZeroBytePadding()
        padded = zero.add_padding(b"", block_size)
        assert len(padded) == 0
        
        # ISO10126: adds full block
        iso10126 = ISO10126Padding()
        padded = iso10126.add_padding(b"", block_size)
        assert len(padded) == 16
        assert padded[-1] == 16
        
        # ISO7816-4: adds full block
        iso7816 = ISO7816d4Padding()
        padded = iso7816.add_padding(b"", block_size)
        assert len(padded) == 16
        assert padded[0] == 0x80
    
    def test_large_data(self):
        """Should handle large data correctly."""
        data = b"X" * 1000
        block_size = 16
        
        schemes = [
            PKCS7Padding(),
            ZeroBytePadding(),
            ISO10126Padding(),
            ISO7816d4Padding(),
        ]
        
        for scheme in schemes:
            padded = scheme.add_padding(data, block_size)
            # Should be aligned to block size
            assert len(padded) % block_size == 0
            # Should contain original data
            assert padded[:1000] == data
    
    def test_various_block_sizes(self):
        """Should work with various block sizes."""
        data = b"Test"
        block_sizes = [8, 16, 32, 64, 128]
        
        pkcs7 = PKCS7Padding()
        
        for block_size in block_sizes:
            padded = pkcs7.add_padding(data, block_size)
            assert len(padded) % block_size == 0
            unpadded = pkcs7.remove_padding(padded, block_size)
            assert bytes(unpadded) == data
