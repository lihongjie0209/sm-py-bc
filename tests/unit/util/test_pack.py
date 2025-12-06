"""
Pack utility tests.

Tests the Pack utility class for packing/unpacking integers to/from byte arrays.
Supports both 32-bit (int) and 64-bit (long) operations with big-endian byte order.

Reference: Similar to Java Pack utility from bc-java
Status: Enhanced and aligned with expected behavior
"""

import pytest
from sm_bc.util.pack import Pack


class TestPackBigEndianToInt:
    """Tests for reading 32-bit integers from byte arrays."""
    
    def test_should_read_basic_value(self):
        """Should read basic 32-bit value."""
        bs = bytearray([0x01, 0x02, 0x03, 0x04])
        result = Pack.big_endian_to_int(bs, 0)
        assert result == 0x01020304
    
    def test_should_read_with_offset(self):
        """Should read with offset."""
        bs = bytearray([0xff, 0x01, 0x02, 0x03, 0x04, 0xff])
        result = Pack.big_endian_to_int(bs, 1)
        assert result == 0x01020304
    
    def test_should_read_max_value(self):
        """Should read max 32-bit unsigned value."""
        bs = bytearray([0xff, 0xff, 0xff, 0xff])
        result = Pack.big_endian_to_int(bs, 0)
        assert result == 0xffffffff
    
    def test_should_read_zero(self):
        """Should read zero."""
        bs = bytearray([0x00, 0x00, 0x00, 0x00])
        result = Pack.big_endian_to_int(bs, 0)
        assert result == 0
    
    def test_should_work_with_bytes(self):
        """Should work with bytes (not just bytearray)."""
        bs = bytes([0x12, 0x34, 0x56, 0x78])
        result = Pack.big_endian_to_int(bs, 0)
        assert result == 0x12345678
    
    def test_should_read_patterns(self):
        """Should read various patterns correctly."""
        test_cases = [
            ([0x00, 0x00, 0x00, 0x01], 0x00000001),
            ([0x00, 0x00, 0x01, 0x00], 0x00000100),
            ([0x00, 0x01, 0x00, 0x00], 0x00010000),
            ([0x01, 0x00, 0x00, 0x00], 0x01000000),
            ([0x80, 0x00, 0x00, 0x00], 0x80000000),
            ([0x7f, 0xff, 0xff, 0xff], 0x7fffffff),
        ]
        
        for bytes_val, expected in test_cases:
            bs = bytearray(bytes_val)
            result = Pack.big_endian_to_int(bs, 0)
            assert result == expected, f"Failed for {bytes_val}"


class TestPackIntToBigEndian:
    """Tests for writing 32-bit integers to byte arrays."""
    
    def test_should_write_basic_value(self):
        """Should write basic 32-bit value."""
        bs = bytearray(4)
        Pack.int_to_big_endian(0x01020304, bs, 0)
        assert list(bs) == [0x01, 0x02, 0x03, 0x04]
    
    def test_should_write_with_offset(self):
        """Should write with offset."""
        bs = bytearray(6)
        Pack.int_to_big_endian(0x01020304, bs, 1)
        assert list(bs) == [0x00, 0x01, 0x02, 0x03, 0x04, 0x00]
    
    def test_should_write_max_value(self):
        """Should write max 32-bit unsigned value."""
        bs = bytearray(4)
        Pack.int_to_big_endian(0xffffffff, bs, 0)
        assert list(bs) == [0xff, 0xff, 0xff, 0xff]
    
    def test_should_write_zero(self):
        """Should write zero."""
        bs = bytearray(4)
        Pack.int_to_big_endian(0, bs, 0)
        assert list(bs) == [0x00, 0x00, 0x00, 0x00]
    
    def test_should_overwrite_existing_data(self):
        """Should overwrite existing data."""
        bs = bytearray([0xff] * 6)
        Pack.int_to_big_endian(0x12345678, bs, 1)
        assert list(bs) == [0xff, 0x12, 0x34, 0x56, 0x78, 0xff]
    
    def test_should_write_patterns(self):
        """Should write various patterns correctly."""
        test_cases = [
            (0x00000001, [0x00, 0x00, 0x00, 0x01]),
            (0x00000100, [0x00, 0x00, 0x01, 0x00]),
            (0x00010000, [0x00, 0x01, 0x00, 0x00]),
            (0x01000000, [0x01, 0x00, 0x00, 0x00]),
            (0x80000000, [0x80, 0x00, 0x00, 0x00]),
            (0x7fffffff, [0x7f, 0xff, 0xff, 0xff]),
        ]
        
        for value, expected_bytes in test_cases:
            bs = bytearray(4)
            Pack.int_to_big_endian(value, bs, 0)
            assert list(bs) == expected_bytes, f"Failed for {hex(value)}"


class TestPackIntRoundTrip:
    """Round-trip tests for 32-bit integers."""
    
    def test_should_round_trip_basic(self):
        """Should round-trip basic value."""
        original = 0x12345678
        bs = bytearray(4)
        Pack.int_to_big_endian(original, bs, 0)
        result = Pack.big_endian_to_int(bs, 0)
        assert result == original
    
    def test_should_round_trip_multiple_values(self):
        """Should round-trip multiple values."""
        test_values = [
            0x00000000,
            0x00000001,
            0x000000ff,
            0x0000ffff,
            0x00ffffff,
            0x12345678,
            0x7fffffff,
            0x80000000,
            0xffffffff,
        ]
        
        for value in test_values:
            bs = bytearray(4)
            Pack.int_to_big_endian(value, bs, 0)
            result = Pack.big_endian_to_int(bs, 0)
            assert result == value, f"Failed for {hex(value)}"
    
    def test_should_round_trip_with_offset(self):
        """Should round-trip with offset."""
        original = 0xabcdef01
        bs = bytearray(10)
        Pack.int_to_big_endian(original, bs, 3)
        result = Pack.big_endian_to_int(bs, 3)
        assert result == original


class TestPackBigEndianToLong:
    """Tests for reading 64-bit integers from byte arrays."""
    
    def test_should_read_basic_value(self):
        """Should read basic 64-bit value."""
        bs = bytearray([
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08
        ])
        result = Pack.big_endian_to_long(bs, 0)
        assert result == 0x0102030405060708
    
    def test_should_read_with_offset(self):
        """Should read with offset."""
        bs = bytearray([
            0xff, 0xff,
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0xff, 0xff
        ])
        result = Pack.big_endian_to_long(bs, 2)
        assert result == 0x0102030405060708
    
    def test_should_read_max_value(self):
        """Should read max 64-bit value."""
        bs = bytearray([0xff] * 8)
        result = Pack.big_endian_to_long(bs, 0)
        assert result == 0xffffffffffffffff
    
    def test_should_read_zero(self):
        """Should read zero."""
        bs = bytearray([0x00] * 8)
        result = Pack.big_endian_to_long(bs, 0)
        assert result == 0
    
    def test_should_work_with_bytes(self):
        """Should work with bytes."""
        bs = bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])
        result = Pack.big_endian_to_long(bs, 0)
        assert result == 0x123456789abcdef0


class TestPackLongToBigEndian:
    """Tests for writing 64-bit integers to byte arrays."""
    
    def test_should_write_basic_value(self):
        """Should write basic 64-bit value."""
        bs = bytearray(8)
        val = 0x0102030405060708
        Pack.long_to_big_endian(val, bs, 0)
        assert list(bs) == [
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08
        ]
    
    def test_should_write_with_offset(self):
        """Should write with offset."""
        bs = bytearray(12)
        val = 0x0102030405060708
        Pack.long_to_big_endian(val, bs, 2)
        assert list(bs[2:10]) == [
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08
        ]
    
    def test_should_write_max_value(self):
        """Should write max 64-bit value."""
        bs = bytearray(8)
        Pack.long_to_big_endian(0xffffffffffffffff, bs, 0)
        assert list(bs) == [0xff] * 8
    
    def test_should_write_zero(self):
        """Should write zero."""
        bs = bytearray(8)
        Pack.long_to_big_endian(0, bs, 0)
        assert list(bs) == [0x00] * 8


class TestPackLongRoundTrip:
    """Round-trip tests for 64-bit integers."""
    
    def test_should_round_trip_basic(self):
        """Should round-trip basic value."""
        original = 0x123456789abcdef0
        bs = bytearray(8)
        Pack.long_to_big_endian(original, bs, 0)
        result = Pack.big_endian_to_long(bs, 0)
        assert result == original
    
    def test_should_round_trip_multiple_values(self):
        """Should round-trip multiple values."""
        test_values = [
            0x0000000000000000,
            0x0000000000000001,
            0x00000000ffffffff,
            0x0102030405060708,
            0x7fffffffffffffff,
            0x8000000000000000,
            0xffffffffffffffff,
        ]
        
        for value in test_values:
            bs = bytearray(8)
            Pack.long_to_big_endian(value, bs, 0)
            result = Pack.big_endian_to_long(bs, 0)
            assert result == value, f"Failed for {hex(value)}"
    
    def test_should_round_trip_with_offset(self):
        """Should round-trip with offset."""
        original = 0xfedcba9876543210
        bs = bytearray(16)
        Pack.long_to_big_endian(original, bs, 4)
        result = Pack.big_endian_to_long(bs, 4)
        assert result == original


class TestPackEdgeCases:
    """Edge case tests for Pack operations."""
    
    def test_should_handle_boundary_values_int(self):
        """Should handle boundary values for int."""
        # Test boundary between signed/unsigned interpretation
        test_cases = [
            0x7fffffff,  # Max positive in signed 32-bit
            0x80000000,  # Min negative in signed 32-bit (but we treat as unsigned)
            0xfffffffe,
            0xffffffff,  # Max unsigned 32-bit
        ]
        
        for value in test_cases:
            bs = bytearray(4)
            Pack.int_to_big_endian(value, bs, 0)
            result = Pack.big_endian_to_int(bs, 0)
            assert result == value
    
    def test_should_handle_boundary_values_long(self):
        """Should handle boundary values for long."""
        test_cases = [
            0x7fffffffffffffff,
            0x8000000000000000,
            0xfffffffffffffffe,
            0xffffffffffffffff,
        ]
        
        for value in test_cases:
            bs = bytearray(8)
            Pack.long_to_big_endian(value, bs, 0)
            result = Pack.big_endian_to_long(bs, 0)
            assert result == value
    
    def test_should_handle_alternating_patterns(self):
        """Should handle alternating bit patterns."""
        # Alternating bits: 0xAA = 10101010
        bs_int = bytearray([0xaa] * 4)
        result_int = Pack.big_endian_to_int(bs_int, 0)
        assert result_int == 0xaaaaaaaa
        
        bs_long = bytearray([0xaa] * 8)
        result_long = Pack.big_endian_to_long(bs_long, 0)
        assert result_long == 0xaaaaaaaaaaaaaaaa


class TestPackConsistency:
    """Consistency tests across different operations."""
    
    def test_should_be_consistent_across_types(self):
        """Should be consistent when reading as int vs part of long."""
        bs = bytearray([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])
        
        # Read first 4 bytes as int
        int_val = Pack.big_endian_to_int(bs, 0)
        assert int_val == 0x12345678
        
        # Read all 8 bytes as long
        long_val = Pack.big_endian_to_long(bs, 0)
        assert long_val == 0x123456789abcdef0
        
        # High 32 bits of long should equal int
        assert (long_val >> 32) == int_val
    
    def test_should_maintain_byte_order(self):
        """Should maintain big-endian byte order consistently."""
        value = 0x01020304
        bs = bytearray(4)
        Pack.int_to_big_endian(value, bs, 0)
        
        # Most significant byte should be first
        assert bs[0] == 0x01
        assert bs[1] == 0x02
        assert bs[2] == 0x03
        assert bs[3] == 0x04
