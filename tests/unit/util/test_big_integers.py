"""
BigIntegers utility tests.

Tests the BigIntegers utility class for BigInt operations including:
- Byte array conversions
- Random BigInt generation
- Bit length calculations

Reference: test/unit/util/UtilityIntegration.test.ts (sm-js-bc)
Status: Aligned with JS tests
"""

import pytest
from sm_bc.util.big_integers import BigIntegers
from sm_bc.util.secure_random import SecureRandom


class TestBigIntegersConversions:
    """Tests for BigInt to/from byte array conversions."""
    
    def test_should_convert_bigint_to_bytes_with_specified_length(self):
        """Should convert bigint to bytes with specified length."""
        value = 0x123456789ABCDEF
        bytes_result = BigIntegers.as_unsigned_byte_array(8, value)
        
        assert bytes_result is not None
        assert len(bytes_result) == 8
    
    def test_should_handle_zero(self):
        """Should handle zero."""
        bytes_result = BigIntegers.as_unsigned_byte_array(4, 0)
        expected = bytes([0, 0, 0, 0])
        
        assert bytes_result == expected
    
    def test_should_handle_large_numbers(self):
        """Should handle large numbers."""
        large_num = 2**256 - 1
        bytes_result = BigIntegers.as_unsigned_byte_array(32, large_num)
        
        assert len(bytes_result) == 32  # 256 bits = 32 bytes
        assert bytes_result[0] == 0xFF
        assert all(b == 0xFF for b in bytes_result)
    
    def test_should_convert_from_unsigned_byte_array(self):
        """Should convert from unsigned byte array."""
        byte_data = bytes([0x01, 0x23, 0x45, 0x67])
        value = BigIntegers.from_unsigned_byte_array(byte_data)
        
        assert value == 0x01234567
    
    def test_should_handle_round_trip_conversion(self):
        """Should handle round trip conversion."""
        original = 0x123456789ABCDEF
        bytes_result = BigIntegers.as_unsigned_byte_array(8, original)
        result = BigIntegers.from_unsigned_byte_array(bytes_result)
        
        assert result == original
    
    def test_should_handle_small_values_with_padding(self):
        """Should handle small values with padding."""
        value = 0xFF
        bytes_result = BigIntegers.as_unsigned_byte_array(4, value)
        
        assert len(bytes_result) == 4
        assert bytes_result == bytes([0x00, 0x00, 0x00, 0xFF])
    
    def test_should_handle_max_byte_value(self):
        """Should handle max byte value."""
        value = 0xFF
        bytes_result = BigIntegers.as_unsigned_byte_array(1, value)
        
        assert len(bytes_result) == 1
        assert bytes_result[0] == 0xFF


class TestBigIntegersBitLength:
    """Tests for bit length calculations."""
    
    def test_should_calculate_bit_length_of_zero(self):
        """Should calculate bit length of zero."""
        assert BigIntegers.bit_length(0) == 0
    
    def test_should_calculate_bit_length_of_one(self):
        """Should calculate bit length of one."""
        assert BigIntegers.bit_length(1) == 1
    
    def test_should_calculate_bit_length_of_powers_of_two(self):
        """Should calculate bit length of powers of two."""
        test_cases = [
            (2, 2),      # 0b10
            (4, 3),      # 0b100
            (8, 4),      # 0b1000
            (16, 5),     # 0b10000
            (256, 9),    # 0b100000000
            (1024, 11),  # 0b10000000000
        ]
        
        for value, expected_length in test_cases:
            assert BigIntegers.bit_length(value) == expected_length, f"Failed for {value}"
    
    def test_should_calculate_bit_length_of_arbitrary_numbers(self):
        """Should calculate bit length of arbitrary numbers."""
        test_cases = [
            (3, 2),      # 0b11
            (7, 3),      # 0b111
            (15, 4),     # 0b1111
            (255, 8),    # 0b11111111
            (1023, 10),  # 0b1111111111
        ]
        
        for value, expected_length in test_cases:
            assert BigIntegers.bit_length(value) == expected_length, f"Failed for {value}"
    
    def test_should_handle_negative_numbers(self):
        """Should handle negative numbers."""
        # Bit length of negative number should be same as positive
        assert BigIntegers.bit_length(-1) == 1
        assert BigIntegers.bit_length(-8) == 4
        assert BigIntegers.bit_length(-256) == 9


class TestBigIntegersRandomGeneration:
    """Tests for random BigInt generation."""
    
    def test_should_create_random_biginteger(self):
        """Should create random BigInteger."""
        random = SecureRandom()
        bit_length = 128
        
        value = BigIntegers.create_random_big_integer(bit_length, random)
        
        assert value >= 0
        # Bit length should be <= specified bit length
        assert value.bit_length() <= bit_length
    
    def test_should_generate_different_random_values(self):
        """Should generate different random values."""
        random = SecureRandom()
        bit_length = 256
        
        value1 = BigIntegers.create_random_big_integer(bit_length, random)
        value2 = BigIntegers.create_random_big_integer(bit_length, random)
        
        # Should be different (extremely unlikely to be the same)
        assert value1 != value2
    
    def test_should_respect_bit_length_constraint(self):
        """Should respect bit length constraint."""
        random = SecureRandom()
        
        for bit_length in [8, 16, 32, 64, 128]:
            value = BigIntegers.create_random_big_integer(bit_length, random)
            
            # The generated value should not exceed the bit length
            assert value.bit_length() <= bit_length, f"Failed for bit_length={bit_length}"
            
            # Most of the time, it should be close to the bit length
            # (This is probabilistic, but very likely)
            if bit_length > 1:
                # At least the value should not be trivially small
                assert value > 0
    
    def test_should_handle_small_bit_lengths(self):
        """Should handle small bit lengths."""
        random = SecureRandom()
        
        # 1-bit: should be 0 or 1
        value1 = BigIntegers.create_random_big_integer(1, random)
        assert value1 in [0, 1]
        
        # 2-bit: should be 0-3
        value2 = BigIntegers.create_random_big_integer(2, random)
        assert 0 <= value2 <= 3
    
    def test_should_generate_multiple_random_values(self):
        """Should generate multiple random values."""
        random = SecureRandom()
        bit_length = 64
        count = 10
        
        values = [BigIntegers.create_random_big_integer(bit_length, random) for _ in range(count)]
        
        # All values should be unique (extremely likely)
        assert len(set(values)) == count


class TestBigIntegersEdgeCases:
    """Edge case tests for BigIntegers."""
    
    def test_should_handle_zero_byte_length(self):
        """Should handle zero byte length."""
        bytes_result = BigIntegers.as_unsigned_byte_array(0, 0)
        assert len(bytes_result) == 0
    
    def test_should_handle_empty_byte_array(self):
        """Should handle empty byte array."""
        value = BigIntegers.from_unsigned_byte_array(bytes([]))
        assert value == 0
    
    def test_should_handle_single_byte(self):
        """Should handle single byte."""
        value = 42
        bytes_result = BigIntegers.as_unsigned_byte_array(1, value)
        
        assert len(bytes_result) == 1
        assert bytes_result[0] == 42
        
        # Round trip
        result = BigIntegers.from_unsigned_byte_array(bytes_result)
        assert result == value
    
    def test_should_handle_very_large_numbers(self):
        """Should handle very large numbers."""
        # 2^1024 - 1
        large_value = 2**1024 - 1
        byte_length = 128  # 1024 bits / 8
        
        bytes_result = BigIntegers.as_unsigned_byte_array(byte_length, large_value)
        assert len(bytes_result) == byte_length
        
        # Round trip
        result = BigIntegers.from_unsigned_byte_array(bytes_result)
        assert result == large_value
    
    def test_should_truncate_when_value_exceeds_length(self):
        """Should truncate when value exceeds length."""
        # Value that needs 4 bytes but we only request 2
        value = 0x12345678
        bytes_result = BigIntegers.as_unsigned_byte_array(2, value)
        
        assert len(bytes_result) == 2
        # Should get the low 2 bytes
        assert bytes_result == bytes([0x56, 0x78])


class TestBigIntegersConsistency:
    """Consistency tests for BigIntegers operations."""
    
    def test_should_be_consistent_across_multiple_conversions(self):
        """Should be consistent across multiple conversions."""
        test_values = [0, 1, 255, 256, 65535, 65536, 0x123456, 0xFFFFFFFF]
        
        for value in test_values:
            byte_length = (value.bit_length() + 7) // 8
            if byte_length == 0:
                byte_length = 1
            
            bytes_result = BigIntegers.as_unsigned_byte_array(byte_length, value)
            recovered = BigIntegers.from_unsigned_byte_array(bytes_result)
            
            assert recovered == value, f"Failed for value={value}"
    
    def test_should_maintain_byte_order(self):
        """Should maintain byte order (big-endian)."""
        # Test that bytes are in big-endian order
        value = 0x01020304
        bytes_result = BigIntegers.as_unsigned_byte_array(4, value)
        
        assert bytes_result[0] == 0x01
        assert bytes_result[1] == 0x02
        assert bytes_result[2] == 0x03
        assert bytes_result[3] == 0x04
