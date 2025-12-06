"""
Unit tests for Integers utility class.

Reference: test/unit/util/Integers.test.ts (sm-js-bc)
Status: Full alignment with JS tests
"""

import pytest
from sm_bc.util.integers import Integers


class TestNumberOfLeadingZeros:
    """Tests for numberOfLeadingZeros() method."""
    
    def test_returns_32_for_zero(self):
        """Should return 32 for zero."""
        assert Integers.number_of_leading_zeros(0) == 32
    
    def test_returns_31_for_1(self):
        """Should return 31 for 1."""
        assert Integers.number_of_leading_zeros(1) == 31
    
    def test_returns_30_for_2(self):
        """Should return 30 for 2."""
        assert Integers.number_of_leading_zeros(2) == 30
    
    def test_returns_30_for_3(self):
        """Should return 30 for 3."""
        assert Integers.number_of_leading_zeros(3) == 30
    
    def test_handles_negative_numbers_with_msb_set(self):
        """Should return 0 for negative numbers with MSB set."""
        assert Integers.number_of_leading_zeros(-1) == 0
        assert Integers.number_of_leading_zeros(-2147483648) == 0  # 0x80000000
    
    def test_handles_powers_of_2(self):
        """Should handle powers of 2."""
        assert Integers.number_of_leading_zeros(1) == 31
        assert Integers.number_of_leading_zeros(2) == 30
        assert Integers.number_of_leading_zeros(4) == 29
        assert Integers.number_of_leading_zeros(8) == 28
        assert Integers.number_of_leading_zeros(16) == 27
        assert Integers.number_of_leading_zeros(32) == 26
        assert Integers.number_of_leading_zeros(64) == 25
        assert Integers.number_of_leading_zeros(128) == 24
        assert Integers.number_of_leading_zeros(256) == 23
        assert Integers.number_of_leading_zeros(512) == 22
        assert Integers.number_of_leading_zeros(1024) == 21
    
    def test_handles_large_positive_numbers(self):
        """Should handle large positive numbers."""
        assert Integers.number_of_leading_zeros(0x40000000) == 1  # 2^30
        assert Integers.number_of_leading_zeros(0x7FFFFFFF) == 1  # Max positive int
    
    def test_handles_numbers_with_mixed_bits(self):
        """Should handle numbers with mixed bits."""
        assert Integers.number_of_leading_zeros(0xFF) == 24        # 255
        assert Integers.number_of_leading_zeros(0xFFFF) == 16      # 65535
        assert Integers.number_of_leading_zeros(0xFFFFFF) == 8     # 16777215


class TestBitCount:
    """Tests for bitCount() method."""
    
    def test_returns_0_for_zero(self):
        """Should return 0 for zero."""
        assert Integers.bit_count(0) == 0
    
    def test_returns_1_for_powers_of_2(self):
        """Should return 1 for powers of 2."""
        assert Integers.bit_count(1) == 1
        assert Integers.bit_count(2) == 1
        assert Integers.bit_count(4) == 1
        assert Integers.bit_count(8) == 1
        assert Integers.bit_count(16) == 1
    
    def test_returns_32_for_minus_1(self):
        """Should return 32 for -1 (all bits set)."""
        assert Integers.bit_count(-1) == 32
    
    def test_counts_bits_correctly_for_various_numbers(self):
        """Should count bits correctly for various numbers."""
        assert Integers.bit_count(3) == 2       # 11
        assert Integers.bit_count(7) == 3       # 111
        assert Integers.bit_count(15) == 4      # 1111
        assert Integers.bit_count(31) == 5      # 11111
        assert Integers.bit_count(63) == 6      # 111111
        assert Integers.bit_count(127) == 7     # 1111111
        assert Integers.bit_count(255) == 8     # 11111111
    
    def test_handles_negative_numbers(self):
        """Should handle negative numbers."""
        assert Integers.bit_count(-2) == 31     # All bits set except LSB
        assert Integers.bit_count(-3) == 31     # 11111...1101
        assert Integers.bit_count(-4) == 30     # 11111...1100
    
    def test_handles_alternating_bit_patterns(self):
        """Should handle alternating bit patterns."""
        assert Integers.bit_count(0x55555555) == 16      # 01010101...
        assert Integers.bit_count(0xAAAAAAAA | 0) == 16  # 10101010...


class TestRotateLeft:
    """Tests for rotateLeft() method."""
    
    def test_handles_zero_rotation(self):
        """Should handle zero rotation."""
        assert Integers.rotate_left(0x12345678, 0) == 0x12345678
    
    def test_handles_single_bit_rotation(self):
        """Should handle single bit rotation."""
        assert Integers.rotate_left(1, 1) == 2
        assert Integers.rotate_left(2, 1) == 4
    
    def test_wraps_around_after_32_bits(self):
        """Should wrap around after 32 bits."""
        assert Integers.rotate_left(-2147483648, 1) == 1  # 0x80000000 rotated left by 1
        assert Integers.rotate_left(0x40000000, 1) == -2147483648  # Result is 0x80000000 as signed
    
    def test_handles_full_rotation_32_bits(self):
        """Should handle full rotation (32 bits)."""
        value = 0x12345678
        assert Integers.rotate_left(value, 32) == value
    
    def test_handles_rotation_distances_greater_than_32(self):
        """Should handle rotation distances > 32."""
        value = 0x12345678
        assert Integers.rotate_left(value, 33) == Integers.rotate_left(value, 1)
        assert Integers.rotate_left(value, 64) == value
    
    def test_preserves_bit_patterns_correctly(self):
        """Should preserve bit patterns correctly."""
        assert Integers.rotate_left(0xF0F0F0F0 | 0, 4) == 0x0F0F0F0F
        assert Integers.rotate_left(0xFF000000 | 0, 8) == 0xFF
    
    def test_handles_negative_rotation_distances(self):
        """Should handle negative rotation distances."""
        value = 0x12345678
        # Negative rotation should be equivalent to rotating right
        assert Integers.rotate_left(value, -1) == Integers.rotate_right(value, 1)


class TestRotateRight:
    """Tests for rotateRight() method."""
    
    def test_handles_zero_rotation(self):
        """Should handle zero rotation."""
        assert Integers.rotate_right(0x12345678, 0) == 0x12345678
    
    def test_handles_single_bit_rotation(self):
        """Should handle single bit rotation."""
        assert Integers.rotate_right(2, 1) == 1
        assert Integers.rotate_right(4, 1) == 2
    
    def test_wraps_around_from_lsb_to_msb(self):
        """Should wrap around from LSB to MSB."""
        assert Integers.rotate_right(1, 1) == -2147483648  # 0x80000000 as signed
        assert Integers.rotate_right(3, 1) == -2147483647  # 0x80000001 as signed
    
    def test_handles_full_rotation_32_bits(self):
        """Should handle full rotation (32 bits)."""
        value = 0x12345678
        assert Integers.rotate_right(value, 32) == value
    
    def test_is_inverse_of_rotate_left(self):
        """Should be inverse of rotateLeft."""
        value = 0x12345678
        assert Integers.rotate_right(Integers.rotate_left(value, 5), 5) == value
        assert Integers.rotate_left(Integers.rotate_right(value, 7), 7) == value
    
    def test_preserves_bit_patterns_correctly(self):
        """Should preserve bit patterns correctly."""
        assert Integers.rotate_right(0x0F0F0F0F, 4) == -252645136  # 0xF0F0F0F0 as signed
        assert Integers.rotate_right(0xFF, 8) == -16777216  # 0xFF000000 as signed


class TestNumberOfTrailingZeros:
    """Tests for numberOfTrailingZeros() method."""
    
    def test_returns_32_for_zero(self):
        """Should return 32 for zero."""
        assert Integers.number_of_trailing_zeros(0) == 32
    
    def test_returns_0_for_odd_numbers(self):
        """Should return 0 for odd numbers."""
        assert Integers.number_of_trailing_zeros(1) == 0
        assert Integers.number_of_trailing_zeros(3) == 0
        assert Integers.number_of_trailing_zeros(5) == 0
        assert Integers.number_of_trailing_zeros(-1) == 0
    
    def test_counts_trailing_zeros_for_powers_of_2(self):
        """Should count trailing zeros for powers of 2."""
        assert Integers.number_of_trailing_zeros(2) == 1
        assert Integers.number_of_trailing_zeros(4) == 2
        assert Integers.number_of_trailing_zeros(8) == 3
        assert Integers.number_of_trailing_zeros(16) == 4
        assert Integers.number_of_trailing_zeros(32) == 5
        assert Integers.number_of_trailing_zeros(64) == 6
        assert Integers.number_of_trailing_zeros(128) == 7
        assert Integers.number_of_trailing_zeros(256) == 8
    
    def test_handles_numbers_ending_in_zeros(self):
        """Should handle numbers ending in zeros."""
        assert Integers.number_of_trailing_zeros(6) == 1      # 110
        assert Integers.number_of_trailing_zeros(12) == 2     # 1100
        assert Integers.number_of_trailing_zeros(24) == 3     # 11000
        assert Integers.number_of_trailing_zeros(48) == 4     # 110000
    
    def test_handles_negative_numbers(self):
        """Should handle negative numbers."""
        assert Integers.number_of_trailing_zeros(-2) == 1
        assert Integers.number_of_trailing_zeros(-4) == 2
        assert Integers.number_of_trailing_zeros(-8) == 3
    
    def test_handles_large_numbers(self):
        """Should handle large numbers."""
        assert Integers.number_of_trailing_zeros(-2147483648) == 31  # 0x80000000
        assert Integers.number_of_trailing_zeros(0x40000000) == 30


class TestHighestOneBit:
    """Tests for highestOneBit() method."""
    
    def test_returns_0_for_zero(self):
        """Should return 0 for zero."""
        assert Integers.highest_one_bit(0) == 0
    
    def test_returns_number_itself_for_powers_of_2(self):
        """Should return the number itself for powers of 2."""
        assert Integers.highest_one_bit(1) == 1
        assert Integers.highest_one_bit(2) == 2
        assert Integers.highest_one_bit(4) == 4
        assert Integers.highest_one_bit(8) == 8
        assert Integers.highest_one_bit(16) == 16
    
    def test_returns_highest_power_of_2_for_positive_numbers(self):
        """Should return highest power of 2 ≤ n for positive numbers."""
        assert Integers.highest_one_bit(3) == 2
        assert Integers.highest_one_bit(5) == 4
        assert Integers.highest_one_bit(6) == 4
        assert Integers.highest_one_bit(7) == 4
        assert Integers.highest_one_bit(9) == 8
        assert Integers.highest_one_bit(15) == 8
        assert Integers.highest_one_bit(31) == 16
    
    def test_handles_negative_numbers(self):
        """Should handle negative numbers."""
        assert Integers.highest_one_bit(-1) == -2147483648  # 0x80000000 as signed
        assert Integers.highest_one_bit(-2) == -2147483648  # 0x80000000 as signed
    
    def test_handles_large_positive_numbers(self):
        """Should handle large positive numbers."""
        assert Integers.highest_one_bit(0x7FFFFFFF) == 0x40000000
        assert Integers.highest_one_bit(0x40000000) == 0x40000000
        assert Integers.highest_one_bit(0x3FFFFFFF) == 0x20000000


class TestLowestOneBit:
    """Tests for lowestOneBit() method."""
    
    def test_returns_0_for_zero(self):
        """Should return 0 for zero."""
        assert Integers.lowest_one_bit(0) == 0
    
    def test_returns_1_for_odd_numbers(self):
        """Should return 1 for odd numbers."""
        assert Integers.lowest_one_bit(1) == 1
        assert Integers.lowest_one_bit(3) == 1
        assert Integers.lowest_one_bit(5) == 1
        assert Integers.lowest_one_bit(7) == 1
        assert Integers.lowest_one_bit(-1) == 1
    
    def test_returns_lowest_power_of_2_factor(self):
        """Should return the lowest power of 2 factor."""
        assert Integers.lowest_one_bit(2) == 2
        assert Integers.lowest_one_bit(4) == 4
        assert Integers.lowest_one_bit(6) == 2
        assert Integers.lowest_one_bit(8) == 8
        assert Integers.lowest_one_bit(12) == 4
        assert Integers.lowest_one_bit(16) == 16
        assert Integers.lowest_one_bit(24) == 8
    
    def test_handles_negative_numbers(self):
        """Should handle negative numbers."""
        assert Integers.lowest_one_bit(-2) == 2
        assert Integers.lowest_one_bit(-4) == 4
        assert Integers.lowest_one_bit(-8) == 8
    
    def test_handles_large_numbers(self):
        """Should handle large numbers."""
        assert Integers.lowest_one_bit(-2147483648) == -2147483648  # 0x80000000 as signed
        assert Integers.lowest_one_bit(0x40000000) == 0x40000000
    
    def test_relationship_with_trailing_zeros(self):
        """Should satisfy: lowestOneBit(n) = 2^numberOfTrailingZeros(n) for n != 0."""
        test_values = [1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 24, 31, 32, 48, 64]
        for n in test_values:
            lowest = Integers.lowest_one_bit(n)
            trailing_zeros = Integers.number_of_trailing_zeros(n)
            assert lowest == (1 << trailing_zeros)


class TestEdgeCasesAndIntegration:
    """Edge cases and integration tests."""
    
    def test_all_bit_manipulation_functions_consistently(self):
        """Should handle all bit manipulation functions consistently."""
        test_value = 0x12345678
        
        # Test that operations are consistent
        leading_zeros = Integers.number_of_leading_zeros(test_value)
        trailing_zeros = Integers.number_of_trailing_zeros(test_value)
        bit_count = Integers.bit_count(test_value)
        
        assert 0 <= leading_zeros <= 32
        assert 0 <= trailing_zeros <= 32
        assert 0 <= bit_count <= 32
    
    def test_handles_boundary_values_correctly(self):
        """Should handle boundary values correctly."""
        max_int = 0x7FFFFFFF
        min_int = 0x80000000 | 0
        
        assert Integers.number_of_leading_zeros(max_int) == 1
        assert Integers.number_of_leading_zeros(min_int) == 0
        assert Integers.bit_count(max_int) == 31
        assert Integers.bit_count(min_int) == 1
    
    def test_rotation_symmetry(self):
        """Should handle rotation symmetry."""
        test_values = [0, 1, -1, 0x12345678, -2147483648]  # 0x80000000 as signed
        
        for value in test_values:
            # Rotating left by n then right by n should give original value
            for n in range(32):
                rotated = Integers.rotate_left(value, n)
                restored = Integers.rotate_right(rotated, n)
                assert restored == value
    
    def test_validates_bit_counting_properties(self):
        """Should validate bit counting properties."""
        # For any number n, bitCount(n) + bitCount(~n) should equal 32
        test_values = [0, 1, -1, 0x12345678, 0xAAAAAAAA | 0, 0x55555555]
        
        for n in test_values:
            count = Integers.bit_count(n)
            complement_count = Integers.bit_count(~n)
            assert count + complement_count == 32


class TestPerformanceAndCorrectness:
    """Performance and correctness tests."""
    
    def test_handles_all_32bit_integer_values_correctly(self):
        """Should handle all 32-bit integer values correctly."""
        # Test a sample of values across the entire range
        test_values = [
            0, 1, -1,
            0x7FFFFFFF, -2147483648,     # Max and min signed integers
            -1,                          # All bits set
            0x55555555, -1431655766,     # Alternating patterns (0xAAAAAAAA as signed)
            -16711936, 0x00FF00FF,       # Byte patterns (0xFF00FF00 as signed)
            123456789, -123456789        # Random values
        ]
        
        for value in test_values:
            # Should not raise exceptions
            Integers.number_of_leading_zeros(value)
            Integers.number_of_trailing_zeros(value)
            Integers.bit_count(value)
            Integers.highest_one_bit(value)
            Integers.lowest_one_bit(value)
            Integers.rotate_left(value, 5)
            Integers.rotate_right(value, 5)
