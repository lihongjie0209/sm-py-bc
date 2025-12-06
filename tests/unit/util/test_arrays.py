"""
Arrays utility tests.

Tests the Arrays utility class for byte array operations including:
- Equality comparison (normal and constant-time)
- Array concatenation
- Array filling
- Array cloning

Reference: test/unit/util/UtilityIntegration.test.ts (sm-js-bc)
Status: Enhanced and aligned with JS tests
"""

import pytest
from sm_bc.util.arrays import Arrays


class TestArraysEquality:
    """Tests for array equality checks."""
    
    def test_should_check_array_equality(self):
        """Should check array equality."""
        arr1 = bytes([1, 2, 3, 4])
        arr2 = bytes([1, 2, 3, 4])
        arr3 = bytes([1, 2, 3, 5])
        
        assert Arrays.are_equal(arr1, arr2) is True
        assert Arrays.are_equal(arr1, arr3) is False
    
    def test_should_handle_identical_reference(self):
        """Should handle identical reference."""
        arr = bytes([1, 2, 3])
        assert Arrays.are_equal(arr, arr) is True
    
    def test_should_handle_none_values(self):
        """Should handle None values."""
        arr = bytes([1, 2, 3])
        assert Arrays.are_equal(None, arr) is False
        assert Arrays.are_equal(arr, None) is False
        assert Arrays.are_equal(None, None) is False
    
    def test_should_handle_different_lengths(self):
        """Should handle different lengths."""
        arr1 = bytes([1, 2, 3])
        arr2 = bytes([1, 2, 3, 4])
        assert Arrays.are_equal(arr1, arr2) is False
    
    def test_should_work_with_bytearray(self):
        """Should work with bytearray."""
        arr1 = bytearray([1, 2, 3])
        arr2 = bytearray([1, 2, 3])
        arr3 = bytearray([1, 2, 4])
        
        assert Arrays.are_equal(arr1, arr2) is True
        assert Arrays.are_equal(arr1, arr3) is False


class TestArraysConstantTimeEquality:
    """Tests for constant-time array equality checks."""
    
    def test_constant_time_are_equal_same(self):
        """Should return True for equal arrays."""
        a = b"abc"
        b = b"abc"
        assert Arrays.constant_time_are_equal(a, b) is True
    
    def test_constant_time_are_equal_different(self):
        """Should return False for different arrays."""
        a = b"abc"
        c = b"abd"
        assert Arrays.constant_time_are_equal(a, c) is False
    
    def test_constant_time_are_equal_different_length(self):
        """Should return False for different length arrays."""
        a = b"abc"
        d = b"abcd"
        assert Arrays.constant_time_are_equal(a, d) is False
    
    def test_constant_time_same_reference(self):
        """Should return True for same reference."""
        a = b"test"
        assert Arrays.constant_time_are_equal(a, a) is True
    
    def test_constant_time_with_none(self):
        """Should handle None values."""
        a = b"test"
        assert Arrays.constant_time_are_equal(None, a) is False
        assert Arrays.constant_time_are_equal(a, None) is False


class TestArraysConcatenation:
    """Tests for array concatenation."""
    
    def test_should_concatenate_arrays(self):
        """Should concatenate arrays."""
        arr1 = bytes([1, 2])
        arr2 = bytes([3, 4])
        arr3 = bytes([5, 6])
        
        result = Arrays.concatenate(arr1, arr2, arr3)
        expected = bytes([1, 2, 3, 4, 5, 6])
        
        assert result == expected
    
    def test_should_concatenate_two_arrays(self):
        """Should concatenate two arrays."""
        arr1 = bytes([0xAA, 0xBB])
        arr2 = bytes([0xCC, 0xDD])
        
        result = Arrays.concatenate(arr1, arr2)
        expected = bytes([0xAA, 0xBB, 0xCC, 0xDD])
        
        assert result == expected
    
    def test_should_concatenate_single_array(self):
        """Should concatenate single array."""
        arr = bytes([1, 2, 3])
        result = Arrays.concatenate(arr)
        
        assert result == arr
    
    def test_should_concatenate_empty_arrays(self):
        """Should concatenate empty arrays."""
        arr1 = bytes([])
        arr2 = bytes([1, 2])
        arr3 = bytes([])
        
        result = Arrays.concatenate(arr1, arr2, arr3)
        assert result == bytes([1, 2])
    
    def test_should_work_with_bytearray(self):
        """Should work with bytearray."""
        arr1 = bytearray([1, 2])
        arr2 = bytearray([3, 4])
        
        result = Arrays.concatenate(arr1, arr2)
        assert result == bytearray([1, 2, 3, 4])


class TestArraysFill:
    """Tests for array filling."""
    
    def test_should_fill_arrays(self):
        """Should fill arrays."""
        arr = bytearray(5)
        Arrays.fill(arr, 42)
        
        assert list(arr) == [42, 42, 42, 42, 42]
    
    def test_should_fill_with_different_values(self):
        """Should fill with different values."""
        arr = bytearray(5)
        Arrays.fill(arr, 0xFF)
        
        assert list(arr) == [0xFF] * 5
    
    def test_should_fill_with_zero(self):
        """Should fill with zero."""
        arr = bytearray([1, 2, 3, 4, 5])
        Arrays.fill(arr, 0)
        
        assert list(arr) == [0, 0, 0, 0, 0]
    
    def test_should_handle_empty_array(self):
        """Should handle empty array."""
        arr = bytearray()
        Arrays.fill(arr, 42)
        
        assert len(arr) == 0
    
    def test_should_overwrite_existing_data(self):
        """Should overwrite existing data."""
        arr = bytearray([1, 2, 3])
        Arrays.fill(arr, 0xAA)
        
        assert list(arr) == [0xAA, 0xAA, 0xAA]


class TestArraysClone:
    """Tests for array cloning."""
    
    def test_should_clone_array(self):
        """Should clone array."""
        a = bytearray([1, 2, 3])
        b = Arrays.clone(a)
        
        assert a == b
        assert a is not b
    
    def test_should_create_independent_copy(self):
        """Should create independent copy."""
        original = bytearray([1, 2, 3])
        cloned = Arrays.clone(original)
        
        # Modify original
        original[0] = 99
        
        # Clone should not be affected
        assert cloned[0] == 1
        assert original[0] == 99
    
    def test_should_clone_bytes(self):
        """Should clone bytes."""
        original = bytes([1, 2, 3])
        cloned = Arrays.clone(original)
        
        assert cloned == original
        assert isinstance(cloned, bytearray)
    
    def test_should_clone_empty_array(self):
        """Should clone empty array."""
        original = bytearray()
        cloned = Arrays.clone(original)
        
        assert cloned == original
        assert cloned is not original
    
    def test_should_handle_none(self):
        """Should handle None."""
        result = Arrays.clone(None)
        assert result is None


class TestArraysEdgeCases:
    """Edge case tests for Arrays operations."""
    
    def test_should_handle_large_arrays(self):
        """Should handle large arrays."""
        size = 10000
        arr1 = bytes([i % 256 for i in range(size)])
        arr2 = bytes([i % 256 for i in range(size)])
        
        assert Arrays.are_equal(arr1, arr2) is True
    
    def test_should_concatenate_many_arrays(self):
        """Should concatenate many arrays."""
        arrays = [bytes([i]) for i in range(100)]
        result = Arrays.concatenate(*arrays)
        
        assert len(result) == 100
        assert list(result) == list(range(100))
    
    def test_should_fill_large_array(self):
        """Should fill large array."""
        arr = bytearray(1000)
        Arrays.fill(arr, 0x55)
        
        assert all(b == 0x55 for b in arr)


class TestArraysConsistency:
    """Consistency tests across different operations."""
    
    def test_should_maintain_data_integrity(self):
        """Should maintain data integrity across operations."""
        original = bytes([1, 2, 3, 4, 5])
        
        # Clone
        cloned = Arrays.clone(original)
        assert Arrays.are_equal(original, cloned)
        
        # Fill
        Arrays.fill(cloned, 0)
        assert not Arrays.are_equal(original, cloned)
    
    def test_should_concatenate_and_compare(self):
        """Should concatenate and compare correctly."""
        arr1 = bytes([1, 2])
        arr2 = bytes([3, 4])
        
        result1 = Arrays.concatenate(arr1, arr2)
        result2 = Arrays.concatenate(arr1, arr2)
        
        assert Arrays.are_equal(result1, result2)
    
    def test_should_work_with_mixed_types(self):
        """Should work with mixed bytes and bytearray."""
        b = bytes([1, 2, 3])
        ba = bytearray([1, 2, 3])
        
        assert Arrays.are_equal(b, ba)
        
        result = Arrays.concatenate(b, ba)
        assert len(result) == 6
