"""
Unit tests for SecureRandom class.

Reference: test/unit/util/SecureRandom.test.ts (sm-js-bc)
Status: Full alignment with JS tests
"""

import pytest
from sm_bc.util.secure_random import SecureRandom


class TestConstructorAndBasicOperations:
    """Constructor and basic operations tests."""
    
    def test_should_create_secure_random_instance(self):
        """Should create SecureRandom instance."""
        random = SecureRandom()
        assert random is not None
        assert isinstance(random, SecureRandom)


class TestNextBytes:
    """Tests for nextBytes() method."""
    
    def test_should_fill_array_with_random_bytes(self):
        """Should fill array with random bytes."""
        random = SecureRandom()
        data = bytearray(16)
        original_data = bytearray(data)
        
        random.next_bytes(data)
        
        # Array should be modified
        assert data != original_data
    
    def test_should_handle_empty_arrays(self):
        """Should handle empty arrays."""
        random = SecureRandom()
        empty_array = bytearray(0)
        
        # Should not raise exception
        random.next_bytes(empty_array)
        assert len(empty_array) == 0
    
    def test_should_handle_single_byte_arrays(self):
        """Should handle single byte arrays."""
        random = SecureRandom()
        single_byte = bytearray(1)
        
        random.next_bytes(single_byte)
        assert len(single_byte) == 1
    
    def test_should_handle_large_arrays(self):
        """Should handle large arrays."""
        random = SecureRandom()
        large_array = bytearray(1000)
        
        random.next_bytes(large_array)
        assert len(large_array) == 1000
        
        # Should not be all zeros (extremely unlikely)
        all_zeros = all(b == 0 for b in large_array)
        assert not all_zeros
    
    def test_should_produce_different_results_on_multiple_calls(self):
        """Should produce different results on multiple calls."""
        random = SecureRandom()
        bytes1 = bytearray(32)
        bytes2 = bytearray(32)
        
        random.next_bytes(bytes1)
        random.next_bytes(bytes2)
        
        assert bytes1 != bytes2


class TestGenerateSeed:
    """Tests for generateSeed() method."""
    
    def test_should_generate_seed_of_requested_length(self):
        """Should generate seed of requested length."""
        random = SecureRandom()
        seed_length = 16
        seed = random.generate_seed(seed_length)
        
        assert seed is not None
        assert len(seed) == seed_length
        assert isinstance(seed, bytearray)
    
    def test_should_generate_different_seeds_on_multiple_calls(self):
        """Should generate different seeds on multiple calls."""
        random = SecureRandom()
        seed1 = random.generate_seed(32)
        seed2 = random.generate_seed(32)
        
        assert seed1 != seed2
    
    def test_should_handle_zero_length_seed(self):
        """Should handle zero length seed."""
        random = SecureRandom()
        seed = random.generate_seed(0)
        assert len(seed) == 0
    
    def test_should_handle_single_byte_seed(self):
        """Should handle single byte seed."""
        random = SecureRandom()
        seed = random.generate_seed(1)
        assert len(seed) == 1
    
    def test_should_handle_large_seed_sizes(self):
        """Should handle large seed sizes."""
        random = SecureRandom()
        seed = random.generate_seed(1024)
        assert len(seed) == 1024


class TestMultipleInstancesBehavior:
    """Multiple instances behavior tests."""
    
    def test_should_produce_different_results_from_different_instances(self):
        """Should produce different results from different instances."""
        random1 = SecureRandom()
        random2 = SecureRandom()
        
        bytes1 = bytearray(16)
        bytes2 = bytearray(16)
        
        random1.next_bytes(bytes1)
        random2.next_bytes(bytes2)
        
        # Different instances should produce different random values
        # (extremely unlikely to be the same)
        assert bytes1 != bytes2
    
    def test_should_handle_generate_seed_from_different_instances(self):
        """Should handle generateSeed from different instances."""
        random1 = SecureRandom()
        random2 = SecureRandom()
        
        seed1 = random1.generate_seed(32)
        seed2 = random2.generate_seed(32)
        
        assert seed1 != seed2
    
    def test_should_handle_various_seed_sizes_with_generate_seed(self):
        """Should handle various seed sizes with generateSeed."""
        random = SecureRandom()
        seed_sizes = [1, 4, 8, 16, 32, 64]
        
        for size in seed_sizes:
            seed = random.generate_seed(size)
            assert len(seed) == size


class TestStateManagement:
    """State management tests."""
    
    def test_should_maintain_internal_state_correctly(self):
        """Should maintain internal state correctly."""
        random = SecureRandom()
        results = []
        
        # Generate multiple sequences
        for _ in range(5):
            data = bytearray(8)
            random.next_bytes(data)
            results.append(bytes(data))
        
        # All results should be different
        for i in range(len(results)):
            for j in range(i + 1, len(results)):
                assert results[i] != results[j]
    
    def test_should_handle_consecutive_operations(self):
        """Should handle consecutive operations."""
        random = SecureRandom()
        
        # Mix different sized operations
        small = bytearray(4)
        medium = bytearray(16)
        large = bytearray(64)
        
        random.next_bytes(small)
        random.next_bytes(medium)
        random.next_bytes(large)
        
        assert len(small) == 4
        assert len(medium) == 16
        assert len(large) == 64


class TestCryptographicProperties:
    """Cryptographic properties tests."""
    
    def test_should_produce_bytes_with_reasonable_distribution(self):
        """Should produce bytes with reasonable distribution."""
        random = SecureRandom()
        data = bytearray(1000)
        random.next_bytes(data)
        
        # Count occurrences of each byte value
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        
        # Should have some distribution (not all same value)
        unique_values = sum(1 for count in counts if count > 0)
        assert unique_values > 50  # At least 50 different byte values
        
        # No single byte value should dominate
        max_count = max(counts)
        assert max_count < len(data) * 0.1  # Less than 10% of total
    
    def test_should_not_have_obvious_patterns(self):
        """Should not have obvious patterns."""
        random = SecureRandom()
        data = bytearray(100)
        random.next_bytes(data)
        
        # Check for simple patterns
        consecutive_zeros = 0
        consecutive_ffs = 0
        max_consecutive_zeros = 0
        max_consecutive_ffs = 0
        
        for byte in data:
            if byte == 0:
                consecutive_zeros += 1
                consecutive_ffs = 0
                max_consecutive_zeros = max(max_consecutive_zeros, consecutive_zeros)
            elif byte == 0xFF:
                consecutive_ffs += 1
                consecutive_zeros = 0
                max_consecutive_ffs = max(max_consecutive_ffs, consecutive_ffs)
            else:
                consecutive_zeros = 0
                consecutive_ffs = 0
        
        # Should not have long runs of same byte
        assert max_consecutive_zeros < 20
        assert max_consecutive_ffs < 20


class TestEdgeCasesAndErrorHandling:
    """Edge cases and error handling tests."""
    
    def test_should_handle_rapid_succession_calls(self):
        """Should handle rapid succession calls."""
        random = SecureRandom()
        
        for _ in range(100):
            data = bytearray(1)
            random.next_bytes(data)
            # Should not raise exception
    
    def test_should_handle_mixed_array_sizes(self):
        """Should handle mixed array sizes."""
        random = SecureRandom()
        sizes = [1, 3, 7, 16, 33, 64, 127, 256]
        
        for size in sizes:
            data = bytearray(size)
            random.next_bytes(data)
            assert len(data) == size
    
    def test_should_work_with_different_array_creation_methods(self):
        """Should work with different array creation methods."""
        random = SecureRandom()
        
        # Different ways to create arrays
        array1 = bytearray(16)
        array2 = bytearray([0] * 8)
        array3 = bytearray(b'\x00' * 12)
        
        # Should not raise exceptions
        random.next_bytes(array1)
        random.next_bytes(array2)
        random.next_bytes(array3)


class TestPerformanceAndEfficiency:
    """Performance and efficiency tests."""
    
    def test_should_handle_large_arrays_efficiently(self):
        """Should handle large arrays efficiently."""
        import time
        
        random = SecureRandom()
        large_array = bytearray(10000)
        
        start_time = time.time()
        random.next_bytes(large_array)
        end_time = time.time()
        
        # Should complete reasonably quickly (less than 1 second)
        assert (end_time - start_time) < 1.0
        assert len(large_array) == 10000


class TestNextInt:
    """Tests for nextInt() method."""
    
    def test_should_return_random_integer(self):
        """Should return random integer."""
        random = SecureRandom()
        value = random.next_int()
        
        assert isinstance(value, int)
        assert 0 <= value < 2**32
    
    def test_should_return_different_values_on_multiple_calls(self):
        """Should return different values on multiple calls."""
        random = SecureRandom()
        values = [random.next_int() for _ in range(10)]
        
        # Should have some variation (not all same)
        unique_values = len(set(values))
        assert unique_values > 1
