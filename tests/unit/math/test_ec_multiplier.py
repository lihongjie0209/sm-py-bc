"""
ECMultiplier basic tests.

Tests the EC point multiplication algorithms including:
- SimpleECMultiplier (basic double-and-add)
- Verification of multiplication correctness

Reference: test/unit/math/ECMultiplierBasic.test.ts (sm-js-bc)
Status: Aligned with JS tests

Uses test curve from bc-java:
  y² = x³ + 4x + 20 over F_1063
"""

import pytest
from sm_bc.math.ec_curve import Fp as FpCurve
from sm_bc.math.ec_multiplier import SimpleMultiplier


@pytest.fixture
def test_curve():
    """Create test curve: y² = x³ + 4x + 20 over F_1063."""
    p = 1063
    a = 4
    b = 20
    return FpCurve(p, a, b)


@pytest.fixture
def test_point(test_curve):
    """Create test point G(1, 5) on the curve."""
    return test_curve.validate_point(1, 5)


def normalize_point(point):
    """Helper to normalize a point and get affine coordinates."""
    if point.is_infinity:
        raise ValueError("Cannot get affine coordinates of infinity point")
    normalized = point.normalize()
    return {
        'x': normalized.x.to_big_integer(),
        'y': normalized.y.to_big_integer()
    }


class TestSimpleECMultiplier:
    """Tests for SimpleECMultiplier."""
    
    @pytest.fixture
    def multiplier(self):
        """Create SimpleECMultiplier instance."""
        return SimpleMultiplier()
    
    def test_should_multiply_by_zero(self, multiplier, test_point):
        """Should multiply by zero."""
        result = multiplier.multiply(test_point, 0)
        assert result.is_infinity
    
    def test_should_multiply_by_one(self, multiplier, test_point):
        """Should multiply by one."""
        result = multiplier.multiply(test_point, 1)
        coords = normalize_point(result)
        assert coords['x'] == 1
        assert coords['y'] == 5
    
    def test_should_multiply_by_two(self, multiplier, test_point):
        """Should multiply by two."""
        result = multiplier.multiply(test_point, 2)
        coords = normalize_point(result)
        assert coords['x'] == 817
        assert coords['y'] == 912
    
    def test_should_handle_small_positive_integers(self, multiplier, test_point):
        """Should handle small positive integers."""
        test_cases = [
            {'k': 3, 'expected_x': 54, 'expected_y': 521},
            {'k': 5, 'expected_x': 1010, 'expected_y': 399},
            {'k': 10, 'expected_x': 249, 'expected_y': 649}
        ]
        
        for test_case in test_cases:
            result = multiplier.multiply(test_point, test_case['k'])
            coords = normalize_point(result)
            assert coords['x'] == test_case['expected_x'], f"Failed for k={test_case['k']}"
            assert coords['y'] == test_case['expected_y'], f"Failed for k={test_case['k']}"
    
    def test_should_handle_negative_scalars(self, multiplier, test_point):
        """Should handle negative scalars."""
        result_2 = multiplier.multiply(test_point, 2)
        result_neg_2 = multiplier.multiply(test_point, -2)
        
        # -2*G should be the negation of 2*G
        expected = result_2.negate()
        result_coords = normalize_point(result_neg_2)
        expected_coords = normalize_point(expected)
        
        assert result_coords['x'] == expected_coords['x']
        assert result_coords['y'] == expected_coords['y']
    
    def test_should_handle_large_positive_scalars(self, multiplier, test_point):
        """Should handle large positive scalars."""
        large_k = 12345
        result = multiplier.multiply(test_point, large_k)
        
        assert not result.is_infinity
        assert result.is_valid()
    
    def test_should_multiply_infinity_point(self, multiplier, test_curve):
        """Should multiply infinity point."""
        infinity = test_curve.get_infinity()
        result = multiplier.multiply(infinity, 123)
        assert result.is_infinity


class TestECMultiplierCorrectness:
    """Correctness tests for EC multiplication."""
    
    @pytest.fixture
    def multiplier(self):
        """Create SimpleECMultiplier instance."""
        return SimpleMultiplier()
    
    def test_should_satisfy_distributive_property(self, multiplier, test_point):
        """Should satisfy distributive property: (a+b)*P = a*P + b*P."""
        a = 7
        b = 13
        
        # (a+b)*P
        result_ab = multiplier.multiply(test_point, a + b)
        
        # a*P + b*P
        result_a = multiplier.multiply(test_point, a)
        result_b = multiplier.multiply(test_point, b)
        result_sum = result_a.add(result_b)
        
        coords_ab = normalize_point(result_ab)
        coords_sum = normalize_point(result_sum)
        
        assert coords_ab['x'] == coords_sum['x']
        assert coords_ab['y'] == coords_sum['y']
    
    def test_should_satisfy_associative_property(self, multiplier, test_point):
        """Should satisfy associative property: (a*b)*P = a*(b*P)."""
        a = 5
        b = 7
        
        # (a*b)*P
        result_ab = multiplier.multiply(test_point, a * b)
        
        # a*(b*P)
        result_b = multiplier.multiply(test_point, b)
        result_a_times_b = multiplier.multiply(result_b, a)
        
        coords_ab = normalize_point(result_ab)
        coords_a_times_b = normalize_point(result_a_times_b)
        
        assert coords_ab['x'] == coords_a_times_b['x']
        assert coords_ab['y'] == coords_a_times_b['y']
    
    def test_should_handle_double_operation(self, multiplier, test_point):
        """Should handle double operation: 2*P = P + P."""
        # 2*P using multiplication
        result_mult = multiplier.multiply(test_point, 2)
        
        # P + P using addition
        result_add = test_point.add(test_point)
        
        coords_mult = normalize_point(result_mult)
        coords_add = normalize_point(result_add)
        
        assert coords_mult['x'] == coords_add['x']
        assert coords_mult['y'] == coords_add['y']
    
    def test_should_verify_kP_plus_negkP_equals_infinity(self, multiplier, test_point):
        """Should verify k*P + (-k)*P = infinity."""
        k = 17
        
        result_k = multiplier.multiply(test_point, k)
        result_neg_k = multiplier.multiply(test_point, -k)
        
        result_sum = result_k.add(result_neg_k)
        assert result_sum.is_infinity


class TestECMultiplierEdgeCases:
    """Edge case tests for EC multiplication."""
    
    @pytest.fixture
    def multiplier(self):
        """Create SimpleECMultiplier instance."""
        return SimpleMultiplier()
    
    def test_should_handle_multiplication_by_field_size(self, multiplier, test_point, test_curve):
        """Should handle multiplication by values near field size."""
        p = test_curve.q
        
        # Multiply by p (field size)
        result = multiplier.multiply(test_point, p)
        assert result.is_valid()
    
    def test_should_handle_consecutive_multiplications(self, multiplier, test_point):
        """Should handle consecutive multiplications."""
        # Build up multiplication step by step
        result = test_point
        for i in range(1, 6):
            result = multiplier.multiply(result, 2)
            assert result.is_valid()
    
    def test_should_handle_zero_then_nonzero(self, multiplier, test_point):
        """Should handle zero then non-zero multiplication."""
        # First multiply by 0
        result_zero = multiplier.multiply(test_point, 0)
        assert result_zero.is_infinity
        
        # Then multiply the same point by non-zero
        result_nonzero = multiplier.multiply(test_point, 5)
        assert not result_nonzero.is_infinity
        assert result_nonzero.is_valid()
    
    def test_should_handle_power_of_two_scalars(self, multiplier, test_point):
        """Should handle power-of-two scalars."""
        powers_of_two = [1, 2, 4, 8, 16, 32, 64, 128, 256]
        
        for power in powers_of_two:
            result = multiplier.multiply(test_point, power)
            assert result.is_valid(), f"Failed for 2^{power.bit_length()-1}"
    
    def test_should_handle_one_less_than_power_of_two(self, multiplier, test_point):
        """Should handle scalars that are one less than power of two."""
        values = [1, 3, 7, 15, 31, 63, 127, 255]
        
        for value in values:
            result = multiplier.multiply(test_point, value)
            assert result.is_valid(), f"Failed for {value}"


class TestECMultiplierConsistency:
    """Consistency tests across different operations."""
    
    @pytest.fixture
    def multiplier(self):
        """Create SimpleECMultiplier instance."""
        return SimpleMultiplier()
    
    def test_should_be_consistent_with_point_multiply(self, multiplier, test_point):
        """Should be consistent with point.multiply() method."""
        test_values = [0, 1, 2, 5, 10, 17, 100]
        
        for k in test_values:
            result_multiplier = multiplier.multiply(test_point, k)
            result_point = test_point.multiply(k)
            
            if result_multiplier.is_infinity:
                assert result_point.is_infinity
            else:
                coords_mult = normalize_point(result_multiplier)
                coords_point = normalize_point(result_point)
                assert coords_mult['x'] == coords_point['x']
                assert coords_mult['y'] == coords_point['y']
    
    def test_should_produce_same_results_multiple_calls(self, multiplier, test_point):
        """Should produce same results on multiple calls."""
        k = 42
        
        result1 = multiplier.multiply(test_point, k)
        result2 = multiplier.multiply(test_point, k)
        result3 = multiplier.multiply(test_point, k)
        
        coords1 = normalize_point(result1)
        coords2 = normalize_point(result2)
        coords3 = normalize_point(result3)
        
        assert coords1['x'] == coords2['x'] == coords3['x']
        assert coords1['y'] == coords2['y'] == coords3['y']
