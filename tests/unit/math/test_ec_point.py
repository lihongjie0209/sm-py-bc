"""
ECPoint basic operations unit tests.

Reference: test/unit/math/ECPoint.test.ts (sm-js-bc)
Status: Full alignment with JS tests

Uses test curve from bc-java ECPointTest.java:
  y² = x³ + 4x + 20 over F_1063
"""

import pytest
from sm_bc.math.ec_curve import Fp as FpCurve


class TestECPointValidation:
    """Point validation tests."""
    
    @pytest.fixture
    def test_curve(self):
        """Create test curve: y² = x³ + 4x + 20 over F_1063."""
        p = 1063
        a = 4
        b = 20
        return FpCurve(p, a, b)
    
    @pytest.fixture
    def test_points(self, test_curve):
        """Create test points from bc-java (verified to be on curve)."""
        P1 = test_curve.validate_point(1, 5)
        P2 = test_curve.validate_point(4, 10)
        return P1, P2
    
    def test_should_validate_points_on_curve(self, test_points):
        """Should validate points on curve."""
        P1, P2 = test_points
        assert P1.is_valid()
        assert P2.is_valid()
    
    def test_should_recognize_infinity(self, test_curve):
        """Should recognize infinity."""
        inf = test_curve.get_infinity()
        assert inf.is_infinity
        assert inf.is_valid()


class TestPointDoubling:
    """Point doubling (twice) tests."""
    
    @pytest.fixture
    def test_curve(self):
        """Create test curve."""
        p = 1063
        a = 4
        b = 20
        return FpCurve(p, a, b)
    
    @pytest.fixture
    def P1(self, test_curve):
        """Create test point P1."""
        return test_curve.validate_point(1, 5)
    
    def test_should_compute_2P_correctly(self, P1):
        """Should compute 2*P correctly."""
        two_P = P1.twice()
        
        assert not two_P.is_infinity
        assert two_P.is_valid()
        
        # Verify by computing P + P
        P_plus_P = P1.add(P1)
        assert two_P.normalize() == P_plus_P.normalize()
    
    def test_should_handle_infinity(self, test_curve):
        """Should handle infinity."""
        inf = test_curve.get_infinity()
        result = inf.twice()
        assert result.is_infinity


class TestPointAddition:
    """Point addition tests."""
    
    @pytest.fixture
    def test_curve(self):
        """Create test curve."""
        p = 1063
        a = 4
        b = 20
        return FpCurve(p, a, b)
    
    @pytest.fixture
    def test_points(self, test_curve):
        """Create test points."""
        P1 = test_curve.validate_point(1, 5)
        P2 = test_curve.validate_point(4, 10)
        return P1, P2
    
    def test_should_compute_P1_plus_P2_correctly(self, test_points):
        """Should compute P1 + P2 correctly."""
        P1, P2 = test_points
        result = P1.add(P2)
        assert not result.is_infinity
        assert result.is_valid()
    
    def test_should_be_commutative(self, test_points):
        """Should be commutative: P1 + P2 = P2 + P1."""
        P1, P2 = test_points
        r1 = P1.add(P2)
        r2 = P2.add(P1)
        assert r1.normalize() == r2.normalize()
    
    def test_should_handle_P_plus_infinity_equals_P(self, test_curve, test_points):
        """Should handle P + infinity = P."""
        P1, _ = test_points
        inf = test_curve.get_infinity()
        result = P1.add(inf)
        assert result.normalize() == P1.normalize()
    
    def test_should_handle_infinity_plus_P_equals_P(self, test_curve, test_points):
        """Should handle infinity + P = P."""
        P1, _ = test_points
        inf = test_curve.get_infinity()
        result = inf.add(P1)
        assert result.normalize() == P1.normalize()
    
    def test_should_handle_P_plus_negP_equals_infinity(self, test_points):
        """Should handle P + (-P) = infinity."""
        P1, _ = test_points
        neg_P = P1.negate()
        result = P1.add(neg_P)
        assert result.is_infinity


class TestPointNegation:
    """Point negation tests."""
    
    @pytest.fixture
    def test_curve(self):
        """Create test curve."""
        p = 1063
        a = 4
        b = 20
        return FpCurve(p, a, b)
    
    @pytest.fixture
    def P1(self, test_curve):
        """Create test point P1."""
        return test_curve.validate_point(1, 5)
    
    def test_should_compute_negP_correctly(self, test_curve, P1):
        """Should compute -P correctly."""
        neg_P = P1.negate()
        
        assert not neg_P.is_infinity
        assert neg_P.is_valid()
        
        # Verify x coordinate is same, y is negated (mod p)
        P_norm = P1.normalize()
        neg_P_norm = neg_P.normalize()
        p = test_curve.q  # Use q (the prime) not field_size (bit length)
        
        assert neg_P_norm.x.to_big_integer() == P_norm.x.to_big_integer()
        # y-coordinate of -P should be (p - y) mod p
        expected_y = (p - P_norm.y.to_big_integer()) % p
        actual_y = neg_P_norm.y.to_big_integer()
        assert actual_y == expected_y, f"Expected {expected_y}, got {actual_y}"


class TestPointEncodingDecoding:
    """Point encoding/decoding tests."""
    
    @pytest.fixture
    def test_curve(self):
        """Create test curve."""
        p = 1063
        a = 4
        b = 20
        return FpCurve(p, a, b)
    
    @pytest.fixture
    def P1(self, test_curve):
        """Create test point P1."""
        return test_curve.validate_point(1, 5)
    
    def test_should_encode_decode_uncompressed_point_correctly(self, test_curve, P1):
        """Should encode/decode uncompressed point correctly."""
        encoded = P1.get_encoded(False)
        
        # Should start with 0x04 for uncompressed
        assert encoded[0] == 0x04
        
        decoded = test_curve.decode_point(encoded)
        assert decoded.normalize() == P1.normalize()
    
    def test_should_encode_infinity_as_single_0x00_byte(self, test_curve):
        """Should encode infinity as single 0x00 byte."""
        inf = test_curve.get_infinity()
        encoded = inf.get_encoded(False)
        
        assert len(encoded) == 1
        assert encoded[0] == 0x00
        
        decoded = test_curve.decode_point(encoded)
        assert decoded.is_infinity


class TestPointNormalization:
    """Point normalization tests."""
    
    @pytest.fixture
    def test_curve(self):
        """Create test curve."""
        p = 1063
        a = 4
        b = 20
        return FpCurve(p, a, b)
    
    @pytest.fixture
    def P1(self, test_curve):
        """Create test point P1."""
        return test_curve.validate_point(1, 5)
    
    def test_should_normalize_point_to_affine_coordinates(self, P1):
        """Should normalize point to affine coordinates."""
        normed = P1.normalize()
        
        assert normed.is_valid()
        # Check if normalized (Z=1 or no Z coordinates)
        if normed.zs:
            assert normed.zs[0].to_big_integer() == 1
    
    def test_should_be_idempotent(self, P1):
        """Should be idempotent: normalize(normalize(P)) = normalize(P)."""
        normed1 = P1.normalize()
        normed2 = normed1.normalize()
        
        assert normed2 == normed1


class TestPointMultiplication:
    """Point multiplication tests."""
    
    @pytest.fixture
    def test_curve(self):
        """Create test curve."""
        p = 1063
        a = 4
        b = 20
        return FpCurve(p, a, b)
    
    @pytest.fixture
    def P1(self, test_curve):
        """Create test point P1."""
        return test_curve.validate_point(1, 5)
    
    def test_should_multiply_by_0_to_get_infinity(self, P1):
        """Should multiply by 0 to get infinity."""
        result = P1.multiply(0)
        assert result.is_infinity
    
    def test_should_multiply_by_1_to_get_P(self, P1):
        """Should multiply by 1 to get P."""
        result = P1.multiply(1)
        assert result.normalize() == P1.normalize()
    
    def test_should_multiply_by_2_equals_twice(self, P1):
        """Should multiply by 2 equals twice."""
        result_mult = P1.multiply(2)
        result_twice = P1.twice()
        assert result_mult.normalize() == result_twice.normalize()
    
    def test_should_multiply_by_small_integers(self, P1):
        """Should multiply by small integers."""
        for k in [3, 4, 5, 10]:
            result = P1.multiply(k)
            assert result.is_valid()
            assert not result.is_infinity
    
    def test_should_handle_negative_multiplier(self, P1):
        """Should handle negative multiplier."""
        result_pos = P1.multiply(5)
        result_neg = P1.multiply(-5)
        
        # k*P + (-k)*P should equal infinity
        sum_result = result_pos.add(result_neg)
        assert sum_result.is_infinity
    
    def test_should_verify_kP_consistency(self, P1):
        """Should verify k*P consistency."""
        # 3*P = P + P + P
        three_P_mult = P1.multiply(3)
        three_P_add = P1.add(P1).add(P1)
        assert three_P_mult.normalize() == three_P_add.normalize()


class TestPointEquality:
    """Point equality tests."""
    
    @pytest.fixture
    def test_curve(self):
        """Create test curve."""
        p = 1063
        a = 4
        b = 20
        return FpCurve(p, a, b)
    
    @pytest.fixture
    def test_points(self, test_curve):
        """Create test points."""
        P1 = test_curve.validate_point(1, 5)
        P2 = test_curve.validate_point(4, 10)
        return P1, P2
    
    def test_should_handle_point_self_equality(self, test_points):
        """Should handle point self equality."""
        P1, _ = test_points
        assert P1 == P1
    
    def test_should_handle_different_points_inequality(self, test_points):
        """Should handle different points inequality."""
        P1, P2 = test_points
        assert P1 != P2
    
    def test_should_handle_normalized_equality(self, test_points):
        """Should handle normalized equality."""
        P1, _ = test_points
        # Add and normalize should still equal
        result = P1.add(P1.curve.get_infinity())
        assert result.normalize() == P1.normalize()


class TestInfinityPoint:
    """Infinity point tests."""
    
    @pytest.fixture
    def test_curve(self):
        """Create test curve."""
        p = 1063
        a = 4
        b = 20
        return FpCurve(p, a, b)
    
    def test_should_handle_infinity_plus_infinity(self, test_curve):
        """Should handle infinity + infinity = infinity."""
        inf = test_curve.get_infinity()
        result = inf.add(inf)
        assert result.is_infinity
    
    def test_should_handle_infinity_twice(self, test_curve):
        """Should handle 2 * infinity = infinity."""
        inf = test_curve.get_infinity()
        result = inf.twice()
        assert result.is_infinity
    
    def test_should_handle_infinity_negate(self, test_curve):
        """Should handle -infinity = infinity."""
        inf = test_curve.get_infinity()
        result = inf.negate()
        assert result.is_infinity
    
    def test_should_handle_infinity_multiply(self, test_curve):
        """Should handle k * infinity = infinity."""
        inf = test_curve.get_infinity()
        for k in [0, 1, 5, -3]:
            result = inf.multiply(k)
            assert result.is_infinity
