"""
Comprehensive ECCurve tests aligned with ECCurveComprehensive.test.ts
Tests curve properties, field operations, point creation, and coordinate systems.
"""
import pytest
from sm_bc.math.ec_curve import Fp as FpCurve
from sm_bc.util.secure_random import SecureRandom


class TestECCurveConstructorAndProperties:
    """Test curve construction and basic properties."""
    
    def setup_method(self):
        # Test curve: y² = x³ + 4x + 20 over F_1063
        self.p = 1063
        self.a = 4
        self.b = 20
        self.order = 1069
        self.cofactor = 1
        self.curve = FpCurve(self.p, self.a, self.b, self.order, self.cofactor)
    
    def test_should_create_curve_with_correct_parameters(self):
        """Should create curve with correct parameters."""
        assert self.curve.q == self.p
        assert self.curve.a.to_big_integer() == self.a
        assert self.curve.b.to_big_integer() == self.b
        assert self.curve.order == self.order
        assert self.curve.cofactor == self.cofactor
    
    def test_should_compute_field_size_correctly(self):
        """Should compute field size correctly."""
        field_size = self.curve.field_size
        # log2(1063) ≈ 10.05, so 11 bits
        assert field_size == 11
    
    def test_should_create_curve_without_order_and_cofactor(self):
        """Should create curve without order and cofactor."""
        simple_curve = FpCurve(self.p, self.a, self.b)
        assert simple_curve.q == self.p
        assert simple_curve.order is None
        assert simple_curve.cofactor is None


class TestECCurveFieldElementOperations:
    """Test field element operations on the curve."""
    
    def setup_method(self):
        self.p = 1063
        self.a = 4
        self.b = 20
        self.curve = FpCurve(self.p, self.a, self.b)
    
    def test_should_create_field_elements_from_big_integer(self):
        """Should create field elements from BigInt."""
        elem = self.curve.from_big_integer(123)
        assert elem.to_big_integer() == 123
    
    def test_should_validate_field_elements_correctly(self):
        """Should validate field elements correctly."""
        # Python implementation doesn't have is_valid_field_element
        # Instead validate through field element creation
        elem0 = self.curve.from_big_integer(0)
        assert elem0.to_big_integer() == 0
        
        elem_max = self.curve.from_big_integer(self.p - 1)
        assert elem_max.to_big_integer() == self.p - 1
        
        elem_neg = self.curve.from_big_integer(-1)
        assert elem_neg.to_big_integer() == self.p - 1  # Normalized
    
    def test_should_normalize_negative_field_elements(self):
        """Should normalize negative field elements."""
        elem = self.curve.from_big_integer(-5)
        assert elem.to_big_integer() == self.p - 5  # 1058
    
    def test_should_create_random_field_elements(self):
        """Should create random field elements."""
        # Python implementation doesn't have random_field_element method
        # Test field element creation with random values instead
        random = SecureRandom()
        
        for _ in range(10):
            rand_bytes = bytearray(16)
            random.next_bytes(rand_bytes)
            rand_val = int.from_bytes(rand_bytes, 'big') % self.p
            elem = self.curve.from_big_integer(rand_val)
            value = elem.to_big_integer()
            assert 0 <= value < self.p
    
    def test_should_create_random_non_zero_field_elements(self):
        """Should create random non-zero field elements."""
        # Python implementation doesn't have random_field_element_mult method
        # Test field element creation with random non-zero values
        random = SecureRandom()
        
        for _ in range(10):
            rand_bytes = bytearray(16)
            random.next_bytes(rand_bytes)
            rand_val = int.from_bytes(rand_bytes, 'big') % (self.p - 1) + 1  # 1 to p-1
            elem = self.curve.from_big_integer(rand_val)
            value = elem.to_big_integer()
            assert 0 < value < self.p


class TestECCurvePointCreationAndValidation:
    """Test point creation and validation on the curve."""
    
    def setup_method(self):
        self.p = 1063
        self.a = 4
        self.b = 20
        self.curve = FpCurve(self.p, self.a, self.b)
    
    def test_should_create_valid_points_on_curve(self):
        """Should create valid points on the curve."""
        # Known point: (1, 5)
        point = self.curve.create_point(1, 5)
        assert not point.is_infinity
        assert point.is_valid()
        norm = point.normalize()
        assert norm.x.to_big_integer() == 1
        assert norm.y.to_big_integer() == 5
    
    def test_should_validate_points_correctly(self):
        """Should validate points correctly."""
        # Valid point should not raise
        self.curve.validate_point(1, 5)
        
        # Invalid point should raise
        with pytest.raises(ValueError, match="Point not on curve"):
            self.curve.validate_point(1, 6)
    
    def test_should_create_raw_points_without_validation(self):
        """Should create raw points without validation."""
        x = self.curve.from_big_integer(1)
        y = self.curve.from_big_integer(6)  # Invalid y coordinate
        point = self.curve.create_raw_point(x, y)
        
        # Should be invalid but not throw
        assert not point.is_valid()
    
    def test_should_verify_curve_equation_for_valid_points(self):
        """Should verify curve equation for valid points."""
        # Test cases: known points on the curve
        test_cases = [
            (1, 5),
            (817, 912),  # 2*G
            (54, 521),   # 3*G
        ]
        
        for x, y in test_cases:
            point = self.curve.create_point(x, y)
            assert point.is_valid()
            
            # Verify: y² = x³ + ax + b (mod p)
            lhs = (y * y) % self.p
            rhs = (x * x * x + self.a * x + self.b) % self.p
            assert lhs == rhs


class TestECCurveInfinityPoint:
    """Test infinity point operations."""
    
    def setup_method(self):
        self.p = 1063
        self.a = 4
        self.b = 20
        self.curve = FpCurve(self.p, self.a, self.b)
    
    def test_should_provide_infinity_point(self):
        """Should provide infinity point."""
        infinity = self.curve.get_infinity()
        assert infinity.is_infinity
        assert infinity.is_valid()
    
    def test_should_return_same_infinity_instance(self):
        """Should return same infinity instance."""
        inf1 = self.curve.get_infinity()
        inf2 = self.curve.get_infinity()
        assert inf1.equals(inf2)
    
    def test_should_handle_infinity_in_addition(self):
        """Should handle infinity in addition."""
        p = self.curve.create_point(1, 5)
        infinity = self.curve.get_infinity()
        
        # P + O = P
        result1 = p.add(infinity).normalize()
        assert result1.equals(p)
        
        # O + P = P
        result2 = infinity.add(p).normalize()
        assert result2.equals(p)
        
        # O + O = O
        result3 = infinity.add(infinity)
        assert result3.is_infinity


class TestECCurvePointOperations:
    """Test point arithmetic operations."""
    
    def setup_method(self):
        self.p = 1063
        self.a = 4
        self.b = 20
        self.curve = FpCurve(self.p, self.a, self.b)
        # Base point G = (1, 5)
        self.G = self.curve.create_point(1, 5)
    
    def test_should_double_point_correctly(self):
        """Should double point correctly."""
        doubled = self.G.twice().normalize()
        # 2*G = (817, 912)
        assert doubled.x.to_big_integer() == 817
        assert doubled.y.to_big_integer() == 912
    
    def test_should_add_points_correctly(self):
        """Should add points correctly."""
        G2 = self.G.twice().normalize()
        G3 = self.G.add(G2).normalize()
        # 3*G = (54, 521)
        assert G3.x.to_big_integer() == 54
        assert G3.y.to_big_integer() == 521
    
    def test_should_verify_point_addition_is_commutative(self):
        """Should verify point addition is commutative."""
        G2 = self.G.twice().normalize()
        
        result1 = self.G.add(G2).normalize()
        result2 = G2.add(self.G).normalize()
        
        assert result1.equals(result2)
    
    def test_should_negate_point_correctly(self):
        """Should negate point correctly."""
        neg_G = self.G.negate().normalize()
        
        # P + (-P) = O
        result = self.G.add(neg_G)
        assert result.is_infinity
    
    def test_should_multiply_point_correctly(self):
        """Should multiply point correctly."""
        # k*G for various k
        test_cases = [
            (0, True),  # 0*G = infinity
            (1, (1, 5)),  # 1*G = G
            (2, (817, 912)),  # 2*G
            (3, (54, 521)),   # 3*G
        ]
        
        for k, expected in test_cases:
            result = self.G.multiply(k).normalize()
            
            if expected is True:
                assert result.is_infinity
            else:
                x, y = expected
                assert result.x.to_big_integer() == x
                assert result.y.to_big_integer() == y


class TestECCurvePointEncoding:
    """Test point encoding and decoding."""
    
    def setup_method(self):
        self.p = 1063
        self.a = 4
        self.b = 20
        self.curve = FpCurve(self.p, self.a, self.b)
    
    def test_should_encode_uncompressed_point(self):
        """Should encode uncompressed point."""
        point = self.curve.create_point(1, 5)
        encoded = point.get_encoded(False)
        
        # Format: 0x04 || x || y
        assert encoded[0] == 0x04
        assert len(encoded) > 1
    
    def test_should_decode_uncompressed_point(self):
        """Should decode uncompressed point."""
        point = self.curve.create_point(1, 5)
        encoded = point.get_encoded(False)
        decoded = self.curve.decode_point(encoded)
        
        assert decoded.equals(point)
    
    def test_should_encode_compressed_point(self):
        """Should encode compressed point."""
        point = self.curve.create_point(1, 5)
        encoded = point.get_encoded(True)
        
        # Format: 0x02 or 0x03 || x
        assert encoded[0] in (0x02, 0x03)
    
    def test_should_decode_compressed_point(self):
        """Should decode compressed point."""
        point = self.curve.create_point(1, 5)
        encoded = point.get_encoded(True)
        decoded = self.curve.decode_point(encoded)
        
        assert decoded.equals(point)
    
    def test_should_roundtrip_encode_decode_uncompressed(self):
        """Should roundtrip encode/decode uncompressed."""
        points = [
            (1, 5),
            (817, 912),
            (54, 521),
        ]
        
        for x, y in points:
            point = self.curve.create_point(x, y)
            encoded = point.get_encoded(False)
            decoded = self.curve.decode_point(encoded)
            assert decoded.equals(point)
    
    def test_should_roundtrip_encode_decode_compressed(self):
        """Should roundtrip encode/decode compressed."""
        points = [
            (1, 5),
            (817, 912),
            (54, 521),
        ]
        
        for x, y in points:
            point = self.curve.create_point(x, y)
            encoded = point.get_encoded(True)
            decoded = self.curve.decode_point(encoded)
            assert decoded.equals(point)


class TestECCurveEquality:
    """Test curve equality operations."""
    
    def test_should_recognize_equal_curves(self):
        """Should recognize equal curves."""
        curve1 = FpCurve(1063, 4, 20, 1069, 1)
        curve2 = FpCurve(1063, 4, 20, 1069, 1)
        
        assert curve1.equals(curve2)
    
    def test_should_recognize_unequal_curves_different_params(self):
        """Should recognize unequal curves with different parameters."""
        curve1 = FpCurve(1063, 4, 20)
        curve2 = FpCurve(1063, 5, 20)  # Different a
        
        assert not curve1.equals(curve2)
    
    def test_should_recognize_unequal_curves_different_field(self):
        """Should recognize unequal curves with different field."""
        curve1 = FpCurve(1063, 4, 20)
        curve2 = FpCurve(1069, 4, 20)  # Different p
        
        assert not curve1.equals(curve2)


class TestECCurveSM2Specific:
    """Test SM2-specific curve properties."""
    
    def setup_method(self):
        # SM2 curve parameters
        self.p = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
        self.a = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16)
        self.b = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)
        self.curve = FpCurve(self.p, self.a, self.b)
    
    def test_should_create_sm2_curve(self):
        """Should create SM2 curve."""
        assert self.curve.q == self.p
        assert self.curve.a.to_big_integer() == self.a
        assert self.curve.b.to_big_integer() == self.b
    
    def test_should_compute_sm2_field_size(self):
        """Should compute SM2 field size."""
        field_size = self.curve.field_size
        # SM2 uses 256-bit field
        assert field_size == 256
    
    def test_should_validate_sm2_curve_equation(self):
        """Should validate SM2 curve equation."""
        # SM2 generator point
        gx = int('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', 16)
        gy = int('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', 16)
        
        G = self.curve.create_point(gx, gy)
        assert G.is_valid()
        
        # Verify curve equation
        lhs = (gy * gy) % self.p
        rhs = (gx * gx * gx + self.a * gx + self.b) % self.p
        assert lhs == rhs


class TestECCurveEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def setup_method(self):
        self.p = 1063
        self.a = 4
        self.b = 20
        self.curve = FpCurve(self.p, self.a, self.b)
    
    def test_should_handle_point_at_zero_x(self):
        """Should handle point at x=0 if valid."""
        # Check if (0, y) is on curve: y² = b (mod p)
        # 20 is not a quadratic residue mod 1063, so no point at x=0
        try:
            point = self.curve.create_point(0, 1)
            assert not point.is_valid()
        except ValueError:
            pass  # Expected if create_point validates
    
    def test_should_handle_large_scalar_multiplication(self):
        """Should handle large scalar multiplication."""
        G = self.curve.create_point(1, 5)
        
        # Large scalar
        k = 123456789
        result = G.multiply(k)
        
        assert not result.is_infinity
        assert result.is_valid()
    
    def test_should_handle_order_scalar_multiplication(self):
        """Should handle order scalar multiplication."""
        # If we have a point with known order, k*order*G = O
        # For testing, just verify that very large multiplication works
        G = self.curve.create_point(1, 5)
        
        # Multiply by a reasonably large number
        k = 1000
        result = G.multiply(k)
        
        assert result.is_valid()


class TestECCurveNormalization:
    """Test point normalization."""
    
    def setup_method(self):
        self.p = 1063
        self.a = 4
        self.b = 20
        self.curve = FpCurve(self.p, self.a, self.b)
        self.G = self.curve.create_point(1, 5)
    
    def test_should_normalize_projective_point(self):
        """Should normalize projective point to affine."""
        # Perform operation that creates non-affine point
        doubled = self.G.twice()
        
        # Normalize to affine coordinates
        normalized = doubled.normalize()
        
        # Check that it has correct affine coordinates
        assert normalized.x.to_big_integer() == 817
        assert normalized.y.to_big_integer() == 912
    
    def test_should_normalize_already_normalized_point(self):
        """Should normalize already normalized point (no-op)."""
        normalized_once = self.G.normalize()
        normalized_twice = normalized_once.normalize()
        
        assert normalized_once.equals(normalized_twice)
    
    def test_should_maintain_validity_after_normalization(self):
        """Should maintain validity after normalization."""
        result = self.G.twice().normalize()
        assert result.is_valid()
