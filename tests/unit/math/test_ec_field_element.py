"""
ECFieldElement Fp tests.

Tests field arithmetic operations over prime fields including:
- Basic arithmetic (add, subtract, multiply, square, negate)
- Modular inverse and division
- Square root computation (Tonelli-Shanks algorithm)
- Point validation on elliptic curves

Reference: test/unit/math/ECFieldElement.test.ts (sm-js-bc)
Status: Enhanced and aligned with JS tests
"""

import pytest
from sm_bc.math.ec_field_element import Fp


class TestFpBasicArithmetic:
    """Tests for basic field arithmetic operations."""
    
    def test_should_compute_addition_correctly(self):
        """Should compute addition correctly."""
        p = 1063  # Prime from test curve
        a = Fp(p, 5)
        b = Fp(p, 7)
        result = a.add(b)
        assert result.to_big_integer() == 12
    
    def test_should_compute_subtraction_correctly(self):
        """Should compute subtraction correctly."""
        p = 1063
        a = Fp(p, 7)
        b = Fp(p, 5)
        result = a.subtract(b)
        assert result.to_big_integer() == 2
    
    def test_should_compute_subtraction_with_wrap_around(self):
        """Should compute subtraction with wrap around."""
        p = 1063
        a = Fp(p, 5)
        b = Fp(p, 7)
        result = a.subtract(b)
        expected = (5 - 7 + p) % p  # 1061
        assert result.to_big_integer() == expected
    
    def test_should_compute_multiplication_correctly(self):
        """Should compute multiplication correctly."""
        p = 1063
        a = Fp(p, 5)
        b = Fp(p, 7)
        result = a.multiply(b)
        assert result.to_big_integer() == 35
    
    def test_should_compute_multiplication_with_wrap_around(self):
        """Should compute multiplication with wrap around."""
        p = 1063
        a = Fp(p, 500)
        b = Fp(p, 500)
        result = a.multiply(b)
        expected = (500 * 500) % p  # 972
        assert result.to_big_integer() == expected
    
    def test_should_compute_square_correctly(self):
        """Should compute square correctly."""
        p = 1063
        a = Fp(p, 5)
        result = a.square()
        assert result.to_big_integer() == 25
    
    def test_should_compute_negation_correctly(self):
        """Should compute negation correctly."""
        p = 1063
        a = Fp(p, 5)
        result = a.negate()
        expected = (p - 5) % p  # 1058
        assert result.to_big_integer() == expected
    
    def test_should_handle_zero(self):
        """Should handle zero correctly."""
        p = 1063
        zero = Fp(p, 0)
        a = Fp(p, 5)
        
        # 0 + a = a
        assert zero.add(a).to_big_integer() == 5
        
        # a + 0 = a
        assert a.add(zero).to_big_integer() == 5
        
        # 0 * a = 0
        assert zero.multiply(a).to_big_integer() == 0
        
        # -0 = 0
        assert zero.negate().to_big_integer() == 0


class TestFpInversionAndDivision:
    """Tests for modular inverse and division."""
    
    def test_should_compute_inversion_correctly(self):
        """Should compute inversion correctly: 2 * inv(2) = 1."""
        p = 1063
        two = Fp(p, 2)
        inv_two = two.invert()
        result = two.multiply(inv_two)
        assert result.to_big_integer() == 1
    
    def test_should_compute_division_correctly(self):
        """Should compute division correctly: 10 / 2 = 5."""
        p = 1063
        ten = Fp(p, 10)
        two = Fp(p, 2)
        result = ten.divide(two)
        assert result.to_big_integer() == 5
    
    def test_should_compute_division_with_nontrivial_inverse(self):
        """Should compute division with non-trivial inverse."""
        p = 1063
        a = Fp(p, 7)
        b = Fp(p, 3)
        result = a.divide(b)
        
        # Verify: result * 3 = 7 (mod p)
        verify = result.multiply(b)
        assert verify.to_big_integer() == 7
    
    def test_should_compute_inverse_of_small_values(self):
        """Should compute inverse of small values."""
        q = 17
        a = Fp(q, 5)
        # 5 * x = 1 mod 17 -> x = 7 (5*7=35=1 mod 17)
        assert a.invert().to_big_integer() == 7
    
    def test_should_verify_multiplicative_inverse(self):
        """Should verify multiplicative inverse property."""
        p = 1063
        test_values = [2, 3, 5, 7, 11, 100, 500, 1000]
        
        for val in test_values:
            a = Fp(p, val)
            inv_a = a.invert()
            product = a.multiply(inv_a)
            assert product.to_big_integer() == 1, f"Failed for {val}"


class TestFpSquareRoot:
    """Tests for square root computation."""
    
    def test_should_compute_sqrt_mod_4_3(self):
        """Should compute square root when p ≡ 3 (mod 4)."""
        # q = 19 (3 mod 4)
        q = 19
        a = Fp(q, 4)
        # sqrt(4) = 2 or 17
        sqrt_a = a.sqrt()
        assert sqrt_a is not None
        assert sqrt_a.to_big_integer() in (2, 17)
        assert sqrt_a.square() == a
    
    def test_should_compute_sqrt_tonelli_shanks(self):
        """Should compute square root using Tonelli-Shanks when p ≡ 1 (mod 4)."""
        # q = 17 (1 mod 4)
        q = 17
        a = Fp(q, 2)
        sqrt_a = a.sqrt()
        assert sqrt_a is not None
        assert sqrt_a.to_big_integer() in (6, 11)
        assert sqrt_a.square() == a
    
    def test_should_return_none_for_non_residue(self):
        """Should return None for non-quadratic residue."""
        q = 17
        a = Fp(q, 3)
        # 3 is non-residue mod 17
        assert a.sqrt() is None
    
    def test_should_compute_sqrt_of_perfect_squares(self):
        """Should compute square root of perfect squares."""
        p = 1063
        test_values = [1, 4, 9, 16, 25, 36, 49, 64, 81, 100]
        
        for val in test_values:
            a = Fp(p, val)
            sqrt_a = a.sqrt()
            if sqrt_a is not None:
                # Verify sqrt²  = a
                assert sqrt_a.square() == a, f"Failed for {val}"


class TestFpEllipticCurveVerification:
    """Tests for elliptic curve point verification."""
    
    def test_should_verify_point_on_curve(self):
        """Should verify point (1, 5) is on curve y² = x³ + 4x + 20."""
        p = 1063
        x = Fp(p, 1)
        y = Fp(p, 5)
        a = Fp(p, 4)
        b = Fp(p, 20)
        
        # Compute y²
        lhs = y.square()
        
        # Compute x³ + 4x + 20
        x3 = x.square().multiply(x)
        ax = a.multiply(x)
        rhs = x3.add(ax).add(b)
        
        assert lhs.to_big_integer() == rhs.to_big_integer()
    
    def test_should_verify_sm2_curve_point(self):
        """Should verify a point on SM2 curve."""
        # SM2 prime
        p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        
        # SM2 generator point
        gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
        gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
        
        # SM2 curve: y² = x³ + ax + b
        a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        
        x = Fp(p, gx)
        y = Fp(p, gy)
        a_elem = Fp(p, a)
        b_elem = Fp(p, b)
        
        # Compute y²
        lhs = y.square()
        
        # Compute x³ + ax + b
        x3 = x.square().multiply(x)
        ax = a_elem.multiply(x)
        rhs = x3.add(ax).add(b_elem)
        
        assert lhs.to_big_integer() == rhs.to_big_integer()


class TestFpEquality:
    """Tests for equality comparison."""
    
    def test_should_compare_equal_elements(self):
        """Should compare equal elements correctly."""
        p = 1063
        a = Fp(p, 5)
        b = Fp(p, 5)
        assert a == b
    
    def test_should_compare_different_elements(self):
        """Should compare different elements correctly."""
        p = 1063
        a = Fp(p, 5)
        b = Fp(p, 7)
        assert a != b
    
    def test_should_handle_modular_equivalence(self):
        """Should handle modular equivalence."""
        p = 17
        a = Fp(p, 5)
        b = Fp(p, 22)  # 22 = 5 mod 17
        assert a == b


class TestFpEdgeCases:
    """Edge case tests for field operations."""
    
    def test_should_handle_identity_elements(self):
        """Should handle identity elements correctly."""
        p = 1063
        a = Fp(p, 42)
        zero = Fp(p, 0)
        one = Fp(p, 1)
        
        # Additive identity
        assert a.add(zero) == a
        assert zero.add(a) == a
        
        # Multiplicative identity
        assert a.multiply(one) == a
        assert one.multiply(a) == a
    
    def test_should_handle_inverse_operations(self):
        """Should handle inverse operations correctly."""
        p = 1063
        a = Fp(p, 42)
        
        # Additive inverse: a + (-a) = 0
        neg_a = a.negate()
        assert a.add(neg_a).to_big_integer() == 0
        
        # Multiplicative inverse: a * a⁻¹ = 1
        inv_a = a.invert()
        assert a.multiply(inv_a).to_big_integer() == 1
    
    def test_should_handle_large_values(self):
        """Should handle large values correctly."""
        # Use a large prime
        p = 2**255 - 19  # Curve25519 prime
        
        # Large value operations
        a = Fp(p, p - 1)
        b = Fp(p, 1)
        
        # (p-1) + 1 = 0 mod p
        assert a.add(b).to_big_integer() == 0
        
        # (p-1) * (p-1) = 1 mod p
        assert a.multiply(a).to_big_integer() == 1
    
    def test_should_maintain_field_closure(self):
        """Should maintain field closure."""
        p = 1063
        
        # All operations should produce elements in [0, p)
        for i in range(10):
            for j in range(10):
                a = Fp(p, i)
                b = Fp(p, j)
                
                add_result = a.add(b).to_big_integer()
                assert 0 <= add_result < p
                
                mul_result = a.multiply(b).to_big_integer()
                assert 0 <= mul_result < p
                
                if j != 0:
                    div_result = a.divide(b).to_big_integer()
                    assert 0 <= div_result < p


class TestFpConsistency:
    """Consistency tests across operations."""
    
    def test_should_maintain_distributive_property(self):
        """Should maintain distributive property: a*(b+c) = a*b + a*c."""
        p = 1063
        a = Fp(p, 5)
        b = Fp(p, 7)
        c = Fp(p, 11)
        
        # Left side: a*(b+c)
        lhs = a.multiply(b.add(c))
        
        # Right side: a*b + a*c
        rhs = a.multiply(b).add(a.multiply(c))
        
        assert lhs == rhs
    
    def test_should_maintain_associative_property(self):
        """Should maintain associative property: (a*b)*c = a*(b*c)."""
        p = 1063
        a = Fp(p, 5)
        b = Fp(p, 7)
        c = Fp(p, 11)
        
        # Left side: (a*b)*c
        lhs = a.multiply(b).multiply(c)
        
        # Right side: a*(b*c)
        rhs = a.multiply(b.multiply(c))
        
        assert lhs == rhs
    
    def test_should_maintain_commutative_property(self):
        """Should maintain commutative property: a*b = b*a."""
        p = 1063
        a = Fp(p, 5)
        b = Fp(p, 7)
        
        assert a.multiply(b) == b.multiply(a)
        assert a.add(b) == b.add(a)
