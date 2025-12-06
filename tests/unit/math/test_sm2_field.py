import pytest
from sm_bc.math.ec_field_element import Fp

# SM2 P
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF

class TestSM2Field:
    def test_arithmetic(self):
        a = Fp(P, 100)
        b = Fp(P, 200)
        assert a.add(b).to_big_integer() == 300
        assert a.multiply(b).to_big_integer() == 20000
        
        # Inverse
        inv_a = a.invert()
        assert a.multiply(inv_a).to_big_integer() == 1
        
        # Square
        assert a.square().to_big_integer() == 10000
        
        # Negate
        neg_a = a.negate()
        assert a.add(neg_a).to_big_integer() == 0
        
        # Large number
        large = Fp(P, P - 1)
        assert large.add(Fp(P, 1)).to_big_integer() == 0
        
    def test_sqrt(self):
        # P % 4 = 3. Fast sqrt should work.
        assert P % 4 == 3
        
        val = Fp(P, 4)
        sqrt_val = val.sqrt()
        assert sqrt_val is not None
        assert sqrt_val.to_big_integer() in [2, P-2]
        assert sqrt_val.square() == val
