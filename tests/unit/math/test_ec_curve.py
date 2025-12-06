import pytest
from sm_bc.math.ec_curve import Fp as FpCurve
from sm_bc.math.ec_point import Fp as FpPoint

class TestECCurve:
    def setup_method(self):
        # Simple curve y^2 = x^3 + ax + b over Fp
        # p = 17, a = 2, b = 2
        # y^2 = x^3 + 2x + 2
        # (5, 1) is a point: 1^2 = 1. 5^3 + 2*5 + 2 = 125 + 10 + 2 = 137 = 1 mod 17.
        self.q = 17
        self.a = 2
        self.b = 2
        self.curve = FpCurve(self.q, self.a, self.b)

    def test_create_point(self):
        p = self.curve.create_point(5, 1)
        assert not p.is_infinity
        assert p.x.to_big_integer() == 5
        assert p.y.to_big_integer() == 1
        assert p.is_valid()

    def test_point_addition(self):
        p1 = self.curve.create_point(5, 1)
        # ... (comments) ...
        
        p2 = p1.twice().normalize()
        assert p2.x.to_big_integer() == 6
        assert p2.y.to_big_integer() == 3
        
        p3 = p1.add(p1).normalize()
        assert p3.x.to_big_integer() == 6
        assert p3.y.to_big_integer() == 3

    def test_multiply(self):
        p = self.curve.create_point(5, 1)
        # ... (comments) ...
        
        p3 = p.multiply(3).normalize()
        assert p3.x.to_big_integer() == 10
        assert p3.y.to_big_integer() == 6

    def test_encode_decode_uncompressed(self):
        p = self.curve.create_point(5, 1)
        encoded = p.get_encoded(False)
        # 04 + x (5) + y (1). Field size roughly 1 byte (17 < 256).
        # q=17 -> 5 bits. (5+7)//8 = 1 byte.
        # Expected: 04 05 01
        assert encoded == b'\x04\x05\x01'
        
        decoded = self.curve.decode_point(encoded)
        assert decoded == p

    def test_encode_decode_compressed(self):
        p = self.curve.create_point(5, 1)
        encoded = p.get_encoded(True)
        # y=1 (odd) -> 03
        # Expected: 03 05
        assert encoded == b'\x03\x05'
        
        decoded = self.curve.decode_point(encoded)
        assert decoded == p
        
        # Test even y
        p2 = self.curve.create_point(6, 3) # 3 is odd? wait.
        # 3 is odd. Let's find an even y point.
        # (0, y): y^2 = 2. No.
        # (3, y): 27 + 6 + 2 = 35 = 1. y=1, 16. 16 is even.
        p3 = self.curve.create_point(3, 16)
        encoded3 = p3.get_encoded(True)
        # 02 03
        assert encoded3 == b'\x02\x03'
        
        decoded3 = self.curve.decode_point(encoded3)
        assert decoded3 == p3
