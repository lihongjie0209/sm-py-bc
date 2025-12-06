
import time
from sm_bc.math.ec_curve import Fp as FpCurve
from sm_bc.crypto.params.ec_domain_parameters import ECDomainParameters
from sm_bc.math.ec_point import Fp as FpPoint

# SM2 Standard Parameters
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

def test_perf():
    curve = FpCurve(P, A, B, N, 1)
    g = curve.create_point(GX, GY)
    
    # Random scalar ~ 256 bits
    k = 0x1234567812345678123456781234567812345678123456781234567812345678
    
    start = time.time()
    res = g.multiply(k)
    end = time.time()
    print(f"Multiply time: {end - start:.4f}s")

if __name__ == "__main__":
    test_perf()
