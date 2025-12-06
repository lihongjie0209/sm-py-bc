import pytest
from sm_bc.crypto.signers.dsa_encoding import StandardDSAEncoding

class TestStandardDSAEncoding:
    def setup_method(self):
        self.encoder = StandardDSAEncoding()

    def test_encode_decode_simple(self):
        r = 12345
        s = 67890
        encoded = self.encoder.encode(0, r, s)
        
        # Manual check of DER
        # r=12345 (0x3039). 2 bytes.
        # s=67890 (0x10932). 3 bytes (needs 0x00 padding? no, 1 is positive). 
        # Wait 0x10932. 17 bits.
        # (17+1+7)//8 = 3 bytes. 0x01 0x09 0x32. MSB is 0.
        
        decoded_r, decoded_s = self.encoder.decode(0, encoded)
        assert decoded_r == r
        assert decoded_s == s

    def test_encode_decode_negative_handling_internal(self):
        # DSA r, s are usually positive integers.
        # But we test large numbers that might look negative if unsigned
        r = 0x80000000
        # bit length 32. (32+1+7)//8 = 5 bytes. Should prepend 00.
        
        encoded = self.encoder.encode(0, r, r)
        decoded_r, decoded_s = self.encoder.decode(0, encoded)
        assert decoded_r == r
        assert decoded_s == r

    def test_zero(self):
        encoded = self.encoder.encode(0, 0, 0)
        decoded_r, decoded_s = self.encoder.decode(0, encoded)
        assert decoded_r == 0
        assert decoded_s == 0
