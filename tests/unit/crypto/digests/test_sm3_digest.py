import pytest
from sm_bc.crypto.digests.sm3_digest import SM3Digest

class TestSM3Digest:
    def test_empty_string(self):
        digest = SM3Digest()
        output = bytearray(32)
        digest.do_final(output, 0)
        expected = "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
        assert output.hex() == expected

    def test_abc(self):
        digest = SM3Digest()
        data = b"abc"
        digest.update_bytes(data, 0, len(data))
        output = bytearray(32)
        digest.do_final(output, 0)
        expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        assert output.hex() == expected

    def test_long_string(self):
        # 64 characters "abcd..."
        input_str = "abcd" * 16
        data = input_str.encode('ascii')
        digest = SM3Digest()
        digest.update_bytes(data, 0, len(data))
        output = bytearray(32)
        digest.do_final(output, 0)
        expected = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
        assert output.hex() == expected

    def test_multiple_updates(self):
        digest = SM3Digest()
        digest.update_bytes(b"a", 0, 1)
        digest.update_bytes(b"b", 0, 1)
        digest.update_bytes(b"c", 0, 1)
        output = bytearray(32)
        digest.do_final(output, 0)
        expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        assert output.hex() == expected

    def test_reset(self):
        digest = SM3Digest()
        digest.update_bytes(b"abc", 0, 3)
        output1 = bytearray(32)
        digest.do_final(output1, 0)
        
        # Should auto-reset, but we can also manually reset
        digest.reset()
        digest.update_bytes(b"abc", 0, 3)
        output2 = bytearray(32)
        digest.do_final(output2, 0)
        
        assert output1 == output2

    def test_copy(self):
        digest1 = SM3Digest()
        digest1.update_bytes(b"a", 0, 1)
        
        digest2 = digest1.copy()
        
        digest1.update_bytes(b"bc", 0, 2)
        output1 = bytearray(32)
        digest1.do_final(output1, 0)
        
        digest2.update_bytes(b"bc", 0, 2)
        output2 = bytearray(32)
        digest2.do_final(output2, 0)
        
        assert output1 == output2
