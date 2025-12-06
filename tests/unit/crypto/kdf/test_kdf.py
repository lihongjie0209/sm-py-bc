import pytest
from sm_bc.crypto.kdf.kdf import KDF
from sm_bc.crypto.digests.sm3_digest import SM3Digest
from sm_bc.util.arrays import Arrays

class TestKDF:
    def test_derive_key_sm3(self):
        sm3_digest = SM3Digest()
        seed = b"test_seed"
        key_length = 64  # Two SM3 blocks worth of key material

        derived_key = KDF.derive_key(sm3_digest, seed, key_length)
        
        assert len(derived_key) == key_length
        
        # Manually compute expected output for comparison
        # Block 1: H(seed || 0x00000001)
        sm3_digest.reset()
        sm3_digest.update_bytes(seed, 0, len(seed))
        sm3_digest.update_bytes(b'\x00\x00\x00\x01', 0, 4)
        hash1 = bytearray(32)
        sm3_digest.do_final(hash1, 0)
        
        # Block 2: H(seed || 0x00000002)
        sm3_digest.reset()
        sm3_digest.update_bytes(seed, 0, len(seed))
        sm3_digest.update_bytes(b'\x00\x00\x00\x02', 0, 4)
        hash2 = bytearray(32)
        sm3_digest.do_final(hash2, 0)
        
        expected_key = hash1 + hash2
        
        assert Arrays.constant_time_are_equal(derived_key, expected_key)
        
    def test_derive_key_partial_last_block(self):
        sm3_digest = SM3Digest()
        seed = b"short_seed"
        key_length = 40 # 1 full block + 8 bytes from second block
        
        derived_key = KDF.derive_key(sm3_digest, seed, key_length)
        assert len(derived_key) == key_length
        
        # Manually compute expected output
        sm3_digest.reset()
        sm3_digest.update_bytes(seed, 0, len(seed))
        sm3_digest.update_bytes(b'\x00\x00\x00\x01', 0, 4)
        hash1 = bytearray(32)
        sm3_digest.do_final(hash1, 0)
        
        sm3_digest.reset()
        sm3_digest.update_bytes(seed, 0, len(seed))
        sm3_digest.update_bytes(b'\x00\x00\x00\x02', 0, 4)
        hash2 = bytearray(32)
        sm3_digest.do_final(hash2, 0)
        
        expected_key = hash1 + hash2[0:8] # First 8 bytes of second hash
        
        assert Arrays.constant_time_are_equal(derived_key, expected_key)

    def test_derive_key_zero_length(self):
        sm3_digest = SM3Digest()
        seed = b"any_seed"
        key_length = 0
        
        derived_key = KDF.derive_key(sm3_digest, seed, key_length)
        assert len(derived_key) == 0
        assert derived_key == bytearray()

    def test_derive_key_single_block_exact(self):
        sm3_digest = SM3Digest()
        seed = b"single_block_seed"
        key_length = 32
        
        derived_key = KDF.derive_key(sm3_digest, seed, key_length)
        assert len(derived_key) == key_length
        
        sm3_digest.reset()
        sm3_digest.update_bytes(seed, 0, len(seed))
        sm3_digest.update_bytes(b'\x00\x00\x00\x01', 0, 4)
        hash1 = bytearray(32)
        sm3_digest.do_final(hash1, 0)
        
        assert Arrays.constant_time_are_equal(derived_key, hash1)

