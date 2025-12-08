"""
Tests for HMAC (Hash-based Message Authentication Code) implementation.

Reference:
- RFC 2104 test vectors
- org.bouncycastle.crypto.test.HMacTest (Bouncy Castle Java)
"""

import pytest
from sm_bc.crypto.digests.sm3_digest import SM3Digest
from sm_bc.crypto.macs.hmac import HMac
from sm_bc.crypto.params.key_parameter import KeyParameter
from sm_bc.exceptions import DataLengthException


class TestHMac:
    """Test cases for HMac implementation."""
    
    def test_algorithm_name(self):
        """Test that algorithm name is correct."""
        hmac = HMac(SM3Digest())
        assert hmac.get_algorithm_name() == "HMac/SM3"
    
    def test_mac_size(self):
        """Test that MAC size matches the underlying digest size."""
        hmac = HMac(SM3Digest())
        assert hmac.get_mac_size() == 32  # SM3 produces 32 bytes
    
    def test_simple_hmac(self):
        """Test basic HMAC operation with SM3."""
        hmac = HMac(SM3Digest())
        key = b"key"
        message = b"The quick brown fox jumps over the lazy dog"
        
        hmac.init(KeyParameter(key))
        hmac.update_bytes(message, 0, len(message))
        
        mac = bytearray(hmac.get_mac_size())
        hmac.do_final(mac, 0)
        
        # The result should be consistent and 32 bytes long
        assert len(mac) == 32
        # Verify it's not all zeros
        assert mac != bytearray(32)
    
    def test_hmac_empty_message(self):
        """Test HMAC with empty message."""
        hmac = HMac(SM3Digest())
        key = b"key"
        
        hmac.init(KeyParameter(key))
        
        mac = bytearray(hmac.get_mac_size())
        hmac.do_final(mac, 0)
        
        # Should produce a valid MAC even with empty message
        assert len(mac) == 32
        assert mac != bytearray(32)  # Should not be all zeros
    
    def test_hmac_long_key(self):
        """Test HMAC with key longer than block size."""
        hmac = HMac(SM3Digest())
        # SM3 block size is 64 bytes, use a longer key
        key = b"a" * 100
        message = b"test message"
        
        hmac.init(KeyParameter(key))
        hmac.update_bytes(message, 0, len(message))
        
        mac = bytearray(hmac.get_mac_size())
        hmac.do_final(mac, 0)
        
        assert len(mac) == 32
        # Should hash the key first when it's too long
    
    def test_hmac_multiple_updates(self):
        """Test that multiple update calls produce same result as single update."""
        hmac1 = HMac(SM3Digest())
        hmac2 = HMac(SM3Digest())
        key = b"test-key"
        message = b"abcdefghijklmnop"
        
        # Single update
        hmac1.init(KeyParameter(key))
        hmac1.update_bytes(message, 0, len(message))
        mac1 = bytearray(hmac1.get_mac_size())
        hmac1.do_final(mac1, 0)
        
        # Multiple updates
        hmac2.init(KeyParameter(key))
        hmac2.update_bytes(message, 0, 8)
        hmac2.update_bytes(message, 8, 8)
        mac2 = bytearray(hmac2.get_mac_size())
        hmac2.do_final(mac2, 0)
        
        assert mac1 == mac2
    
    def test_hmac_single_byte_update(self):
        """Test update with single bytes."""
        hmac = HMac(SM3Digest())
        key = b"key"
        message = b"abc"
        
        hmac.init(KeyParameter(key))
        for byte in message:
            hmac.update(byte)
        
        mac = bytearray(hmac.get_mac_size())
        hmac.do_final(mac, 0)
        
        assert len(mac) == 32
    
    def test_hmac_reset(self):
        """Test that reset allows reusing the MAC with same key."""
        hmac = HMac(SM3Digest())
        key = b"test-key"
        message1 = b"first message"
        message2 = b"second message"
        
        # First computation
        hmac.init(KeyParameter(key))
        hmac.update_bytes(message1, 0, len(message1))
        mac1 = bytearray(hmac.get_mac_size())
        hmac.do_final(mac1, 0)
        
        # After do_final, should be reset automatically
        # Compute MAC for different message
        hmac.update_bytes(message2, 0, len(message2))
        mac2 = bytearray(hmac.get_mac_size())
        hmac.do_final(mac2, 0)
        
        # MACs should be different
        assert mac1 != mac2
        
        # Manual reset
        hmac.reset()
        hmac.update_bytes(message1, 0, len(message1))
        mac3 = bytearray(hmac.get_mac_size())
        hmac.do_final(mac3, 0)
        
        # Should match first computation
        assert mac1 == mac3
    
    def test_hmac_output_buffer_too_small(self):
        """Test that DataLengthException is raised when output buffer is too small."""
        hmac = HMac(SM3Digest())
        key = b"key"
        message = b"test"
        
        hmac.init(KeyParameter(key))
        hmac.update_bytes(message, 0, len(message))
        
        # Buffer too small
        mac = bytearray(10)  # Need 32 bytes
        with pytest.raises(DataLengthException):
            hmac.do_final(mac, 0)
    
    def test_hmac_invalid_param_type(self):
        """Test that ValueError is raised when params is not KeyParameter."""
        hmac = HMac(SM3Digest())
        
        with pytest.raises(ValueError, match="HMac requires KeyParameter"):
            hmac.init(None)  # type: ignore
    
    def test_hmac_different_keys_different_macs(self):
        """Test that different keys produce different MACs."""
        message = b"test message"
        
        hmac1 = HMac(SM3Digest())
        hmac1.init(KeyParameter(b"key1"))
        hmac1.update_bytes(message, 0, len(message))
        mac1 = bytearray(hmac1.get_mac_size())
        hmac1.do_final(mac1, 0)
        
        hmac2 = HMac(SM3Digest())
        hmac2.init(KeyParameter(b"key2"))
        hmac2.update_bytes(message, 0, len(message))
        mac2 = bytearray(hmac2.get_mac_size())
        hmac2.do_final(mac2, 0)
        
        assert mac1 != mac2
    
    def test_hmac_consistency(self):
        """Test that same key and message always produce same MAC."""
        key = b"consistent-key"
        message = b"consistent-message"
        
        macs = []
        for _ in range(3):
            hmac = HMac(SM3Digest())
            hmac.init(KeyParameter(key))
            hmac.update_bytes(message, 0, len(message))
            mac = bytearray(hmac.get_mac_size())
            hmac.do_final(mac, 0)
            macs.append(bytes(mac))
        
        # All MACs should be identical
        assert macs[0] == macs[1] == macs[2]
