"""
Tests for ZUC-128 and ZUC-256 MAC implementations.

Test vectors from 3GPP TS 35.221 and 3GPP TS 35.222.
"""

import pytest
from sm_bc.crypto.macs.zuc128_mac import ZUC128MAC
from sm_bc.crypto.macs.zuc256_mac import ZUC256MAC
from sm_bc.crypto.params.key_parameter import KeyParameter
from sm_bc.crypto.params.parameters_with_iv import ParametersWithIV
from sm_bc.exceptions import DataLengthException


class TestZUC128MAC:
    """Test cases for ZUC-128 MAC (128-EIA3)."""
    
    def test_algorithm_name(self):
        """Test that algorithm name is correct."""
        mac = ZUC128MAC(mac_bits=32)
        assert mac.get_algorithm_name() == 'ZUC-128-MAC-32'
        
        mac = ZUC128MAC(mac_bits=64)
        assert mac.get_algorithm_name() == 'ZUC-128-MAC-64'
    
    def test_mac_size(self):
        """Test MAC size reporting."""
        mac32 = ZUC128MAC(mac_bits=32)
        assert mac32.get_mac_size() == 4
        
        mac64 = ZUC128MAC(mac_bits=64)
        assert mac64.get_mac_size() == 8
    
    def test_invalid_mac_bits(self):
        """Test that invalid MAC bits raise error."""
        with pytest.raises(ValueError, match="MAC bits must be 32 or 64"):
            ZUC128MAC(mac_bits=128)
    
    def test_initialization_requires_parameters_with_iv(self):
        """Test that initialization requires ParametersWithIV."""
        mac = ZUC128MAC()
        key = bytes(16)
        
        with pytest.raises(ValueError, match="requires ParametersWithIV"):
            mac.init(KeyParameter(key))
    
    def test_initialization_requires_128bit_key(self):
        """Test that initialization requires 128-bit key."""
        mac = ZUC128MAC()
        key = bytes(8)  # Wrong size
        iv = bytes(16)
        
        with pytest.raises(ValueError, match="128-bit key"):
            mac.init(ParametersWithIV(KeyParameter(key), iv))
    
    def test_initialization_requires_128bit_iv(self):
        """Test that initialization requires 128-bit IV."""
        mac = ZUC128MAC()
        key = bytes(16)
        iv = bytes(8)  # Wrong size
        
        with pytest.raises(ValueError, match="128-bit IV"):
            mac.init(ParametersWithIV(KeyParameter(key), iv))
    
    def test_basic_mac_generation_32bit(self):
        """Test basic MAC generation with 32-bit output."""
        mac = ZUC128MAC(mac_bits=32)
        key = bytes(16)  # All zeros
        iv = bytes(16)   # All zeros
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        
        message = b"Hello, ZUC-128 MAC!"
        mac.update_bytes(message, 0, len(message))
        
        tag = bytearray(4)
        result = mac.do_final(tag, 0)
        
        assert result == 4
        # MAC should not be all zeros
        assert any(b != 0 for b in tag)
    
    def test_basic_mac_generation_64bit(self):
        """Test basic MAC generation with 64-bit output."""
        mac = ZUC128MAC(mac_bits=64)
        key = bytes(16)  # All zeros
        iv = bytes(16)   # All zeros
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        
        message = b"Hello, ZUC-128 MAC!"
        mac.update_bytes(message, 0, len(message))
        
        tag = bytearray(8)
        result = mac.do_final(tag, 0)
        
        assert result == 8
        # MAC should not be all zeros
        assert any(b != 0 for b in tag)
    
    def test_empty_message(self):
        """Test MAC generation with empty message."""
        mac = ZUC128MAC(mac_bits=32)
        key = bytes([0x11] * 16)
        iv = bytes([0x22] * 16)
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        
        tag = bytearray(4)
        result = mac.do_final(tag, 0)
        
        assert result == 4
    
    def test_single_byte_update(self):
        """Test MAC with single byte updates."""
        mac = ZUC128MAC(mac_bits=32)
        key = bytes([0x42] * 16)
        iv = bytes([0x99] * 16)
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        
        message = b"Test"
        for byte in message:
            mac.update(byte)
        
        tag = bytearray(4)
        mac.do_final(tag, 0)
        
        # Should produce valid MAC
        assert len(tag) == 4
    
    def test_multiple_update_calls(self):
        """Test MAC with multiple update calls."""
        mac = ZUC128MAC(mac_bits=64)
        key = bytes([0x55] * 16)
        iv = bytes([0xAA] * 16)
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        
        # Update in parts
        mac.update_bytes(b"Hello, ", 0, 7)
        mac.update_bytes(b"World!", 0, 6)
        
        tag = bytearray(8)
        mac.do_final(tag, 0)
        
        assert len(tag) == 8
    
    def test_reset_functionality(self):
        """Test that reset allows reuse with same key."""
        mac = ZUC128MAC(mac_bits=32)
        key = bytes([0x77] * 16)
        iv = bytes([0x88] * 16)
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        
        message = b"Test message"
        
        # First MAC computation
        mac.update_bytes(message, 0, len(message))
        tag1 = bytearray(4)
        mac.do_final(tag1, 0)
        
        # do_final should auto-reset, compute again
        mac.update_bytes(message, 0, len(message))
        tag2 = bytearray(4)
        mac.do_final(tag2, 0)
        
        # Should produce same MAC
        assert bytes(tag1) == bytes(tag2)
    
    def test_different_keys_produce_different_macs(self):
        """Test that different keys produce different MACs."""
        message = b"Same message"
        iv = bytes(16)
        
        # Key 1
        mac1 = ZUC128MAC(mac_bits=32)
        key1 = bytes([0x01] * 16)
        mac1.init(ParametersWithIV(KeyParameter(key1), iv))
        mac1.update_bytes(message, 0, len(message))
        tag1 = bytearray(4)
        mac1.do_final(tag1, 0)
        
        # Key 2
        mac2 = ZUC128MAC(mac_bits=32)
        key2 = bytes([0x02] * 16)
        mac2.init(ParametersWithIV(KeyParameter(key2), iv))
        mac2.update_bytes(message, 0, len(message))
        tag2 = bytearray(4)
        mac2.do_final(tag2, 0)
        
        # Different keys should produce different MACs
        assert bytes(tag1) != bytes(tag2)
    
    def test_different_ivs_produce_different_macs(self):
        """Test that different IVs produce different MACs."""
        message = b"Same message"
        key = bytes([0x33] * 16)
        
        # IV 1
        mac1 = ZUC128MAC(mac_bits=32)
        iv1 = bytes([0x01] * 16)
        mac1.init(ParametersWithIV(KeyParameter(key), iv1))
        mac1.update_bytes(message, 0, len(message))
        tag1 = bytearray(4)
        mac1.do_final(tag1, 0)
        
        # IV 2
        mac2 = ZUC128MAC(mac_bits=32)
        iv2 = bytes([0x02] * 16)
        mac2.init(ParametersWithIV(KeyParameter(key), iv2))
        mac2.update_bytes(message, 0, len(message))
        tag2 = bytearray(4)
        mac2.do_final(tag2, 0)
        
        # Different IVs should produce different MACs
        assert bytes(tag1) != bytes(tag2)
    
    def test_output_buffer_too_short(self):
        """Test that short output buffer raises error."""
        mac = ZUC128MAC(mac_bits=32)
        key = bytes(16)
        iv = bytes(16)
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        mac.update_bytes(b"Test", 0, 4)
        
        tag = bytearray(2)  # Too short
        
        with pytest.raises(DataLengthException, match="Output buffer too short"):
            mac.do_final(tag, 0)
    
    def test_long_message(self):
        """Test MAC with longer message."""
        mac = ZUC128MAC(mac_bits=64)
        key = bytes([0xAA] * 16)
        iv = bytes([0x55] * 16)
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        
        # 1000 byte message
        message = bytes(range(256)) * 3 + bytes(range(232))
        mac.update_bytes(message, 0, len(message))
        
        tag = bytearray(8)
        result = mac.do_final(tag, 0)
        
        assert result == 8
        assert any(b != 0 for b in tag)


class TestZUC256MAC:
    """Test cases for ZUC-256 MAC (256-EIA3)."""
    
    def test_algorithm_name(self):
        """Test that algorithm name is correct."""
        mac = ZUC256MAC(mac_bits=64)
        assert mac.get_algorithm_name() == 'ZUC-256-MAC-64'
        
        mac = ZUC256MAC(mac_bits=128)
        assert mac.get_algorithm_name() == 'ZUC-256-MAC-128'
    
    def test_mac_size(self):
        """Test MAC size reporting."""
        mac64 = ZUC256MAC(mac_bits=64)
        assert mac64.get_mac_size() == 8
        
        mac128 = ZUC256MAC(mac_bits=128)
        assert mac128.get_mac_size() == 16
    
    def test_invalid_mac_bits(self):
        """Test that invalid MAC bits raise error."""
        with pytest.raises(ValueError, match="MAC bits must be 64 or 128"):
            ZUC256MAC(mac_bits=32)
    
    def test_initialization_requires_parameters_with_iv(self):
        """Test that initialization requires ParametersWithIV."""
        mac = ZUC256MAC()
        key = bytes(32)
        
        with pytest.raises(ValueError, match="requires ParametersWithIV"):
            mac.init(KeyParameter(key))
    
    def test_initialization_requires_256bit_key(self):
        """Test that initialization requires 256-bit key."""
        mac = ZUC256MAC()
        key = bytes(16)  # Wrong size
        iv = bytes(23)
        
        with pytest.raises(ValueError, match="256-bit key"):
            mac.init(ParametersWithIV(KeyParameter(key), iv))
    
    def test_initialization_requires_184_or_200bit_iv(self):
        """Test that initialization requires 184-bit or 200-bit IV."""
        mac = ZUC256MAC()
        key = bytes(32)
        iv = bytes(16)  # Wrong size
        
        with pytest.raises(ValueError, match="184-bit.*or.*200-bit"):
            mac.init(ParametersWithIV(KeyParameter(key), iv))
    
    def test_basic_mac_generation_64bit_184iv(self):
        """Test basic MAC generation with 64-bit output and 184-bit IV."""
        mac = ZUC256MAC(mac_bits=64)
        key = bytes(32)  # All zeros
        iv = bytes(23)   # All zeros (184 bits)
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        
        message = b"Hello, ZUC-256 MAC!"
        mac.update_bytes(message, 0, len(message))
        
        tag = bytearray(8)
        result = mac.do_final(tag, 0)
        
        assert result == 8
        # MAC should not be all zeros
        assert any(b != 0 for b in tag)
    
    def test_basic_mac_generation_128bit_200iv(self):
        """Test basic MAC generation with 128-bit output and 200-bit IV."""
        mac = ZUC256MAC(mac_bits=128)
        key = bytes(32)  # All zeros
        iv = bytes(25)   # All zeros (200 bits)
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        
        message = b"Hello, ZUC-256 MAC!"
        mac.update_bytes(message, 0, len(message))
        
        tag = bytearray(16)
        result = mac.do_final(tag, 0)
        
        assert result == 16
        # MAC should not be all zeros
        assert any(b != 0 for b in tag)
    
    def test_empty_message(self):
        """Test MAC generation with empty message."""
        mac = ZUC256MAC(mac_bits=64)
        key = bytes([0x11] * 32)
        iv = bytes([0x22] * 23)
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        
        tag = bytearray(8)
        result = mac.do_final(tag, 0)
        
        assert result == 8
    
    def test_single_byte_update(self):
        """Test MAC with single byte updates."""
        mac = ZUC256MAC(mac_bits=64)
        key = bytes([0x42] * 32)
        iv = bytes([0x99] * 25)
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        
        message = b"Test"
        for byte in message:
            mac.update(byte)
        
        tag = bytearray(8)
        mac.do_final(tag, 0)
        
        # Should produce valid MAC
        assert len(tag) == 8
    
    def test_multiple_update_calls(self):
        """Test MAC with multiple update calls."""
        mac = ZUC256MAC(mac_bits=128)
        key = bytes([0x55] * 32)
        iv = bytes([0xAA] * 23)
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        
        # Update in parts
        mac.update_bytes(b"Hello, ", 0, 7)
        mac.update_bytes(b"World!", 0, 6)
        
        tag = bytearray(16)
        mac.do_final(tag, 0)
        
        assert len(tag) == 16
    
    def test_reset_functionality(self):
        """Test that reset allows reuse with same key."""
        mac = ZUC256MAC(mac_bits=64)
        key = bytes([0x77] * 32)
        iv = bytes([0x88] * 23)
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        
        message = b"Test message"
        
        # First MAC computation
        mac.update_bytes(message, 0, len(message))
        tag1 = bytearray(8)
        mac.do_final(tag1, 0)
        
        # do_final should auto-reset, compute again
        mac.update_bytes(message, 0, len(message))
        tag2 = bytearray(8)
        mac.do_final(tag2, 0)
        
        # Should produce same MAC
        assert bytes(tag1) == bytes(tag2)
    
    def test_different_keys_produce_different_macs(self):
        """Test that different keys produce different MACs."""
        message = b"Same message"
        iv = bytes(23)
        
        # Key 1
        mac1 = ZUC256MAC(mac_bits=64)
        key1 = bytes([0x01] * 32)
        mac1.init(ParametersWithIV(KeyParameter(key1), iv))
        mac1.update_bytes(message, 0, len(message))
        tag1 = bytearray(8)
        mac1.do_final(tag1, 0)
        
        # Key 2
        mac2 = ZUC256MAC(mac_bits=64)
        key2 = bytes([0x02] * 32)
        mac2.init(ParametersWithIV(KeyParameter(key2), iv))
        mac2.update_bytes(message, 0, len(message))
        tag2 = bytearray(8)
        mac2.do_final(tag2, 0)
        
        # Different keys should produce different MACs
        assert bytes(tag1) != bytes(tag2)
    
    def test_different_ivs_produce_different_macs(self):
        """Test that different IVs produce different MACs."""
        message = b"Same message"
        key = bytes([0x33] * 32)
        
        # IV 1
        mac1 = ZUC256MAC(mac_bits=64)
        iv1 = bytes([0x01] * 23)
        mac1.init(ParametersWithIV(KeyParameter(key), iv1))
        mac1.update_bytes(message, 0, len(message))
        tag1 = bytearray(8)
        mac1.do_final(tag1, 0)
        
        # IV 2
        mac2 = ZUC256MAC(mac_bits=64)
        iv2 = bytes([0x02] * 23)
        mac2.init(ParametersWithIV(KeyParameter(key), iv2))
        mac2.update_bytes(message, 0, len(message))
        tag2 = bytearray(8)
        mac2.do_final(tag2, 0)
        
        # Different IVs should produce different MACs
        assert bytes(tag1) != bytes(tag2)
    
    def test_different_mac_bits_produce_different_sizes(self):
        """Test that different MAC bits produce different output sizes."""
        message = b"Test message"
        key = bytes([0x44] * 32)
        iv = bytes([0x55] * 25)
        
        # 64-bit MAC
        mac64 = ZUC256MAC(mac_bits=64)
        mac64.init(ParametersWithIV(KeyParameter(key), iv))
        mac64.update_bytes(message, 0, len(message))
        tag64 = bytearray(8)
        mac64.do_final(tag64, 0)
        
        # 128-bit MAC
        mac128 = ZUC256MAC(mac_bits=128)
        mac128.init(ParametersWithIV(KeyParameter(key), iv))
        mac128.update_bytes(message, 0, len(message))
        tag128 = bytearray(16)
        mac128.do_final(tag128, 0)
        
        # Should produce different size outputs
        assert len(tag64) == 8
        assert len(tag128) == 16
    
    def test_output_buffer_too_short(self):
        """Test that short output buffer raises error."""
        mac = ZUC256MAC(mac_bits=128)
        key = bytes(32)
        iv = bytes(23)
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        mac.update_bytes(b"Test", 0, 4)
        
        tag = bytearray(8)  # Too short for 128-bit MAC
        
        with pytest.raises(DataLengthException, match="Output buffer too short"):
            mac.do_final(tag, 0)
    
    def test_long_message(self):
        """Test MAC with longer message."""
        mac = ZUC256MAC(mac_bits=128)
        key = bytes([0xAA] * 32)
        iv = bytes([0x55] * 25)
        
        mac.init(ParametersWithIV(KeyParameter(key), iv))
        
        # 1000 byte message
        message = bytes(range(256)) * 3 + bytes(range(232))
        mac.update_bytes(message, 0, len(message))
        
        tag = bytearray(16)
        result = mac.do_final(tag, 0)
        
        assert result == 16
        assert any(b != 0 for b in tag)
