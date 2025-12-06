"""
SIC/CTR mode tests with SM4.

Reference: test/unit/crypto/modes/SICBlockCipher.test.ts (sm-js-bc)
"""

import pytest
from sm_bc.crypto.modes.sic_block_cipher import SICBlockCipher
from sm_bc.crypto.engines.sm4_engine import SM4Engine
from sm_bc.crypto.params.key_parameter import KeyParameter
from sm_bc.crypto.params.parameters_with_iv import ParametersWithIV


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


class TestSICBlockCipherBasic:
    """Basic functionality tests."""
    
    def test_algorithm_name(self):
        """Should return correct algorithm name."""
        engine = SM4Engine()
        cipher = SICBlockCipher(engine)
        assert cipher.get_algorithm_name() == 'SM4/SIC'
    
    def test_block_size(self):
        """Should return correct block size."""
        engine = SM4Engine()
        cipher = SICBlockCipher(engine)
        assert cipher.get_block_size() == 16
    
    def test_get_underlying_cipher(self):
        """Should correctly get underlying engine."""
        engine = SM4Engine()
        cipher = SICBlockCipher(engine)
        assert cipher.get_underlying_cipher() is engine
    
    def test_requires_parameters_with_iv(self):
        """Should require ParametersWithIV."""
        engine = SM4Engine()
        cipher = SICBlockCipher(engine)
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        with pytest.raises(ValueError, match='requires ParametersWithIV'):
            cipher.init(True, KeyParameter(key))


class TestSICEncryptionDecryption:
    """Encryption and decryption tests."""
    
    def test_encrypt_single_block(self):
        """Should correctly encrypt single block."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000000')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        cipher = SICBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), iv)
        
        cipher.init(True, params)
        
        ciphertext = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext, 0)
        
        # CTR: C = P XOR E(counter)
        # First block uses counter = IV
        assert len(ciphertext) == 16
        # Should not be all zeros
        assert ciphertext != bytes(16)
    
    def test_decrypt_equals_encrypt(self):
        """CTR mode: decryption equals encryption."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000001')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        # Encrypt
        enc_engine = SM4Engine()
        enc_cipher = SICBlockCipher(enc_engine)
        enc_params = ParametersWithIV(KeyParameter(key), iv)
        enc_cipher.init(True, enc_params)
        
        ciphertext = bytearray(16)
        enc_cipher.process_block(plaintext, 0, ciphertext, 0)
        
        # Decrypt (using same operation!)
        dec_engine = SM4Engine()
        dec_cipher = SICBlockCipher(dec_engine)
        dec_params = ParametersWithIV(KeyParameter(key), iv)
        dec_cipher.init(False, dec_params)  # forEncryption ignored in CTR
        
        decrypted = bytearray(16)
        dec_cipher.process_block(ciphertext, 0, decrypted, 0)
        
        assert bytes_to_hex(decrypted) == bytes_to_hex(plaintext)
    
    def test_multiple_blocks(self):
        """Should handle multiple blocks with counter increment."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('0000000000000000000000000000007f')  # Close to overflow
        
        plaintext1 = hex_to_bytes('0123456789abcdeffedcba9876543210')
        plaintext2 = hex_to_bytes('fedcba98765432100123456789abcdef')
        plaintext3 = hex_to_bytes('aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb')
        
        engine = SM4Engine()
        cipher = SICBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), iv)
        cipher.init(True, params)
        
        ciphertext1 = bytearray(16)
        ciphertext2 = bytearray(16)
        ciphertext3 = bytearray(16)
        
        cipher.process_block(plaintext1, 0, ciphertext1, 0)
        cipher.process_block(plaintext2, 0, ciphertext2, 0)
        cipher.process_block(plaintext3, 0, ciphertext3, 0)
        
        # All ciphertexts should be different
        assert bytes_to_hex(ciphertext1) != bytes_to_hex(ciphertext2)
        assert bytes_to_hex(ciphertext2) != bytes_to_hex(ciphertext3)
        
        # Decrypt all blocks
        cipher.init(False, params)
        decrypted1 = bytearray(16)
        decrypted2 = bytearray(16)
        decrypted3 = bytearray(16)
        
        cipher.process_block(ciphertext1, 0, decrypted1, 0)
        cipher.process_block(ciphertext2, 0, decrypted2, 0)
        cipher.process_block(ciphertext3, 0, decrypted3, 0)
        
        assert bytes_to_hex(decrypted1) == bytes_to_hex(plaintext1)
        assert bytes_to_hex(decrypted2) == bytes_to_hex(plaintext2)
        assert bytes_to_hex(decrypted3) == bytes_to_hex(plaintext3)


class TestSICStreamMode:
    """Test stream processing with process_bytes."""
    
    def test_process_bytes(self):
        """Should process arbitrary length data."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000000')
        
        # Non-block-aligned data
        plaintext = b"Hello, CTR mode! This is a test."
        
        engine = SM4Engine()
        cipher = SICBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), iv)
        cipher.init(True, params)
        
        ciphertext = bytearray(len(plaintext))
        cipher.process_bytes(plaintext, 0, len(plaintext), ciphertext, 0)
        
        # Decrypt
        cipher.init(False, params)
        decrypted = bytearray(len(ciphertext))
        cipher.process_bytes(ciphertext, 0, len(ciphertext), decrypted, 0)
        
        assert bytes(decrypted) == plaintext
    
    def test_partial_block_processing(self):
        """Should handle partial block processing."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000001')
        
        plaintext = b"Short msg"  # 9 bytes
        
        engine = SM4Engine()
        cipher = SICBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), iv)
        cipher.init(True, params)
        
        ciphertext = bytearray(len(plaintext))
        cipher.process_bytes(plaintext, 0, len(plaintext), ciphertext, 0)
        
        # Decrypt
        cipher.init(False, params)
        decrypted = bytearray(len(ciphertext))
        cipher.process_bytes(ciphertext, 0, len(ciphertext), decrypted, 0)
        
        assert bytes(decrypted) == plaintext


class TestSICCounterBehavior:
    """Test counter increment and overflow behavior."""
    
    def test_counter_increments(self):
        """Should increment counter for each block."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000000')
        
        # Same plaintext
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        cipher = SICBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), iv)
        cipher.init(True, params)
        
        ciphertext1 = bytearray(16)
        ciphertext2 = bytearray(16)
        
        cipher.process_block(plaintext, 0, ciphertext1, 0)
        cipher.process_block(plaintext, 0, ciphertext2, 0)
        
        # Same plaintext, different counter → different ciphertext
        assert bytes_to_hex(ciphertext1) != bytes_to_hex(ciphertext2)
    
    def test_reset_resets_counter(self):
        """Should reset counter to IV."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000001')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        cipher = SICBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), iv)
        cipher.init(True, params)
        
        ciphertext1 = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext1, 0)
        
        # Reset
        cipher.reset()
        
        ciphertext2 = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext2, 0)
        
        # After reset, same plaintext → same ciphertext (same counter)
        assert bytes_to_hex(ciphertext1) == bytes_to_hex(ciphertext2)


class TestSICIVValidation:
    """Test IV validation."""
    
    def test_iv_too_long(self):
        """Should reject IV longer than block size."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        long_iv = hex_to_bytes('00112233445566778899aabbccddeeff00')  # 17 bytes
        
        engine = SM4Engine()
        cipher = SICBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), long_iv)
        
        with pytest.raises(ValueError, match='no greater than'):
            cipher.init(True, params)
    
    def test_iv_too_short(self):
        """Should reject IV that is too short."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        short_iv = hex_to_bytes('0011223344')  # 5 bytes
        
        engine = SM4Engine()
        cipher = SICBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), short_iv)
        
        with pytest.raises(ValueError, match='at least'):
            cipher.init(True, params)
    
    def test_valid_iv_lengths(self):
        """Should accept valid IV lengths."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        # Valid IV lengths for 16-byte block: 8-16 bytes
        valid_ivs = [
            hex_to_bytes('0011223344556677'),  # 8 bytes
            hex_to_bytes('00112233445566778899aabbccddee'),  # 15 bytes
            hex_to_bytes('00112233445566778899aabbccddeeff'),  # 16 bytes
        ]
        
        for iv in valid_ivs:
            engine = SM4Engine()
            cipher = SICBlockCipher(engine)
            params = ParametersWithIV(KeyParameter(key), iv)
            
            # Should not throw
            cipher.init(True, params)
            
            ciphertext = bytearray(16)
            cipher.process_block(plaintext, 0, ciphertext, 0)
            
            assert len(ciphertext) == 16


class TestSICRoundTrip:
    """Round-trip encryption/decryption tests."""
    
    def test_long_message_roundtrip(self):
        """Should handle long messages correctly."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('fedcba9876543210fedcba9876543210')
        
        # Long message (multiple blocks)
        plaintext = b"The quick brown fox jumps over the lazy dog. " * 5
        
        engine = SM4Engine()
        cipher = SICBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), iv)
        
        # Encrypt
        cipher.init(True, params)
        ciphertext = bytearray(len(plaintext))
        cipher.process_bytes(plaintext, 0, len(plaintext), ciphertext, 0)
        
        # Decrypt
        cipher.init(False, params)
        decrypted = bytearray(len(ciphertext))
        cipher.process_bytes(ciphertext, 0, len(ciphertext), decrypted, 0)
        
        assert bytes(decrypted) == plaintext
