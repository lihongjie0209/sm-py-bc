"""
CBC mode tests with SM4.

Reference: test/unit/crypto/modes/CBCBlockCipher.test.ts (sm-js-bc)
"""

import pytest
from sm_bc.crypto.modes.cbc_block_cipher import CBCBlockCipher
from sm_bc.crypto.engines.sm4_engine import SM4Engine
from sm_bc.crypto.params.key_parameter import KeyParameter
from sm_bc.crypto.params.parameters_with_iv import ParametersWithIV


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


class TestCBCBlockCipherBasic:
    """Basic functionality tests."""
    
    def test_algorithm_name(self):
        """Should return correct algorithm name."""
        engine = SM4Engine()
        cipher = CBCBlockCipher(engine)
        assert cipher.get_algorithm_name() == 'SM4/CBC'
    
    def test_block_size(self):
        """Should return correct block size."""
        engine = SM4Engine()
        cipher = CBCBlockCipher(engine)
        assert cipher.get_block_size() == 16
    
    def test_get_underlying_cipher(self):
        """Should correctly get underlying engine."""
        engine = SM4Engine()
        cipher = CBCBlockCipher(engine)
        assert cipher.get_underlying_cipher() is engine


class TestCBCEncryptionDecryption:
    """Encryption and decryption tests."""
    
    def test_encrypt_single_block(self):
        """Should correctly encrypt single block."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000000')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        cipher = CBCBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), iv)
        
        cipher.init(True, params)
        
        ciphertext = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext, 0)
        
        # CBC first block: C1 = E(P1 XOR IV)
        # Since IV is all zeros, this equals E(P1)
        expected = hex_to_bytes('681edf34d206965e86b3e94f536e4246')
        assert bytes_to_hex(ciphertext) == bytes_to_hex(expected)
    
    def test_decrypt_single_block(self):
        """Should correctly decrypt single block."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000000')
        ciphertext = hex_to_bytes('681edf34d206965e86b3e94f536e4246')
        
        engine = SM4Engine()
        cipher = CBCBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), iv)
        
        cipher.init(False, params)
        
        plaintext = bytearray(16)
        cipher.process_block(ciphertext, 0, plaintext, 0)
        
        expected = hex_to_bytes('0123456789abcdeffedcba9876543210')
        assert bytes_to_hex(plaintext) == bytes_to_hex(expected)
    
    def test_encrypt_multiple_blocks(self):
        """Should correctly process multiple blocks encryption."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00112233445566778899aabbccddeeff')
        plaintext1 = hex_to_bytes('0123456789abcdeffedcba9876543210')
        plaintext2 = hex_to_bytes('fedcba98765432100123456789abcdef')
        
        engine = SM4Engine()
        cipher = CBCBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), iv)
        
        cipher.init(True, params)
        
        ciphertext1 = bytearray(16)
        ciphertext2 = bytearray(16)
        
        cipher.process_block(plaintext1, 0, ciphertext1, 0)
        cipher.process_block(plaintext2, 0, ciphertext2, 0)
        
        # Verify two ciphertext blocks are different
        assert bytes_to_hex(ciphertext1) != bytes_to_hex(ciphertext2)
        
        # Decrypt and verify
        cipher.init(False, params)
        decrypted1 = bytearray(16)
        decrypted2 = bytearray(16)
        
        cipher.process_block(ciphertext1, 0, decrypted1, 0)
        cipher.process_block(ciphertext2, 0, decrypted2, 0)
        
        assert bytes_to_hex(decrypted1) == bytes_to_hex(plaintext1)
        assert bytes_to_hex(decrypted2) == bytes_to_hex(plaintext2)
    
    def test_encrypt_decrypt_roundtrip(self):
        """Encryption decryption roundtrip should restore original."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('0123456789abcdef0123456789abcdef')
        plaintext = hex_to_bytes('00112233445566778899aabbccddeeff')
        
        # Encrypt
        enc_engine = SM4Engine()
        enc_cipher = CBCBlockCipher(enc_engine)
        enc_params = ParametersWithIV(KeyParameter(key), iv)
        enc_cipher.init(True, enc_params)
        
        ciphertext = bytearray(16)
        enc_cipher.process_block(plaintext, 0, ciphertext, 0)
        
        # Decrypt
        dec_engine = SM4Engine()
        dec_cipher = CBCBlockCipher(dec_engine)
        dec_params = ParametersWithIV(KeyParameter(key), iv)
        dec_cipher.init(False, dec_params)
        
        decrypted = bytearray(16)
        dec_cipher.process_block(ciphertext, 0, decrypted, 0)
        
        assert bytes_to_hex(decrypted) == bytes_to_hex(plaintext)


class TestCBCChaining:
    """Test CBC chaining behavior."""
    
    def test_chaining_effect(self):
        """Should demonstrate chaining effect in CBC mode."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00000000000000000000000000000000')
        
        # Same plaintext blocks
        plaintext1 = hex_to_bytes('0123456789abcdeffedcba9876543210')
        plaintext2 = hex_to_bytes('0123456789abcdeffedcba9876543210')  # Same!
        
        engine = SM4Engine()
        cipher = CBCBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), iv)
        cipher.init(True, params)
        
        ciphertext1 = bytearray(16)
        ciphertext2 = bytearray(16)
        
        cipher.process_block(plaintext1, 0, ciphertext1, 0)
        cipher.process_block(plaintext2, 0, ciphertext2, 0)
        
        # Due to chaining, same plaintext produces different ciphertext
        assert bytes_to_hex(ciphertext1) != bytes_to_hex(ciphertext2)
    
    def test_reset_behavior(self):
        """Should reset chaining vector to IV."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('00112233445566778899aabbccddeeff')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        cipher = CBCBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), iv)
        
        # First encryption
        cipher.init(True, params)
        ciphertext1 = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext1, 0)
        
        # Reset and encrypt again
        cipher.reset()
        ciphertext2 = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext2, 0)
        
        # Should produce same ciphertext (same IV, same plaintext)
        assert bytes_to_hex(ciphertext1) == bytes_to_hex(ciphertext2)


class TestCBCIVHandling:
    """Test IV handling."""
    
    def test_zero_iv(self):
        """Should handle all-zero IV."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        plaintext = hex_to_bytes('0123456789abcdeffedcba9876543210')
        
        engine = SM4Engine()
        cipher = CBCBlockCipher(engine)
        
        # Init without ParametersWithIV (uses zero IV)
        cipher.init(True, KeyParameter(key))
        
        ciphertext = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext, 0)
        
        # Should equal ECB mode encryption (first block with zero IV)
        expected = hex_to_bytes('681edf34d206965e86b3e94f536e4246')
        assert bytes_to_hex(ciphertext) == bytes_to_hex(expected)
    
    def test_wrong_iv_length(self):
        """Should throw error for wrong IV length."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        wrong_iv = hex_to_bytes('0011223344556677')  # Only 8 bytes
        
        engine = SM4Engine()
        cipher = CBCBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), wrong_iv)
        
        with pytest.raises(ValueError, match='same length as block size'):
            cipher.init(True, params)


class TestCBCMultipleBlocks:
    """Test processing multiple blocks."""
    
    def test_long_message_encryption(self):
        """Should handle multi-block messages."""
        key = hex_to_bytes('0123456789abcdeffedcba9876543210')
        iv = hex_to_bytes('fedcba9876543210fedcba9876543210')
        
        # 3 blocks of plaintext
        plaintexts = [
            hex_to_bytes('00112233445566778899aabbccddeeff'),
            hex_to_bytes('0123456789abcdeffedcba9876543210'),
            hex_to_bytes('aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb')
        ]
        
        engine = SM4Engine()
        cipher = CBCBlockCipher(engine)
        params = ParametersWithIV(KeyParameter(key), iv)
        
        # Encrypt all blocks
        cipher.init(True, params)
        ciphertexts = []
        for plaintext in plaintexts:
            ciphertext = bytearray(16)
            cipher.process_block(plaintext, 0, ciphertext, 0)
            ciphertexts.append(bytes(ciphertext))
        
        # Decrypt all blocks
        cipher.init(False, params)
        decrypted = []
        for ciphertext in ciphertexts:
            decrypted_block = bytearray(16)
            cipher.process_block(ciphertext, 0, decrypted_block, 0)
            decrypted.append(bytes(decrypted_block))
        
        # Verify all blocks decrypted correctly
        for i in range(len(plaintexts)):
            assert bytes_to_hex(decrypted[i]) == bytes_to_hex(plaintexts[i])
