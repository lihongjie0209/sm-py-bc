"""
Comprehensive unit tests for GCM mode
"""
import pytest
from sm_bc.crypto.modes.gcm_block_cipher import GCMBlockCipher
from sm_bc.crypto.engines.sm4_engine import SM4Engine
from sm_bc.crypto.params.key_parameter import KeyParameter
from sm_bc.crypto.params.aead_parameters import AEADParameters
from sm_bc.crypto.params.parameters_with_iv import ParametersWithIV


class TestGCMBlockCipher:
    """Test suite for GCM mode"""
    
    # Test key
    KEY = bytes([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    ])
    
    # 12-byte standard nonce
    NONCE = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b
    ])
    
    def test_get_algorithm_name(self):
        """Should return correct algorithm name"""
        cipher = GCMBlockCipher(SM4Engine())
        assert cipher.get_algorithm_name() == "SM4/GCM"
    
    def test_get_block_size(self):
        """Should return correct block size (16 bytes)"""
        cipher = GCMBlockCipher(SM4Engine())
        assert cipher.get_block_size() == 16
    
    def test_invalid_mac_size(self):
        """Should raise error on invalid MAC size"""
        cipher = GCMBlockCipher(SM4Engine())
        params = AEADParameters(KeyParameter(self.KEY), 24, self.NONCE)  # 24 is not multiple of 8
        with pytest.raises(ValueError, match="Invalid value for MAC size"):
            cipher.init(True, params)
    
    def test_empty_nonce(self):
        """Should raise error when nonce is empty"""
        cipher = GCMBlockCipher(SM4Engine())
        empty_nonce = bytes()
        params = AEADParameters(KeyParameter(self.KEY), 128, empty_nonce)
        with pytest.raises(ValueError, match="IV must be at least 1 byte"):
            cipher.init(True, params)
    
    def test_encrypt_decrypt_empty_data(self):
        """Should correctly encrypt and decrypt empty data"""
        plaintext = bytes()
        
        # Encrypt
        enc_cipher = GCMBlockCipher(SM4Engine())
        params = AEADParameters(KeyParameter(self.KEY), 128, self.NONCE)
        enc_cipher.init(True, params)
        
        ciphertext = bytearray(enc_cipher.get_output_size(0))
        enc_len = enc_cipher.process_bytes(plaintext, 0, 0, ciphertext, 0)
        final_len = enc_cipher.do_final(ciphertext, enc_len)
        
        assert final_len == 16  # Only tag
        
        # Decrypt
        dec_cipher = GCMBlockCipher(SM4Engine())
        dec_cipher.init(False, params)
        
        decrypted = bytearray(dec_cipher.get_output_size(final_len))
        dec_len = dec_cipher.process_bytes(bytes(ciphertext), 0, final_len, decrypted, 0)
        dec_final_len = dec_cipher.do_final(decrypted, dec_len)
        
        assert dec_final_len == 0
    
    def test_encrypt_decrypt_16_bytes(self):
        """Should correctly encrypt and decrypt 16 bytes of data"""
        plaintext = bytes(range(16))
        
        # Encrypt
        enc_cipher = GCMBlockCipher(SM4Engine())
        params = AEADParameters(KeyParameter(self.KEY), 128, self.NONCE)
        enc_cipher.init(True, params)
        
        ciphertext = bytearray(enc_cipher.get_output_size(16))
        enc_len = enc_cipher.process_bytes(plaintext, 0, 16, ciphertext, 0)
        final_len = enc_cipher.do_final(ciphertext, enc_len)
        
        assert enc_len + final_len == 32  # 16 bytes data + 16 bytes tag
        
        # Decrypt
        dec_cipher = GCMBlockCipher(SM4Engine())
        dec_cipher.init(False, params)
        
        decrypted = bytearray(dec_cipher.get_output_size(enc_len + final_len))
        dec_len = dec_cipher.process_bytes(bytes(ciphertext), 0, enc_len + final_len, decrypted, 0)
        dec_final_len = dec_cipher.do_final(decrypted, dec_len)
        
        assert dec_final_len == 16
        assert bytes(decrypted[:16]) == plaintext
    
    def test_encrypt_decrypt_32_bytes(self):
        """Should correctly encrypt and decrypt 32 bytes of data"""
        plaintext = bytes(range(32))
        
        # Encrypt
        enc_cipher = GCMBlockCipher(SM4Engine())
        params = AEADParameters(KeyParameter(self.KEY), 128, self.NONCE)
        enc_cipher.init(True, params)
        
        ciphertext = bytearray(enc_cipher.get_output_size(32))
        enc_len = enc_cipher.process_bytes(plaintext, 0, 32, ciphertext, 0)
        final_len = enc_cipher.do_final(ciphertext, enc_len)
        
        assert enc_len + final_len == 48  # 32 bytes data + 16 bytes tag
        
        # Decrypt
        dec_cipher = GCMBlockCipher(SM4Engine())
        dec_cipher.init(False, params)
        
        decrypted = bytearray(dec_cipher.get_output_size(enc_len + final_len))
        dec_len = dec_cipher.process_bytes(bytes(ciphertext), 0, enc_len + final_len, decrypted, 0)
        dec_final_len = dec_cipher.do_final(decrypted, dec_len)
        
        assert dec_final_len == 32
        assert bytes(decrypted[:32]) == plaintext
    
    def test_encrypt_decrypt_unaligned_data(self):
        """Should correctly encrypt and decrypt non-aligned data (17 bytes)"""
        plaintext = bytes(range(17))
        
        # Encrypt
        enc_cipher = GCMBlockCipher(SM4Engine())
        params = AEADParameters(KeyParameter(self.KEY), 128, self.NONCE)
        enc_cipher.init(True, params)
        
        ciphertext = bytearray(enc_cipher.get_output_size(17))
        enc_len = enc_cipher.process_bytes(plaintext, 0, 17, ciphertext, 0)
        final_len = enc_cipher.do_final(ciphertext, enc_len)
        
        assert enc_len + final_len == 33  # 17 bytes data + 16 bytes tag
        
        # Decrypt
        dec_cipher = GCMBlockCipher(SM4Engine())
        dec_cipher.init(False, params)
        
        decrypted = bytearray(dec_cipher.get_output_size(enc_len + final_len))
        dec_len = dec_cipher.process_bytes(bytes(ciphertext), 0, enc_len + final_len, decrypted, 0)
        dec_final_len = dec_cipher.do_final(decrypted, dec_len)
        
        assert dec_final_len == 17
        assert bytes(decrypted[:17]) == plaintext
    
    def test_with_aad(self):
        """Should correctly handle AAD"""
        plaintext = bytes(range(16))
        aad = bytes([0xaa, 0xbb, 0xcc, 0xdd])
        
        # Encrypt
        enc_cipher = GCMBlockCipher(SM4Engine())
        params = AEADParameters(KeyParameter(self.KEY), 128, self.NONCE, aad)
        enc_cipher.init(True, params)
        
        ciphertext = bytearray(enc_cipher.get_output_size(16))
        enc_len = enc_cipher.process_bytes(plaintext, 0, 16, ciphertext, 0)
        final_len = enc_cipher.do_final(ciphertext, enc_len)
        
        # Decrypt with correct AAD
        dec_cipher1 = GCMBlockCipher(SM4Engine())
        dec_cipher1.init(False, params)
        
        decrypted1 = bytearray(dec_cipher1.get_output_size(enc_len + final_len))
        dec_len1 = dec_cipher1.process_bytes(bytes(ciphertext), 0, enc_len + final_len, decrypted1, 0)
        dec_final_len1 = dec_cipher1.do_final(decrypted1, dec_len1)
        
        assert dec_final_len1 == 16
        assert bytes(decrypted1[:16]) == plaintext
        
        # Decrypt with wrong AAD - should fail
        wrong_aad = bytes([0xaa, 0xbb, 0xcc, 0xee])
        wrong_params = AEADParameters(KeyParameter(self.KEY), 128, self.NONCE, wrong_aad)
        dec_cipher2 = GCMBlockCipher(SM4Engine())
        dec_cipher2.init(False, wrong_params)
        
        decrypted2 = bytearray(dec_cipher2.get_output_size(enc_len + final_len))
        dec_len2 = dec_cipher2.process_bytes(bytes(ciphertext), 0, enc_len + final_len, decrypted2, 0)
        
        with pytest.raises(Exception, match="mac check in GCM failed"):
            dec_cipher2.do_final(decrypted2, dec_len2)
    
    def test_96_bit_mac(self):
        """Should support 96-bit MAC"""
        plaintext = bytes(range(16))
        
        # Encrypt
        enc_cipher = GCMBlockCipher(SM4Engine())
        params = AEADParameters(KeyParameter(self.KEY), 96, self.NONCE)
        enc_cipher.init(True, params)
        
        ciphertext = bytearray(enc_cipher.get_output_size(16))
        enc_len = enc_cipher.process_bytes(plaintext, 0, 16, ciphertext, 0)
        final_len = enc_cipher.do_final(ciphertext, enc_len)
        
        assert enc_len + final_len == 28  # 16 bytes data + 12 bytes tag
        
        # Decrypt
        dec_cipher = GCMBlockCipher(SM4Engine())
        dec_cipher.init(False, params)
        
        decrypted = bytearray(dec_cipher.get_output_size(enc_len + final_len))
        dec_len = dec_cipher.process_bytes(bytes(ciphertext), 0, enc_len + final_len, decrypted, 0)
        dec_final_len = dec_cipher.do_final(decrypted, dec_len)
        
        assert dec_final_len == 16
        assert bytes(decrypted[:16]) == plaintext
    
    def test_12_byte_nonce(self):
        """Should support 12-byte nonce (standard)"""
        plaintext = bytes(range(16))
        nonce12 = bytes(range(12))
        
        cipher = GCMBlockCipher(SM4Engine())
        params = AEADParameters(KeyParameter(self.KEY), 128, nonce12)
        
        # Should not throw
        cipher.init(True, params)
    
    def test_non_12_byte_nonce(self):
        """Should support non-12-byte nonce"""
        plaintext = bytes(range(16))
        nonce16 = bytes(range(16))
        
        cipher = GCMBlockCipher(SM4Engine())
        params = AEADParameters(KeyParameter(self.KEY), 128, nonce16)
        
        # Should not throw
        cipher.init(True, params)
    
    def test_different_nonce_different_ciphertext(self):
        """Different nonces should produce different ciphertexts"""
        plaintext = bytes(range(16))
        
        nonce1 = bytes(range(12))
        nonce2 = bytes(range(1, 13))
        
        # Encrypt with nonce1
        cipher1 = GCMBlockCipher(SM4Engine())
        cipher1.init(True, AEADParameters(KeyParameter(self.KEY), 128, nonce1))
        ciphertext1 = bytearray(cipher1.get_output_size(16))
        cipher1.process_bytes(plaintext, 0, 16, ciphertext1, 0)
        cipher1.do_final(ciphertext1, 0)
        
        # Encrypt with nonce2
        cipher2 = GCMBlockCipher(SM4Engine())
        cipher2.init(True, AEADParameters(KeyParameter(self.KEY), 128, nonce2))
        ciphertext2 = bytearray(cipher2.get_output_size(16))
        cipher2.process_bytes(plaintext, 0, 16, ciphertext2, 0)
        cipher2.do_final(ciphertext2, 0)
        
        # Ciphertexts should be different
        assert bytes(ciphertext1) != bytes(ciphertext2)
    
    def test_tampered_tag_rejected(self):
        """Should reject decryption when tag is tampered"""
        plaintext = bytes(range(16))
        
        # Encrypt
        enc_cipher = GCMBlockCipher(SM4Engine())
        params = AEADParameters(KeyParameter(self.KEY), 128, self.NONCE)
        enc_cipher.init(True, params)
        
        ciphertext = bytearray(enc_cipher.get_output_size(16))
        enc_len = enc_cipher.process_bytes(plaintext, 0, 16, ciphertext, 0)
        final_len = enc_cipher.do_final(ciphertext, enc_len)
        
        # Tamper with tag
        ciphertext[enc_len + final_len - 1] ^= 0x01
        
        # Decrypt should fail
        dec_cipher = GCMBlockCipher(SM4Engine())
        dec_cipher.init(False, params)
        
        decrypted = bytearray(dec_cipher.get_output_size(enc_len + final_len))
        dec_len = dec_cipher.process_bytes(bytes(ciphertext), 0, enc_len + final_len, decrypted, 0)
        
        with pytest.raises(Exception, match="mac check in GCM failed"):
            dec_cipher.do_final(decrypted, dec_len)
    
    def test_tampered_ciphertext_rejected(self):
        """Should reject decryption when ciphertext is tampered"""
        plaintext = bytes(range(16))
        
        # Encrypt
        enc_cipher = GCMBlockCipher(SM4Engine())
        params = AEADParameters(KeyParameter(self.KEY), 128, self.NONCE)
        enc_cipher.init(True, params)
        
        ciphertext = bytearray(enc_cipher.get_output_size(16))
        enc_len = enc_cipher.process_bytes(plaintext, 0, 16, ciphertext, 0)
        final_len = enc_cipher.do_final(ciphertext, enc_len)
        
        # Tamper with ciphertext
        ciphertext[0] ^= 0x01
        
        # Decrypt should fail
        dec_cipher = GCMBlockCipher(SM4Engine())
        dec_cipher.init(False, params)
        
        decrypted = bytearray(dec_cipher.get_output_size(enc_len + final_len))
        dec_len = dec_cipher.process_bytes(bytes(ciphertext), 0, enc_len + final_len, decrypted, 0)
        
        with pytest.raises(Exception, match="mac check in GCM failed"):
            dec_cipher.do_final(decrypted, dec_len)
    
    def test_parameters_with_iv(self):
        """Should support ParametersWithIV parameters"""
        plaintext = bytes(range(16))
        
        # Encrypt
        enc_cipher = GCMBlockCipher(SM4Engine())
        params = ParametersWithIV(KeyParameter(self.KEY), self.NONCE)
        enc_cipher.init(True, params)
        
        ciphertext = bytearray(enc_cipher.get_output_size(16))
        enc_len = enc_cipher.process_bytes(plaintext, 0, 16, ciphertext, 0)
        final_len = enc_cipher.do_final(ciphertext, enc_len)
        
        # Decrypt
        dec_cipher = GCMBlockCipher(SM4Engine())
        dec_cipher.init(False, params)
        
        decrypted = bytearray(dec_cipher.get_output_size(enc_len + final_len))
        dec_len = dec_cipher.process_bytes(bytes(ciphertext), 0, enc_len + final_len, decrypted, 0)
        dec_final_len = dec_cipher.do_final(decrypted, dec_len)
        
        assert dec_final_len == 16
        assert bytes(decrypted[:16]) == plaintext
    
    def test_large_data(self):
        """Should correctly handle large data (1KB)"""
        plaintext = bytes(range(256)) * 4  # 1024 bytes
        
        # Encrypt
        enc_cipher = GCMBlockCipher(SM4Engine())
        params = AEADParameters(KeyParameter(self.KEY), 128, self.NONCE)
        enc_cipher.init(True, params)
        
        ciphertext = bytearray(enc_cipher.get_output_size(1024))
        enc_len = enc_cipher.process_bytes(plaintext, 0, 1024, ciphertext, 0)
        final_len = enc_cipher.do_final(ciphertext, enc_len)
        
        assert enc_len + final_len == 1040  # 1024 bytes data + 16 bytes tag
        
        # Decrypt
        dec_cipher = GCMBlockCipher(SM4Engine())
        dec_cipher.init(False, params)
        
        decrypted = bytearray(dec_cipher.get_output_size(enc_len + final_len))
        dec_len = dec_cipher.process_bytes(bytes(ciphertext), 0, enc_len + final_len, decrypted, 0)
        dec_final_len = dec_cipher.do_final(decrypted, dec_len)
        
        assert dec_final_len == 1024
        assert bytes(decrypted[:1024]) == plaintext
    
    def test_incremental_processing(self):
        """Should support incremental processing"""
        plaintext = bytes(range(32))
        
        # Encrypt incrementally
        enc_cipher = GCMBlockCipher(SM4Engine())
        params = AEADParameters(KeyParameter(self.KEY), 128, self.NONCE)
        enc_cipher.init(True, params)
        
        ciphertext = bytearray(enc_cipher.get_output_size(32))
        offset = 0
        
        # Process in 3 chunks: 10, 12, 10 bytes
        offset += enc_cipher.process_bytes(plaintext, 0, 10, ciphertext, offset)
        offset += enc_cipher.process_bytes(plaintext, 10, 12, ciphertext, offset)
        offset += enc_cipher.process_bytes(plaintext, 22, 10, ciphertext, offset)
        offset += enc_cipher.do_final(ciphertext, offset)
        
        assert offset == 48  # 32 bytes data + 16 bytes tag
        
        # Decrypt incrementally
        dec_cipher = GCMBlockCipher(SM4Engine())
        dec_cipher.init(False, params)
        
        decrypted = bytearray(dec_cipher.get_output_size(offset))
        dec_offset = 0
        
        # Process in different chunks: 15, 20, 13 bytes
        dec_offset += dec_cipher.process_bytes(bytes(ciphertext), 0, 15, decrypted, dec_offset)
        dec_offset += dec_cipher.process_bytes(bytes(ciphertext), 15, 20, decrypted, dec_offset)
        dec_offset += dec_cipher.process_bytes(bytes(ciphertext), 35, 13, decrypted, dec_offset)
        dec_offset += dec_cipher.do_final(decrypted, dec_offset)
        
        assert dec_offset == 32
        assert bytes(decrypted[:32]) == plaintext


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
