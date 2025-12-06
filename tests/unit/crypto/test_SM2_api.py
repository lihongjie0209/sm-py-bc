"""
Unit tests for SM2 high-level API.
"""

import pytest
from sm_bc.crypto.SM2 import SM2


class TestSM2HighLevelAPI:
    """Test SM2 high-level convenience API."""
    
    def test_generate_key_pair(self):
        """Test key pair generation."""
        kp = SM2.generate_key_pair()
        
        assert 'private_key' in kp
        assert 'public_key' in kp
        assert 'x' in kp['public_key']
        assert 'y' in kp['public_key']
        
        # Validate private key
        assert SM2.validate_private_key(kp['private_key'])
        
        # Validate public key
        curve = SM2.get_curve()
        Q = curve.create_point(kp['public_key']['x'], kp['public_key']['y'])
        assert SM2.validate_public_key(Q)
    
    def test_encrypt_decrypt_with_dict_public_key(self):
        """Test encryption/decryption with dict public key."""
        # Generate key pair
        kp = SM2.generate_key_pair()
        
        # Test with string message
        plaintext = "Hello, SM2!"
        ciphertext = SM2.encrypt(plaintext, kp['public_key'])
        decrypted = SM2.decrypt(ciphertext, kp['private_key'])
        
        assert decrypted.decode('utf-8') == plaintext
    
    def test_encrypt_decrypt_with_separate_coordinates(self):
        """Test encryption/decryption with separate x, y coordinates."""
        # Generate key pair
        kp = SM2.generate_key_pair()
        
        # Test with bytes message
        plaintext = b"Test message"
        ciphertext = SM2.encrypt(plaintext, kp['public_key']['x'], kp['public_key']['y'])
        decrypted = SM2.decrypt(ciphertext, kp['private_key'])
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_bytes(self):
        """Test encryption/decryption with bytes."""
        kp = SM2.generate_key_pair()
        
        plaintext = b"Binary data: \x00\x01\x02\xff"
        ciphertext = SM2.encrypt(plaintext, kp['public_key'])
        decrypted = SM2.decrypt(ciphertext, kp['private_key'])
        
        assert decrypted == plaintext
    
    def test_sign_verify_with_dict_public_key(self):
        """Test signing/verification with dict public key."""
        # Generate key pair
        kp = SM2.generate_key_pair()
        
        # Test with string message
        message = "Sign this message"
        signature = SM2.sign(message, kp['private_key'])
        
        # Verify with correct key
        assert SM2.verify(message, signature, kp['public_key'])
        
        # Verify fails with wrong message
        assert not SM2.verify("Different message", signature, kp['public_key'])
    
    def test_sign_verify_with_separate_coordinates(self):
        """Test signing/verification with separate x, y coordinates."""
        # Generate key pair
        kp = SM2.generate_key_pair()
        
        # Test with bytes message
        message = b"Sign this data"
        signature = SM2.sign(message, kp['private_key'])
        
        # Verify with correct key
        assert SM2.verify(message, signature, kp['public_key']['x'], kp['public_key']['y'])
    
    def test_sign_verify_bytes(self):
        """Test signing/verification with bytes."""
        kp = SM2.generate_key_pair()
        
        message = b"Binary message: \x00\x01\x02\xff"
        signature = SM2.sign(message, kp['private_key'])
        
        assert SM2.verify(message, signature, kp['public_key'])
    
    def test_sign_verify_fails_with_wrong_key(self):
        """Test that verification fails with wrong public key."""
        # Generate two key pairs
        kp1 = SM2.generate_key_pair()
        kp2 = SM2.generate_key_pair()
        
        message = "Test message"
        signature = SM2.sign(message, kp1['private_key'])
        
        # Verify with wrong key should fail
        assert not SM2.verify(message, signature, kp2['public_key'])
    
    def test_parameters_access(self):
        """Test accessing SM2 parameters."""
        # Get curve
        curve = SM2.get_curve()
        assert curve is not None
        
        # Get base point
        G = SM2.get_G()
        assert G is not None
        assert not G.is_infinity
        
        # Get order
        n = SM2.get_n()
        assert n == SM2.n
        
        # Get cofactor
        h = SM2.get_h()
        assert h == 1
        
        # Get domain parameters
        params = SM2.get_parameters()
        assert params is not None
    
    def test_validate_private_key(self):
        """Test private key validation."""
        # Valid key
        assert SM2.validate_private_key(123456789)
        
        # Zero is invalid
        assert not SM2.validate_private_key(0)
        
        # >= n is invalid
        assert not SM2.validate_private_key(SM2.n)
        assert not SM2.validate_private_key(SM2.n + 1)
        
        # Negative is invalid
        assert not SM2.validate_private_key(-1)
    
    def test_validate_public_key(self):
        """Test public key validation."""
        # Generate valid key pair
        kp = SM2.generate_key_pair()
        curve = SM2.get_curve()
        Q = curve.create_point(kp['public_key']['x'], kp['public_key']['y'])
        
        # Valid key
        assert SM2.validate_public_key(Q)
        
        # Infinity is invalid
        infinity = curve.get_infinity()
        assert not SM2.validate_public_key(infinity)
    
    def test_invalid_public_key_format_encrypt(self):
        """Test encryption with invalid public key format."""
        with pytest.raises(ValueError, match="Invalid public key format"):
            SM2.encrypt("test", "invalid")
    
    def test_invalid_public_key_format_verify(self):
        """Test verification with invalid public key format."""
        with pytest.raises(ValueError, match="Invalid public key format"):
            SM2.verify("test", b"sig", "invalid")
    
    def test_multiple_encryptions_different_ciphertexts(self):
        """Test that multiple encryptions produce different ciphertexts (due to randomness)."""
        kp = SM2.generate_key_pair()
        plaintext = "Same message"
        
        c1 = SM2.encrypt(plaintext, kp['public_key'])
        c2 = SM2.encrypt(plaintext, kp['public_key'])
        
        # Ciphertexts should be different due to random k
        assert c1 != c2
        
        # But both should decrypt to same plaintext
        assert SM2.decrypt(c1, kp['private_key']).decode('utf-8') == plaintext
        assert SM2.decrypt(c2, kp['private_key']).decode('utf-8') == plaintext
    
    def test_multiple_signatures_different(self):
        """Test that multiple signatures produce different signatures (due to randomness)."""
        kp = SM2.generate_key_pair()
        message = "Same message"
        
        s1 = SM2.sign(message, kp['private_key'])
        s2 = SM2.sign(message, kp['private_key'])
        
        # Signatures should be different due to random k
        assert s1 != s2
        
        # But both should verify
        assert SM2.verify(message, s1, kp['public_key'])
        assert SM2.verify(message, s2, kp['public_key'])
    
    def test_long_message_encryption(self):
        """Test encryption/decryption with longer messages."""
        kp = SM2.generate_key_pair()
        
        # Long message
        plaintext = "A" * 1000
        ciphertext = SM2.encrypt(plaintext, kp['public_key'])
        decrypted = SM2.decrypt(ciphertext, kp['private_key'])
        
        assert decrypted.decode('utf-8') == plaintext
    
    def test_long_message_signing(self):
        """Test signing/verification with longer messages."""
        kp = SM2.generate_key_pair()
        
        # Long message
        message = "B" * 1000
        signature = SM2.sign(message, kp['private_key'])
        
        assert SM2.verify(message, signature, kp['public_key'])
    
    def test_single_byte_message_encryption(self):
        """Test encryption/decryption with single byte message."""
        kp = SM2.generate_key_pair()
        
        plaintext = b"A"
        ciphertext = SM2.encrypt(plaintext, kp['public_key'])
        decrypted = SM2.decrypt(ciphertext, kp['private_key'])
        
        assert decrypted == plaintext
    
    def test_single_byte_message_signing(self):
        """Test signing/verification with single byte message."""
        kp = SM2.generate_key_pair()
        
        message = b"A"
        signature = SM2.sign(message, kp['private_key'])
        
        assert SM2.verify(message, signature, kp['public_key'])


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
