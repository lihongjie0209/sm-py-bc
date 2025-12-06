"""
SM2Engine unit tests.

Reference: test/unit/crypto/SM2Engine.test.ts (sm-js-bc)
"""

import pytest
from sm_bc.crypto.engines.sm2_engine import SM2Engine, SM2Mode
from sm_bc.crypto.params.ec_public_key_parameters import ECPublicKeyParameters
from sm_bc.crypto.params.ec_private_key_parameters import ECPrivateKeyParameters
from sm_bc.crypto.params.parameters_with_random import ParametersWithRandom
from sm_bc.crypto.params.ec_domain_parameters import ECDomainParameters
from sm_bc.util.secure_random import SecureRandom
from sm_bc.util.big_integers import BigIntegers
from sm_bc.exceptions import DataLengthException, InvalidCipherTextException


# SM2 domain parameters (same as SM2.ts)
def get_sm2_parameters():
    """Get SM2 domain parameters."""
    from sm_bc.math.ec_curve import Fp as FpCurve
    
    # SM2 parameters from GM/T 0003-2012
    p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    h = 1
    
    curve = FpCurve(p, a, b, n, h)
    
    gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    
    g = curve.create_point(gx, gy)
    
    return ECDomainParameters(curve, g, n, h)


def generate_key_pair():
    """Generate test key pair with fixed private key."""
    domain_params = get_sm2_parameters()
    n = domain_params.n
    g = domain_params.g
    
    # Fixed private key for testing
    d = 0x128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263
    
    # Calculate public key Q = dG
    q = g.multiply(d).normalize()
    
    return {
        'private_key': ECPrivateKeyParameters(d, domain_params),
        'public_key': ECPublicKeyParameters(q, domain_params)
    }


def generate_random_key_pair():
    """Generate random key pair."""
    domain_params = get_sm2_parameters()
    n = domain_params.n
    g = domain_params.g
    
    random = SecureRandom()
    while True:
        d = BigIntegers.create_random_big_integer(256, random)
        if d != 0 and d < n:
            break
    
    q = g.multiply(d).normalize()
    
    return {
        'private_key': ECPrivateKeyParameters(d, domain_params),
        'public_key': ECPublicKeyParameters(q, domain_params)
    }


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


class TestSM2EngineBasic:
    """Basic encryption/decryption tests."""
    
    def test_encrypt_decrypt_c1c2c3_mode(self):
        """Should encrypt and decrypt short message in C1C2C3 mode."""
        key_pair = generate_key_pair()
        message = b'Hello SM2!'
        
        # Encrypt
        encrypt_engine = SM2Engine(mode=SM2Mode.C1C2C3)
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        encrypt_engine.init(True, encrypt_params)
        ciphertext = encrypt_engine.process_block(message, 0, len(message))
        
        # Decrypt
        decrypt_engine = SM2Engine(mode=SM2Mode.C1C2C3)
        decrypt_engine.init(False, key_pair['private_key'])
        decrypted = decrypt_engine.process_block(ciphertext, 0, len(ciphertext))
        
        assert bytes_to_hex(decrypted) == bytes_to_hex(message)
        assert decrypted.decode('utf-8') == 'Hello SM2!'
    
    def test_encrypt_decrypt_c1c3c2_mode(self):
        """Should encrypt and decrypt short message in C1C3C2 mode."""
        key_pair = generate_key_pair()
        message = b'Hello SM2!'
        
        # Encrypt
        encrypt_engine = SM2Engine(mode=SM2Mode.C1C3C2)
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        encrypt_engine.init(True, encrypt_params)
        ciphertext = encrypt_engine.process_block(message, 0, len(message))
        
        # Decrypt
        decrypt_engine = SM2Engine(mode=SM2Mode.C1C3C2)
        decrypt_engine.init(False, key_pair['private_key'])
        decrypted = decrypt_engine.process_block(ciphertext, 0, len(ciphertext))
        
        assert bytes_to_hex(decrypted) == bytes_to_hex(message)
        assert decrypted.decode('utf-8') == 'Hello SM2!'
    
    def test_handle_empty_message(self):
        """Should throw DataLengthException for empty message."""
        key_pair = generate_key_pair()
        message = b''
        
        encrypt_engine = SM2Engine()
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        encrypt_engine.init(True, encrypt_params)
        
        with pytest.raises(DataLengthException):
            encrypt_engine.process_block(message, 0, len(message))
    
    def test_handle_single_byte(self):
        """Should handle single byte message."""
        key_pair = generate_key_pair()
        message = bytes([0x42])
        
        encrypt_engine = SM2Engine()
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        encrypt_engine.init(True, encrypt_params)
        ciphertext = encrypt_engine.process_block(message, 0, len(message))
        
        decrypt_engine = SM2Engine()
        decrypt_engine.init(False, key_pair['private_key'])
        decrypted = decrypt_engine.process_block(ciphertext, 0, len(ciphertext))
        
        assert bytes_to_hex(decrypted) == bytes_to_hex(message)


class TestSM2EngineDifferentLengths:
    """Test different message lengths."""
    
    @pytest.mark.parametrize("length", [1, 16, 32, 63, 64, 65, 100, 256])
    def test_various_lengths(self, length):
        """Should encrypt and decrypt messages of various lengths."""
        key_pair = generate_key_pair()
        message = bytearray(length)
        for i in range(length):
            message[i] = i & 0xff
        
        encrypt_engine = SM2Engine()
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        encrypt_engine.init(True, encrypt_params)
        ciphertext = encrypt_engine.process_block(message, 0, len(message))
        
        decrypt_engine = SM2Engine()
        decrypt_engine.init(False, key_pair['private_key'])
        decrypted = decrypt_engine.process_block(ciphertext, 0, len(ciphertext))
        
        assert bytes_to_hex(decrypted) == bytes_to_hex(message)


class TestSM2EngineModeCompatibility:
    """Test mode compatibility."""
    
    def test_c1c2c3_cannot_decrypt_c1c3c2(self):
        """Should not decrypt C1C2C3 ciphertext with C1C3C2 mode."""
        key_pair = generate_key_pair()
        message = b'Test message'
        
        # Encrypt with C1C2C3 mode
        encrypt_engine = SM2Engine(mode=SM2Mode.C1C2C3)
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        encrypt_engine.init(True, encrypt_params)
        ciphertext = encrypt_engine.process_block(message, 0, len(message))
        
        # Try to decrypt with C1C3C2 mode (should fail)
        decrypt_engine = SM2Engine(mode=SM2Mode.C1C3C2)
        decrypt_engine.init(False, key_pair['private_key'])
        
        with pytest.raises(InvalidCipherTextException):
            decrypt_engine.process_block(ciphertext, 0, len(ciphertext))
    
    def test_c1c3c2_cannot_decrypt_c1c2c3(self):
        """Should not decrypt C1C3C2 ciphertext with C1C2C3 mode."""
        key_pair = generate_key_pair()
        message = b'Test message'
        
        # Encrypt with C1C3C2 mode
        encrypt_engine = SM2Engine(mode=SM2Mode.C1C3C2)
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        encrypt_engine.init(True, encrypt_params)
        ciphertext = encrypt_engine.process_block(message, 0, len(message))
        
        # Try to decrypt with C1C2C3 mode (should fail)
        decrypt_engine = SM2Engine(mode=SM2Mode.C1C2C3)
        decrypt_engine.init(False, key_pair['private_key'])
        
        with pytest.raises(InvalidCipherTextException):
            decrypt_engine.process_block(ciphertext, 0, len(ciphertext))


class TestSM2EngineOutputSize:
    """Test output size calculation."""
    
    def test_calculate_correct_output_size(self):
        """Should calculate correct output size."""
        key_pair = generate_key_pair()
        engine = SM2Engine()
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        engine.init(True, encrypt_params)
        
        input_lengths = [0, 1, 16, 32, 64, 100, 256]
        
        for input_len in input_lengths:
            expected_size = (1 + 2 * 32) + input_len + 32  # C1(65) + message + C3(32)
            assert engine.get_output_size(input_len) == expected_size


class TestSM2EngineCiphertextStructure:
    """Test ciphertext structure."""
    
    def test_c1c2c3_ciphertext_length(self):
        """Should produce ciphertext with correct length in C1C2C3 mode."""
        key_pair = generate_key_pair()
        message = b'Test'
        
        encrypt_engine = SM2Engine(mode=SM2Mode.C1C2C3)
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        encrypt_engine.init(True, encrypt_params)
        ciphertext = encrypt_engine.process_block(message, 0, len(message))
        
        # C1 (65 bytes: 0x04 + 32 bytes x + 32 bytes y) + C2 (message.length) + C3 (32 bytes)
        expected_length = 65 + len(message) + 32
        assert len(ciphertext) == expected_length
        
        # C1 should start with 0x04 (uncompressed point)
        assert ciphertext[0] == 0x04
    
    def test_c1c3c2_ciphertext_length(self):
        """Should produce ciphertext with correct length in C1C3C2 mode."""
        key_pair = generate_key_pair()
        message = b'Test'
        
        encrypt_engine = SM2Engine(mode=SM2Mode.C1C3C2)
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        encrypt_engine.init(True, encrypt_params)
        ciphertext = encrypt_engine.process_block(message, 0, len(message))
        
        # C1 (65 bytes) + C3 (32 bytes) + C2 (message.length)
        expected_length = 65 + 32 + len(message)
        assert len(ciphertext) == expected_length
        
        # C1 should start with 0x04
        assert ciphertext[0] == 0x04


class TestSM2EngineMultipleKeyPairs:
    """Test with multiple key pairs."""
    
    def test_different_key_pairs(self):
        """Should work with different key pairs."""
        message = b'Secret message'
        
        # Generate two different key pairs
        key_pair1 = generate_random_key_pair()
        key_pair2 = generate_random_key_pair()
        
        # Encrypt with key pair 1
        engine1 = SM2Engine()
        params1 = ParametersWithRandom(key_pair1['public_key'], SecureRandom())
        engine1.init(True, params1)
        ciphertext1 = engine1.process_block(message, 0, len(message))
        
        # Decrypt with key pair 1
        decrypt1 = SM2Engine()
        decrypt1.init(False, key_pair1['private_key'])
        decrypted1 = decrypt1.process_block(ciphertext1, 0, len(ciphertext1))
        assert decrypted1.decode('utf-8') == 'Secret message'
        
        # Cannot decrypt with key pair 2
        decrypt2 = SM2Engine()
        decrypt2.init(False, key_pair2['private_key'])
        with pytest.raises(InvalidCipherTextException):
            decrypt2.process_block(ciphertext1, 0, len(ciphertext1))


class TestSM2EngineRandomness:
    """Test randomness in encryption."""
    
    def test_different_ciphertexts_same_message(self):
        """Should produce different ciphertexts for same message."""
        key_pair = generate_key_pair()
        message = b'Same message'
        
        ciphertexts = []
        
        for _ in range(3):
            engine = SM2Engine()
            params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
            engine.init(True, params)
            ciphertext = engine.process_block(message, 0, len(message))
            ciphertexts.append(bytes_to_hex(ciphertext))
        
        # All ciphertexts should be different (due to random k)
        assert ciphertexts[0] != ciphertexts[1]
        assert ciphertexts[1] != ciphertexts[2]
        assert ciphertexts[0] != ciphertexts[2]
    
    def test_decrypt_all_random_ciphertexts(self):
        """Should decrypt all random ciphertexts to same message."""
        key_pair = generate_key_pair()
        message = b'Same message'
        
        for _ in range(5):
            encrypt_engine = SM2Engine()
            encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
            encrypt_engine.init(True, encrypt_params)
            ciphertext = encrypt_engine.process_block(message, 0, len(message))
            
            decrypt_engine = SM2Engine()
            decrypt_engine.init(False, key_pair['private_key'])
            decrypted = decrypt_engine.process_block(ciphertext, 0, len(ciphertext))
            
            assert decrypted.decode('utf-8') == 'Same message'


class TestSM2EngineErrorHandling:
    """Test error handling."""
    
    def test_corrupted_ciphertext(self):
        """Should throw on corrupted ciphertext."""
        key_pair = generate_key_pair()
        message = b'Test message'
        
        encrypt_engine = SM2Engine()
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        encrypt_engine.init(True, encrypt_params)
        ciphertext = bytearray(encrypt_engine.process_block(message, 0, len(message)))
        
        # Corrupt one byte in ciphertext
        ciphertext[-1] ^= 0x01
        
        decrypt_engine = SM2Engine()
        decrypt_engine.init(False, key_pair['private_key'])
        
        with pytest.raises(InvalidCipherTextException):
            decrypt_engine.process_block(ciphertext, 0, len(ciphertext))
    
    def test_truncated_ciphertext(self):
        """Should throw on truncated ciphertext."""
        key_pair = generate_key_pair()
        message = b'Test message'
        
        encrypt_engine = SM2Engine()
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        encrypt_engine.init(True, encrypt_params)
        ciphertext = encrypt_engine.process_block(message, 0, len(message))
        
        # Truncate ciphertext
        truncated = ciphertext[:-10]
        
        decrypt_engine = SM2Engine()
        decrypt_engine.init(False, key_pair['private_key'])
        
        with pytest.raises((InvalidCipherTextException, Exception)):
            decrypt_engine.process_block(truncated, 0, len(truncated))
    
    def test_invalid_buffer_length(self):
        """Should throw on invalid buffer length."""
        key_pair = generate_key_pair()
        message = bytearray(10)
        
        engine = SM2Engine()
        params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        engine.init(True, params)
        
        with pytest.raises(DataLengthException):
            engine.process_block(message, 0, 20)  # inLen > buffer
    
    def test_zero_length_input_decryption(self):
        """Should throw on zero-length input for decryption."""
        key_pair = generate_key_pair()
        message = b''
        
        engine = SM2Engine()
        engine.init(False, key_pair['private_key'])
        
        with pytest.raises(DataLengthException):
            engine.process_block(message, 0, 0)


class TestSM2EngineEdgeCases:
    """Test edge cases."""
    
    def test_message_all_zeros(self):
        """Should handle message with all zeros."""
        key_pair = generate_key_pair()
        message = bytearray(32)
        
        encrypt_engine = SM2Engine()
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        encrypt_engine.init(True, encrypt_params)
        ciphertext = encrypt_engine.process_block(message, 0, len(message))
        
        decrypt_engine = SM2Engine()
        decrypt_engine.init(False, key_pair['private_key'])
        decrypted = decrypt_engine.process_block(ciphertext, 0, len(ciphertext))
        
        assert bytes_to_hex(decrypted) == bytes_to_hex(message)
    
    def test_message_all_0xff(self):
        """Should handle message with all 0xFF."""
        key_pair = generate_key_pair()
        message = bytearray([0xFF] * 32)
        
        encrypt_engine = SM2Engine()
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        encrypt_engine.init(True, encrypt_params)
        ciphertext = encrypt_engine.process_block(message, 0, len(message))
        
        decrypt_engine = SM2Engine()
        decrypt_engine.init(False, key_pair['private_key'])
        decrypted = decrypt_engine.process_block(ciphertext, 0, len(ciphertext))
        
        assert bytes_to_hex(decrypted) == bytes_to_hex(message)
    
    def test_message_with_pattern(self):
        """Should handle message with pattern."""
        key_pair = generate_key_pair()
        message = bytearray(100)
        for i in range(len(message)):
            message[i] = (i * 7) & 0xff
        
        encrypt_engine = SM2Engine()
        encrypt_params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        encrypt_engine.init(True, encrypt_params)
        ciphertext = encrypt_engine.process_block(message, 0, len(message))
        
        decrypt_engine = SM2Engine()
        decrypt_engine.init(False, key_pair['private_key'])
        decrypted = decrypt_engine.process_block(ciphertext, 0, len(ciphertext))
        
        assert bytes_to_hex(decrypted) == bytes_to_hex(message)


class TestSM2EngineReusability:
    """Test engine reusability."""
    
    def test_multiple_encryptions_same_engine(self):
        """Should allow multiple encryptions with same engine."""
        key_pair = generate_key_pair()
        engine = SM2Engine()
        params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
        engine.init(True, params)
        
        messages = [
            b'First',
            b'Second',
            b'Third'
        ]
        
        for message in messages:
            ciphertext = engine.process_block(message, 0, len(message))
            
            decrypt_engine = SM2Engine()
            decrypt_engine.init(False, key_pair['private_key'])
            decrypted = decrypt_engine.process_block(ciphertext, 0, len(ciphertext))
            
            assert bytes_to_hex(decrypted) == bytes_to_hex(message)
    
    def test_multiple_decryptions_same_engine(self):
        """Should allow multiple decryptions with same engine."""
        key_pair = generate_key_pair()
        messages = [
            b'First',
            b'Second',
            b'Third'
        ]
        
        ciphertexts = []
        for message in messages:
            engine = SM2Engine()
            params = ParametersWithRandom(key_pair['public_key'], SecureRandom())
            engine.init(True, params)
            ciphertexts.append(engine.process_block(message, 0, len(message)))
        
        decrypt_engine = SM2Engine()
        decrypt_engine.init(False, key_pair['private_key'])
        
        for i, message in enumerate(messages):
            decrypted = decrypt_engine.process_block(ciphertexts[i], 0, len(ciphertexts[i]))
            assert bytes_to_hex(decrypted) == bytes_to_hex(message)
