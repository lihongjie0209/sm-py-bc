"""
Simple File Encryption Tool using SM4

A practical example of using SM4 cipher for file encryption/decryption.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sm_bc.crypto.cipher import create_sm4_cipher
import secrets
import json


def derive_key_from_password(password: str) -> bytes:
    """
    Simple key derivation from password.
    
    NOTE: This is a SIMPLIFIED example for demonstration.
    In production, use proper KDF like PBKDF2, bcrypt, or Argon2.
    """
    # Simple hash-based derivation (NOT SECURE FOR PRODUCTION)
    from sm_bc.crypto.digests.sm3_digest import SM3Digest
    
    digest = SM3Digest()
    password_bytes = password.encode('utf-8')
    digest.update_bytes(password_bytes, 0, len(password_bytes))
    
    hash_output = bytearray(32)
    digest.do_final(hash_output, 0)
    
    # Use first 16 bytes as key
    return bytes(hash_output[:16])


def encrypt_file(input_path: str, output_path: str, password: str):
    """
    Encrypt a file using SM4-CBC with PKCS#7 padding.
    
    Args:
        input_path: Path to plaintext file
        output_path: Path to encrypted output file
        password: Password for encryption
    """
    print(f"\n[*] Encrypting file: {input_path}")
    
    # Read plaintext
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    print(f"[*] File size: {len(plaintext)} bytes")
    
    # Derive key from password
    key = derive_key_from_password(password)
    print(f"[*] Key derived from password")
    
    # Generate random IV
    iv = secrets.token_bytes(16)
    print(f"[*] Generated random IV: {iv.hex()}")
    
    # Create cipher
    cipher = create_sm4_cipher(mode='CBC', padding='PKCS7')
    cipher.init(True, key, iv)
    
    # Encrypt
    ciphertext = cipher.encrypt(plaintext)
    print(f"[*] Encrypted size: {len(ciphertext)} bytes")
    
    # Create metadata
    metadata = {
        'version': '1.0',
        'cipher': 'SM4/CBC/PKCS7',
        'iv': iv.hex(),
    }
    
    # Write encrypted file with metadata
    with open(output_path, 'wb') as f:
        # Write metadata as JSON header
        metadata_json = json.dumps(metadata).encode('utf-8')
        metadata_length = len(metadata_json)
        
        # Write: [4 bytes length][metadata JSON][ciphertext]
        f.write(metadata_length.to_bytes(4, 'big'))
        f.write(metadata_json)
        f.write(ciphertext)
    
    print(f"[OK] File encrypted successfully: {output_path}")
    print(f"[*] Total output size: {os.path.getsize(output_path)} bytes")


def decrypt_file(input_path: str, output_path: str, password: str):
    """
    Decrypt a file encrypted with encrypt_file.
    
    Args:
        input_path: Path to encrypted file
        output_path: Path to decrypted output file
        password: Password for decryption
    """
    print(f"\n[*] Decrypting file: {input_path}")
    
    # Read encrypted file
    with open(input_path, 'rb') as f:
        # Read metadata length
        metadata_length_bytes = f.read(4)
        if len(metadata_length_bytes) != 4:
            raise ValueError("Invalid encrypted file format")
        
        metadata_length = int.from_bytes(metadata_length_bytes, 'big')
        
        # Read metadata JSON
        metadata_json = f.read(metadata_length)
        metadata = json.loads(metadata_json.decode('utf-8'))
        
        # Read ciphertext
        ciphertext = f.read()
    
    print(f"[*] Encrypted size: {len(ciphertext)} bytes")
    print(f"[*] Cipher: {metadata['cipher']}")
    
    # Extract IV from metadata
    iv = bytes.fromhex(metadata['iv'])
    print(f"[*] IV from file: {iv.hex()}")
    
    # Derive key from password
    key = derive_key_from_password(password)
    print(f"[*] Key derived from password")
    
    # Create cipher
    cipher = create_sm4_cipher(mode='CBC', padding='PKCS7')
    cipher.init(False, key, iv)
    
    # Decrypt
    try:
        plaintext = cipher.decrypt(ciphertext)
        print(f"[*] Decrypted size: {len(plaintext)} bytes")
    except ValueError as e:
        print(f"[FAIL] Decryption failed: {e}")
        print("[*] Wrong password or corrupted file?")
        return False
    
    # Write plaintext
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    
    print(f"[OK] File decrypted successfully: {output_path}")
    return True


def demo_file_encryption():
    """Demonstrate file encryption/decryption."""
    
    print("=" * 70)
    print("  SM4 File Encryption Tool Demo")
    print("=" * 70)
    
    # Create temporary test file
    test_file = "test_plaintext.txt"
    encrypted_file = "test_encrypted.sm4"
    decrypted_file = "test_decrypted.txt"
    
    # Create test content
    test_content = b"""This is a test file for SM4 encryption.

    It contains multiple lines of text,
    including special characters: @#$%^&*()
    
    And some numbers: 1234567890
    
    This demonstrates that SM4 can encrypt any binary data,
    not just text files.
    """
    
    print("\n[*] Creating test file...")
    with open(test_file, 'wb') as f:
        f.write(test_content)
    print(f"[OK] Test file created: {test_file} ({len(test_content)} bytes)")
    
    # Encrypt
    password = "MySecretPassword123!"
    print(f"\n[*] Using password: {password}")
    
    try:
        encrypt_file(test_file, encrypted_file, password)
        
        # Decrypt with correct password
        print("\n" + "=" * 70)
        print("  Testing Decryption with CORRECT Password")
        print("=" * 70)
        
        decrypt_file(encrypted_file, decrypted_file, password)
        
        # Verify
        with open(decrypted_file, 'rb') as f:
            decrypted_content = f.read()
        
        if decrypted_content == test_content:
            print("\n[OK] Verification successful! Original and decrypted files match.")
        else:
            print("\n[FAIL] Verification failed! Files don't match.")
        
        # Try wrong password
        print("\n" + "=" * 70)
        print("  Testing Decryption with WRONG Password")
        print("=" * 70)
        
        wrong_password = "WrongPassword"
        print(f"[*] Using wrong password: {wrong_password}")
        
        wrong_decrypted = "test_wrong_decrypted.txt"
        success = decrypt_file(encrypted_file, wrong_decrypted, wrong_password)
        
        if not success:
            print("[OK] Correctly rejected wrong password!")
        
    finally:
        # Cleanup
        print("\n[*] Cleaning up temporary files...")
        for f in [test_file, encrypted_file, decrypted_file, "test_wrong_decrypted.txt"]:
            if os.path.exists(f):
                os.remove(f)
                print(f"[*] Removed: {f}")
    
    print("\n" + "=" * 70)
    print("  Demo Complete!")
    print("=" * 70)
    
    print("""
    Key Takeaways:
    
    [*] SM4-CBC with PKCS#7 provides secure file encryption
    [*] IV is randomly generated and stored with encrypted file
    [*] Metadata allows versioning and cipher information
    [*] Wrong password results in decryption failure
    
    IMPORTANT NOTES for Production Use:
    
    [WARN] This demo uses SIMPLIFIED key derivation
    [*] Use proper KDF (PBKDF2, Argon2) in production
    [*] Consider adding authentication (HMAC or GCM mode)
    [*] Implement key stretching (multiple iterations)
    [*] Store salt with encrypted file
    [*] Consider file integrity checks
    """)


if __name__ == '__main__':
    demo_file_encryption()
