"""
ZUC Stream Cipher and MAC Demonstration.

This example demonstrates the usage of ZUC-128, ZUC-256 stream ciphers
and their corresponding MAC algorithms (128-EIA3, 256-EIA3).

ZUC (祖冲之算法) is named after the ancient Chinese mathematician Zu Chongzhi (429-500 AD)
and is designed for 3GPP LTE/5G mobile communications.
"""

import secrets
from sm_bc.crypto.engines.zuc_engine import ZUCEngine
from sm_bc.crypto.engines.zuc256_engine import ZUC256Engine
from sm_bc.crypto.macs.zuc128_mac import ZUC128MAC
from sm_bc.crypto.macs.zuc256_mac import ZUC256MAC
from sm_bc.crypto.params.key_parameter import KeyParameter
from sm_bc.crypto.params.parameters_with_iv import ParametersWithIV


def print_section(title: str):
    """Print a section header."""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print('=' * 70)


def print_hex(label: str, data: bytes):
    """Print data in hex format."""
    print(f"{label}: {data.hex()}")


def demo_zuc128_encryption():
    """Demonstrate ZUC-128 stream cipher encryption."""
    print_section("ZUC-128 Stream Cipher Encryption")
    
    # Generate random key and IV
    key = secrets.token_bytes(16)  # 128-bit key
    iv = secrets.token_bytes(16)   # 128-bit IV
    
    print_hex("Key (128-bit)", key)
    print_hex("IV  (128-bit)", iv)
    
    # Create plaintext
    plaintext = b"Hello, ZUC-128! This is a confidential message for 3GPP LTE/5G."
    print(f"\nPlaintext: {plaintext.decode('utf-8')}")
    print(f"Length: {len(plaintext)} bytes")
    
    # Encrypt
    cipher = ZUCEngine()
    cipher.init(True, ParametersWithIV(KeyParameter(key), iv))
    ciphertext = bytearray(len(plaintext))
    cipher.process_bytes(plaintext, 0, len(plaintext), ciphertext, 0)
    
    print_hex("\nCiphertext", bytes(ciphertext))
    
    # Decrypt
    cipher.reset()
    decrypted = bytearray(len(ciphertext))
    cipher.process_bytes(ciphertext, 0, len(ciphertext), decrypted, 0)
    
    print(f"\nDecrypted: {bytes(decrypted).decode('utf-8')}")
    
    # Verify
    assert bytes(decrypted) == plaintext
    print("\n✅ Encryption/Decryption successful!")


def demo_zuc256_encryption():
    """Demonstrate ZUC-256 stream cipher encryption."""
    print_section("ZUC-256 Stream Cipher Encryption")
    
    # Generate random key and IV
    key = secrets.token_bytes(32)  # 256-bit key
    iv = secrets.token_bytes(23)   # 184-bit IV (can also use 25 bytes for 200-bit)
    
    print_hex("Key (256-bit)", key)
    print_hex("IV  (184-bit)", iv)
    
    # Create plaintext
    plaintext = b"Hello, ZUC-256! Enhanced security for 5G networks."
    print(f"\nPlaintext: {plaintext.decode('utf-8')}")
    print(f"Length: {len(plaintext)} bytes")
    
    # Encrypt with ZUC-256
    cipher = ZUC256Engine(mac_bits=128)
    cipher.init(True, ParametersWithIV(KeyParameter(key), iv))
    ciphertext = bytearray(len(plaintext))
    cipher.process_bytes(plaintext, 0, len(plaintext), ciphertext, 0)
    
    print_hex("\nCiphertext", bytes(ciphertext))
    
    # Decrypt
    cipher.reset()
    decrypted = bytearray(len(ciphertext))
    cipher.process_bytes(ciphertext, 0, len(ciphertext), decrypted, 0)
    
    print(f"\nDecrypted: {bytes(decrypted).decode('utf-8')}")
    
    # Verify
    assert bytes(decrypted) == plaintext
    print("\n✅ Encryption/Decryption successful!")


def demo_zuc128_mac():
    """Demonstrate ZUC-128 MAC (128-EIA3) for message integrity."""
    print_section("ZUC-128 MAC (128-EIA3) - Message Authentication")
    
    # Generate random key and IV
    key = secrets.token_bytes(16)  # 128-bit key
    iv = secrets.token_bytes(16)   # 128-bit IV
    
    print_hex("Key (128-bit)", key)
    print_hex("IV  (128-bit)", iv)
    
    # Create message
    message = b"This message integrity is protected by 128-EIA3 algorithm."
    print(f"\nMessage: {message.decode('utf-8')}")
    print(f"Length: {len(message)} bytes")
    
    # Generate 32-bit MAC
    print("\n--- 32-bit MAC ---")
    mac32 = ZUC128MAC(mac_bits=32)
    mac32.init(ParametersWithIV(KeyParameter(key), iv))
    mac32.update_bytes(message, 0, len(message))
    tag32 = bytearray(4)
    mac32.do_final(tag32, 0)
    print_hex("MAC (32-bit)", bytes(tag32))
    
    # Generate 64-bit MAC
    print("\n--- 64-bit MAC ---")
    mac64 = ZUC128MAC(mac_bits=64)
    mac64.init(ParametersWithIV(KeyParameter(key), iv))
    mac64.update_bytes(message, 0, len(message))
    tag64 = bytearray(8)
    mac64.do_final(tag64, 0)
    print_hex("MAC (64-bit)", bytes(tag64))
    
    # Verify MAC
    print("\n--- MAC Verification ---")
    mac_verify = ZUC128MAC(mac_bits=32)
    mac_verify.init(ParametersWithIV(KeyParameter(key), iv))
    mac_verify.update_bytes(message, 0, len(message))
    tag_verify = bytearray(4)
    mac_verify.do_final(tag_verify, 0)
    
    if bytes(tag_verify) == bytes(tag32):
        print("✅ MAC verification successful!")
    else:
        print("❌ MAC verification failed!")


def demo_zuc256_mac():
    """Demonstrate ZUC-256 MAC (256-EIA3) for enhanced message integrity."""
    print_section("ZUC-256 MAC (256-EIA3) - Enhanced Message Authentication")
    
    # Generate random key and IV
    key = secrets.token_bytes(32)  # 256-bit key
    iv = secrets.token_bytes(25)   # 200-bit IV (can also use 23 bytes for 184-bit)
    
    print_hex("Key (256-bit)", key)
    print_hex("IV  (200-bit)", iv)
    
    # Create message
    message = b"This message integrity is protected by 256-EIA3 algorithm with enhanced security."
    print(f"\nMessage: {message.decode('utf-8')}")
    print(f"Length: {len(message)} bytes")
    
    # Generate 64-bit MAC
    print("\n--- 64-bit MAC ---")
    mac64 = ZUC256MAC(mac_bits=64)
    mac64.init(ParametersWithIV(KeyParameter(key), iv))
    mac64.update_bytes(message, 0, len(message))
    tag64 = bytearray(8)
    mac64.do_final(tag64, 0)
    print_hex("MAC (64-bit)", bytes(tag64))
    
    # Generate 128-bit MAC
    print("\n--- 128-bit MAC ---")
    mac128 = ZUC256MAC(mac_bits=128)
    mac128.init(ParametersWithIV(KeyParameter(key), iv))
    mac128.update_bytes(message, 0, len(message))
    tag128 = bytearray(16)
    mac128.do_final(tag128, 0)
    print_hex("MAC (128-bit)", bytes(tag128))
    
    # Verify MAC
    print("\n--- MAC Verification ---")
    mac_verify = ZUC256MAC(mac_bits=128)
    mac_verify.init(ParametersWithIV(KeyParameter(key), iv))
    mac_verify.update_bytes(message, 0, len(message))
    tag_verify = bytearray(16)
    mac_verify.do_final(tag_verify, 0)
    
    if bytes(tag_verify) == bytes(tag128):
        print("✅ MAC verification successful!")
    else:
        print("❌ MAC verification failed!")


def demo_combined_encryption_and_mac():
    """Demonstrate combined encryption and MAC for confidentiality and integrity."""
    print_section("Combined Encryption + MAC (Confidentiality + Integrity)")
    
    # Generate keys and IVs (in practice, derive from same master key)
    enc_key = secrets.token_bytes(16)
    enc_iv = secrets.token_bytes(16)
    mac_key = secrets.token_bytes(16)
    mac_iv = secrets.token_bytes(16)
    
    print("--- Keys ---")
    print_hex("Encryption Key", enc_key)
    print_hex("Encryption IV ", enc_iv)
    print_hex("MAC Key       ", mac_key)
    print_hex("MAC IV        ", mac_iv)
    
    # Original message
    message = b"Confidential and integrity-protected message for secure communication."
    print(f"\n--- Original Message ---")
    print(f"Message: {message.decode('utf-8')}")
    
    # Step 1: Encrypt
    print("\n--- Step 1: Encryption ---")
    cipher = ZUCEngine()
    cipher.init(True, ParametersWithIV(KeyParameter(enc_key), enc_iv))
    ciphertext = bytearray(len(message))
    cipher.process_bytes(message, 0, len(message), ciphertext, 0)
    print_hex("Ciphertext", bytes(ciphertext))
    
    # Step 2: Generate MAC on ciphertext
    print("\n--- Step 2: MAC Generation ---")
    mac = ZUC128MAC(mac_bits=64)
    mac.init(ParametersWithIV(KeyParameter(mac_key), mac_iv))
    mac.update_bytes(ciphertext, 0, len(ciphertext))
    tag = bytearray(8)
    mac.do_final(tag, 0)
    print_hex("MAC Tag", bytes(tag))
    
    # Transmission: Send ciphertext + tag
    print("\n--- Transmission ---")
    print(f"Transmitted: {len(ciphertext)} bytes ciphertext + {len(tag)} bytes MAC")
    
    # Step 3: Verify MAC on received ciphertext
    print("\n--- Step 3: MAC Verification ---")
    mac_verify = ZUC128MAC(mac_bits=64)
    mac_verify.init(ParametersWithIV(KeyParameter(mac_key), mac_iv))
    mac_verify.update_bytes(ciphertext, 0, len(ciphertext))
    tag_verify = bytearray(8)
    mac_verify.do_final(tag_verify, 0)
    
    if bytes(tag_verify) == bytes(tag):
        print("✅ MAC verification successful! Message integrity confirmed.")
        
        # Step 4: Decrypt
        print("\n--- Step 4: Decryption ---")
        cipher.reset()
        decrypted = bytearray(len(ciphertext))
        cipher.process_bytes(ciphertext, 0, len(ciphertext), decrypted, 0)
        print(f"Decrypted: {bytes(decrypted).decode('utf-8')}")
        
        # Final verification
        assert bytes(decrypted) == message
        print("\n✅ Complete secure communication successful!")
    else:
        print("❌ MAC verification failed! Message may have been tampered!")


def main():
    """Run all ZUC demonstrations."""
    print("\n" + "=" * 70)
    print("  ZUC (祖冲之算法) Cryptography Demonstration")
    print("  SM-PY-BC - Pure Python Chinese Cryptography Library")
    print("=" * 70)
    
    # Run all demos
    demo_zuc128_encryption()
    demo_zuc256_encryption()
    demo_zuc128_mac()
    demo_zuc256_mac()
    demo_combined_encryption_and_mac()
    
    print("\n" + "=" * 70)
    print("  All demonstrations completed successfully! ✅")
    print("=" * 70 + "\n")


if __name__ == '__main__':
    main()
