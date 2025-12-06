"""
Comprehensive SM4 Encryption Demo

This demo showcases the high-level SM4Cipher interface with various
cipher modes and padding schemes.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sm_bc.crypto.cipher import create_sm4_cipher
import secrets


def print_section(title: str):
    """Print a formatted section header."""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print('=' * 70)


def print_hex(label: str, data: bytes, max_len: int = 32):
    """Print data in hex format."""
    hex_str = data.hex()
    if len(hex_str) > max_len * 2:
        hex_str = hex_str[:max_len*2] + f"... ({len(data)} bytes total)"
    print(f"{label}: {hex_str}")


def demo_cipher_mode(mode: str, padding: str, plaintext: bytes, key: bytes, iv: bytes = None):
    """Demonstrate a specific cipher mode and padding combination."""
    print(f"\n--- {mode} mode with {padding} padding ---")
    
    try:
        # Create cipher
        cipher = create_sm4_cipher(mode=mode, padding=padding)
        print(f"Algorithm: {cipher.get_algorithm_name()}")
        
        # Encrypt
        cipher.init(True, key, iv)
        ciphertext = cipher.encrypt(plaintext)
        print_hex("Plaintext ", plaintext)
        print_hex("Ciphertext", ciphertext)
        
        # Decrypt
        cipher.init(False, key, iv)
        decrypted = cipher.decrypt(ciphertext)
        print_hex("Decrypted ", decrypted)
        
        # Verify
        if bytes(decrypted) == plaintext:
            print("[OK] Encryption/Decryption successful!")
        else:
            print("[FAIL] Decryption failed - mismatch!")
        
        return True
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def main():
    """Run comprehensive SM4 encryption demo."""
    
    print_section("SM4 Comprehensive Encryption Demo")
    print("Demonstrating high-level cipher interface with multiple modes and paddings")
    
    # Generate test data
    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    
    print_hex("\nGenerated Key", key)
    print_hex("Generated IV ", iv)
    
    # Test messages of various lengths
    messages = {
        "Short": b"Hello, SM4!",
        "Medium": b"This is a longer message to test SM4 encryption with various modes.",
        "Block-aligned": b"ExactlyOneBlock!",  # 16 bytes
    }
    
    # Test different cipher modes
    print_section("1. CBC Mode (Cipher Block Chaining)")
    print("Each block depends on previous block - same plaintext produces different ciphertext")
    
    for name, msg in messages.items():
        print(f"\n{name} message ({len(msg)} bytes):")
        demo_cipher_mode('CBC', 'PKCS7', msg, key, iv)
    
    print_section("2. CTR Mode (Counter Mode / Stream Cipher)")
    print("Converts block cipher into stream cipher - can encrypt any length")
    
    for name, msg in messages.items():
        print(f"\n{name} message ({len(msg)} bytes):")
        demo_cipher_mode('CTR', 'NONE', msg, key, iv)
    
    print_section("3. OFB Mode (Output Feedback)")
    print("Stream cipher mode - encryption and decryption use same operation")
    
    demo_cipher_mode('OFB', 'NONE', messages['Medium'], key, iv)
    
    print_section("4. CFB Mode (Cipher Feedback)")
    print("Self-synchronizing stream cipher - errors don't propagate indefinitely")
    
    demo_cipher_mode('CFB', 'NONE', messages['Medium'], key, iv)
    
    print_section("5. Different Padding Schemes Comparison")
    print("Comparing different padding schemes with CBC mode")
    
    test_msg = b"Padding test!"
    paddings = ['PKCS7', 'ISO7816-4', 'ISO10126', 'ZERO']
    
    for padding in paddings:
        demo_cipher_mode('CBC', padding, test_msg, key, iv)
    
    print_section("6. ECB Mode (Electronic Codebook) - Not Recommended")
    print("[WARN]  Warning: ECB mode is insecure for most applications!")
    print("Same plaintext block always produces same ciphertext block")
    
    # Demonstrate ECB weakness
    repeated_msg = b"AAAAAAAAAAAAAAAA" * 2  # Two identical blocks
    cipher = create_sm4_cipher(mode='ECB', padding='NONE')
    cipher.init(True, key)
    ciphertext = cipher.encrypt(repeated_msg)
    
    print_hex("Plaintext ", repeated_msg)
    print_hex("Ciphertext", ciphertext)
    print("Notice: First 16 bytes == Second 16 bytes (ECB weakness)")
    print(f"Block 1: {ciphertext[:16].hex()}")
    print(f"Block 2: {ciphertext[16:32].hex()}")
    if ciphertext[:16] == ciphertext[16:32]:
        print("[WARN]  Identical blocks reveal plaintext patterns!")
    
    print_section("7. Practical Use Case: File Encryption Simulation")
    
    # Simulate encrypting a "file"
    file_data = b"This is sensitive file content that needs to be encrypted securely."
    file_key = secrets.token_bytes(16)
    file_iv = secrets.token_bytes(16)
    
    print("Scenario: Encrypting sensitive file data")
    print_hex("File data", file_data)
    
    # Use recommended settings: CBC + PKCS7
    cipher = create_sm4_cipher(mode='CBC', padding='PKCS7')
    cipher.init(True, file_key, file_iv)
    encrypted_file = cipher.encrypt(file_data)
    
    print(f"\n[OK] File encrypted: {len(encrypted_file)} bytes")
    print_hex("Encrypted", encrypted_file)
    
    # Decrypt
    cipher.init(False, file_key, file_iv)
    decrypted_file = cipher.decrypt(encrypted_file)
    
    print(f"\n[OK] File decrypted: {len(decrypted_file)} bytes")
    print_hex("Decrypted", decrypted_file)
    
    if bytes(decrypted_file) == file_data:
        print("\n[OK] File integrity verified!")
    
    print_section("Summary and Recommendations")
    print("""
    [OK] RECOMMENDED for most use cases:
       • CBC mode with PKCS#7 padding
       • CTR mode for streaming/arbitrary lengths
       • OFB mode for streaming with simpler structure
    
    [WARN]  USE WITH CAUTION:
       • CFB mode (more complex, use only if needed)
       • ECB mode (INSECURE - DO NOT USE for real data)
    
    [SECURITY] SECURITY TIPS:
       • Always use unique IV for each message
       • Never reuse key+IV combination
       • Consider authenticated encryption (GCM) when available
       • Store keys securely, never hardcode
       • Use PKCS#7 padding as default
    
    [PERFORMANCE] PERFORMANCE:
       • CTR/OFB/CFB: Slightly faster (stream-based)
       • CBC: Good balance of security and performance
       • ECB: Fastest but INSECURE
    """)
    
    print_section("Demo Complete!")
    print("The high-level SM4Cipher interface makes encryption easy and safe.")


if __name__ == '__main__':
    main()
