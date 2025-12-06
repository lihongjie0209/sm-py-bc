"""Simple GCM mode test."""

import sys
sys.path.insert(0, 'src')

from sm_bc.crypto.engines.sm4_engine import SM4Engine
from sm_bc.crypto.modes.gcm_block_cipher import GCMBlockCipher
from sm_bc.crypto.params.key_parameter import KeyParameter
from sm_bc.crypto.params.aead_parameters import AEADParameters

def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str.replace(' ', ''))

def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex().upper()

# Test vectors
key = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
nonce = hex_to_bytes("00001234567800000000ABCD")
plaintext = hex_to_bytes("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA")
aad = hex_to_bytes("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")

print("=== SM4-GCM Test ===")
print(f"Key:       {bytes_to_hex(key)}")
print(f"Nonce:     {bytes_to_hex(nonce)}")
print(f"Plaintext: {bytes_to_hex(plaintext)}")
print(f"AAD:       {bytes_to_hex(aad)}")
print()

# Encryption
cipher = GCMBlockCipher(SM4Engine())
params = AEADParameters(KeyParameter(key), 128, nonce, aad)
cipher.init(True, params)

output = bytearray(cipher.get_output_size(len(plaintext)))
out_off = cipher.process_bytes(plaintext, 0, len(plaintext), output, 0)
out_off += cipher.do_final(output, out_off)

ciphertext = bytes(output[:out_off - 16])
tag = bytes(output[out_off - 16:out_off])

print(f"Ciphertext: {bytes_to_hex(ciphertext)}")
print(f"Tag:        {bytes_to_hex(tag)}")
print()

# Decryption
cipher2 = GCMBlockCipher(SM4Engine())
cipher2.init(False, params)

decrypted = bytearray(cipher2.get_output_size(len(output)))
dec_off = cipher2.process_bytes(output, 0, len(output), decrypted, 0)
dec_off += cipher2.do_final(decrypted, dec_off)

decrypted_text = bytes(decrypted[:dec_off])
print(f"Decrypted:  {bytes_to_hex(decrypted_text)}")
print(f"Match: {decrypted_text == plaintext}")
