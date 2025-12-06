#!/usr/bin/env python3
"""
SM4 ECB 模式简单示例

演示：
1. 生成随机密钥
2. ECB 模式加密/解密（PKCS7 填充）
3. 处理不同长度的数据

注意：ECB 模式不安全，仅用于演示和兼容性测试
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from sm_bc.crypto.engines import SM4Engine
from sm_bc.crypto.modes import ECBBlockCipher
from sm_bc.crypto.paddings import PKCS7Padding
from sm_bc.crypto.cipher import PaddedBufferedBlockCipher
from sm_bc.crypto.params import KeyParameter
import secrets

print('=== SM4 ECB 模式简单示例 ===\n')

# 1. 生成随机密钥
print('--- 1. 生成密钥 ---')
key = secrets.token_bytes(16)
print('密钥长度:', len(key), '字节 (128位)')
print('密钥 (hex):', key.hex())
print()

# 2. 加密和解密
print('--- 2. 加密/解密 ---')
plaintext = 'Hello, SM4! 这是一个测试消息。'
plaintext_bytes = plaintext.encode('utf-8')

print('明文:', plaintext)
print('明文长度:', len(plaintext_bytes), '字节')

# 加密（ECB + PKCS7 填充）
cipher = PaddedBufferedBlockCipher(
    ECBBlockCipher(SM4Engine()),
    PKCS7Padding()
)
cipher.init(True, KeyParameter(key))

output = bytearray(cipher.get_output_size(len(plaintext_bytes)))
length = cipher.process_bytes(plaintext_bytes, 0, len(plaintext_bytes), output, 0)
length += cipher.do_final(output, length)
ciphertext = bytes(output[:length])

print('密文长度:', len(ciphertext), '字节')
print('密文 (hex):', ciphertext.hex())

# 解密
cipher.init(False, KeyParameter(key))
decrypted = bytearray(cipher.get_output_size(len(ciphertext)))
dec_len = cipher.process_bytes(ciphertext, 0, len(ciphertext), decrypted, 0)
dec_len += cipher.do_final(decrypted, dec_len)
decrypted_text = bytes(decrypted[:dec_len]).decode('utf-8')

print('解密结果:', decrypted_text)
print('解密成功:', '✅' if decrypted_text == plaintext else '❌')
print()

# 3. 不同长度的数据
print('--- 3. 不同长度数据 ---')
test_cases = [
    ('空数据', ''),
    ('1 字节', 'A'),
    ('15 字节', 'A' * 15),
    ('16 字节 (1块)', 'A' * 16),
    ('17 字节', 'A' * 17),
    ('32 字节 (2块)', 'A' * 32),
    ('100 字节', 'A' * 100),
]

for name, data in test_cases:
    data_bytes = data.encode('utf-8')
    
    # 加密
    cipher.init(True, KeyParameter(key))
    enc_out = bytearray(cipher.get_output_size(len(data_bytes)))
    enc_len = cipher.process_bytes(data_bytes, 0, len(data_bytes), enc_out, 0)
    enc_len += cipher.do_final(enc_out, enc_len)
    encrypted = bytes(enc_out[:enc_len])
    
    # 解密
    cipher.init(False, KeyParameter(key))
    dec_out = bytearray(cipher.get_output_size(len(encrypted)))
    dec_len = cipher.process_bytes(encrypted, 0, len(encrypted), dec_out, 0)
    dec_len += cipher.do_final(dec_out, dec_len)
    decrypted_data = bytes(dec_out[:dec_len])
    
    success = data_bytes == decrypted_data
    print(f'{name}: {len(data_bytes)} → {len(encrypted)} 字节 {"✅" if success else "❌"}')
print()

# 4. 单块加密（无填充）
print('--- 4. 单块加密（16字节，无填充）---')
block = bytes([0x42] * 16)  # 16 字节的 'B'
print('块数据 (hex):', block.hex())

engine = SM4Engine()
engine.init(True, KeyParameter(key))
encrypted_block = bytearray(16)
engine.process_block(block, 0, encrypted_block, 0)

print('加密后 (hex):', bytes(encrypted_block).hex())

engine.init(False, KeyParameter(key))
decrypted_block = bytearray(16)
engine.process_block(encrypted_block, 0, decrypted_block, 0)

print('解密后 (hex):', bytes(decrypted_block).hex())
print('块加密成功:', '✅' if block == bytes(decrypted_block) else '❌')
print()

print('✅ SM4 ECB 模式示例运行完成')
print()
print('⚠️  安全提示：')
print('   ECB 模式不提供语义安全性，相同明文块产生相同密文块')
print('   仅用于演示和兼容性测试，生产环境请使用 CBC、CTR 或 GCM 模式')
