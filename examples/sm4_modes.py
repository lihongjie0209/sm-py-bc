#!/usr/bin/env python3
"""
SM4 多种工作模式示例

演示：
1. ECB 模式（电子密码本）
2. CBC 模式（密码块链接）
3. CTR 模式（计数器）
4. GCM 模式（伽罗瓦/计数器）

使用底层 API 直接控制加密模式和填充
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from sm_bc.crypto.engines import SM4Engine
from sm_bc.crypto.modes import ECBBlockCipher, CBCBlockCipher, SICBlockCipher, GCMBlockCipher
from sm_bc.crypto.paddings import PKCS7Padding
from sm_bc.crypto.cipher import PaddedBufferedBlockCipher
from sm_bc.crypto.params import KeyParameter, ParametersWithIV, AEADParameters

print('=== SM4 多种工作模式示例 ===\n')

# 准备测试数据
key = bytes([i for i in range(16)])

plaintext = 'Hello, SM4 modes! 你好，SM4！'.encode('utf-8')
print('明文:', plaintext.decode('utf-8'))
print('明文长度:', len(plaintext), '字节')
print()

# ========== ECB 模式 ==========
print('--- 1. ECB 模式（不推荐用于生产）---')
try:
    ecb_cipher = PaddedBufferedBlockCipher(
        ECBBlockCipher(SM4Engine()),
        PKCS7Padding()
    )
    
    # 加密
    ecb_cipher.init(True, KeyParameter(key))
    ecb_output = bytearray(ecb_cipher.get_output_size(len(plaintext)))
    ecb_len = ecb_cipher.process_bytes(plaintext, 0, len(plaintext), ecb_output, 0)
    ecb_len += ecb_cipher.do_final(ecb_output, ecb_len)
    ecb_ciphertext = bytes(ecb_output[:ecb_len])
    
    print('ECB 密文长度:', len(ecb_ciphertext), '字节')
    print('ECB 密文 (hex):', ecb_ciphertext.hex()[:64] + '...')
    
    # 解密
    ecb_cipher.init(False, KeyParameter(key))
    ecb_decrypted = bytearray(ecb_cipher.get_output_size(len(ecb_ciphertext)))
    ecb_dec_len = ecb_cipher.process_bytes(ecb_ciphertext, 0, len(ecb_ciphertext), ecb_decrypted, 0)
    ecb_dec_len += ecb_cipher.do_final(ecb_decrypted, ecb_dec_len)
    
    print('ECB 解密:', bytes(ecb_decrypted[:ecb_dec_len]).decode('utf-8'))
    print('ECB 验证: ✅')
except Exception as error:
    print('ECB 模式错误:', str(error))
print()

# ========== CBC 模式 ==========
print('--- 2. CBC 模式（推荐） ---')
try:
    iv = bytes([i * 2 for i in range(16)])
    
    cbc_cipher = PaddedBufferedBlockCipher(
        CBCBlockCipher(SM4Engine()),
        PKCS7Padding()
    )
    
    # 加密
    cbc_cipher.init(True, ParametersWithIV(KeyParameter(key), iv))
    cbc_output = bytearray(cbc_cipher.get_output_size(len(plaintext)))
    cbc_len = cbc_cipher.process_bytes(plaintext, 0, len(plaintext), cbc_output, 0)
    cbc_len += cbc_cipher.do_final(cbc_output, cbc_len)
    cbc_ciphertext = bytes(cbc_output[:cbc_len])
    
    print('CBC 密文长度:', len(cbc_ciphertext), '字节')
    print('CBC 密文 (hex):', cbc_ciphertext.hex()[:64] + '...')
    
    # 解密
    cbc_cipher.init(False, ParametersWithIV(KeyParameter(key), iv))
    cbc_decrypted = bytearray(cbc_cipher.get_output_size(len(cbc_ciphertext)))
    cbc_dec_len = cbc_cipher.process_bytes(cbc_ciphertext, 0, len(cbc_ciphertext), cbc_decrypted, 0)
    cbc_dec_len += cbc_cipher.do_final(cbc_decrypted, cbc_dec_len)
    
    print('CBC 解密:', bytes(cbc_decrypted[:cbc_dec_len]).decode('utf-8'))
    print('CBC 验证: ✅')
except Exception as error:
    print('CBC 模式错误:', str(error))
print()

# ========== CTR 模式 ==========
print('--- 3. CTR 模式（流密码）---')
try:
    ctr_iv = bytes([0xFF - i for i in range(16)])
    
    ctr_cipher = SICBlockCipher(SM4Engine())
    
    # 加密
    ctr_cipher.init(True, ParametersWithIV(KeyParameter(key), ctr_iv))
    ctr_ciphertext = bytearray(len(plaintext))
    ctr_cipher.process_bytes(plaintext, 0, len(plaintext), ctr_ciphertext, 0)
    
    print('CTR 密文长度:', len(ctr_ciphertext), '字节 (无填充)')
    print('CTR 密文 (hex):', bytes(ctr_ciphertext).hex()[:64] + '...')
    
    # 解密
    ctr_cipher.init(False, ParametersWithIV(KeyParameter(key), ctr_iv))
    ctr_decrypted = bytearray(len(ctr_ciphertext))
    ctr_cipher.process_bytes(ctr_ciphertext, 0, len(ctr_ciphertext), ctr_decrypted, 0)
    
    print('CTR 解密:', bytes(ctr_decrypted).decode('utf-8'))
    print('CTR 验证: ✅')
except Exception as error:
    print('CTR 模式错误:', str(error))
print()

# ========== GCM 模式 ==========
print('--- 4. GCM 模式（认证加密）---')
try:
    gcm_nonce = bytes([i + 100 for i in range(12)])
    
    gcm_cipher = GCMBlockCipher(SM4Engine())
    
    # 加密
    mac_size = 128  # 128位认证标签
    gcm_cipher.init(True, AEADParameters(KeyParameter(key), mac_size, gcm_nonce, None))
    
    gcm_output = bytearray(gcm_cipher.get_output_size(len(plaintext)))
    gcm_len = gcm_cipher.process_bytes(plaintext, 0, len(plaintext), gcm_output, 0)
    gcm_len += gcm_cipher.do_final(gcm_output, gcm_len)
    gcm_ciphertext = bytes(gcm_output[:gcm_len])
    
    print('GCM 密文长度:', len(gcm_ciphertext), '字节 (含16字节MAC标签)')
    print('GCM 密文 (hex):', gcm_ciphertext.hex()[:64] + '...')
    
    # 解密
    gcm_cipher.init(False, AEADParameters(KeyParameter(key), mac_size, gcm_nonce, None))
    gcm_decrypted = bytearray(gcm_cipher.get_output_size(len(gcm_ciphertext)))
    gcm_dec_len = gcm_cipher.process_bytes(gcm_ciphertext, 0, len(gcm_ciphertext), gcm_decrypted, 0)
    gcm_dec_len += gcm_cipher.do_final(gcm_decrypted, gcm_dec_len)
    
    print('GCM 解密:', bytes(gcm_decrypted[:gcm_dec_len]).decode('utf-8'))
    print('GCM 验证: ✅ (含认证标签验证)')
except Exception as error:
    print('GCM 模式错误:', str(error))
print()

print('✅ SM4 多种工作模式示例运行完成')
print()
print('📌 模式选择建议：')
print('   • ECB: ❌ 不安全，仅用于兼容性测试')
print('   • CBC: ✅ 传统选择，需要正确处理 IV')
print('   • CTR: ✅ 流密码模式，可并行，无填充')
print('   • GCM: ⭐ 最佳选择，提供认证加密（AEAD）')
