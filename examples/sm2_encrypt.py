#!/usr/bin/env python3
"""
SM2 公钥加密示例
演示如何使用 SM2 进行加密和解密
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from sm_bc.crypto.engines import SM2Engine
from sm_bc.crypto.params.ec_key_parameters import ECPrivateKeyParameters, ECPublicKeyParameters
from sm_bc.math.ec.custom.sm2 import SM2P256V1Curve
import secrets

print('=== SM2 公钥加密示例 ===\n')

# 初始化曲线
curve = SM2P256V1Curve()

# 生成密钥对
print('步骤 1: 生成密钥对')
d = secrets.randbelow(curve.n)
Q = curve.G.multiply(d)

x_hex = hex(Q.get_affine_x_coord().to_big_integer())[2:]
d_hex = hex(d)[2:]
print('公钥 X:', x_hex[:32] + '...')
print('私钥:', d_hex[:32] + '...')

# 加密
print('\n步骤 2: 使用公钥加密消息')
plaintext = b'Secret message'
print('明文:', plaintext.decode('utf-8'))
print('明文长度:', len(plaintext), '字节')

engine = SM2Engine()
pub_params = ECPublicKeyParameters(Q, curve.domain_params)
engine.init(True, pub_params)
ciphertext = engine.process_block(plaintext, 0, len(plaintext))

print('密文:', bytes(ciphertext).hex())
print('密文长度:', len(ciphertext), '字节')

# 解密
print('\n步骤 3: 使用私钥解密消息')
priv_params = ECPrivateKeyParameters(d, curve.domain_params)
engine.init(False, priv_params)
decrypted = engine.process_block(ciphertext, 0, len(ciphertext))

print('解密结果:', bytes(decrypted).decode('utf-8'))
print('解密成功:', bytes(decrypted) == plaintext and '✅' or '❌')

# 加密不同长度的消息
print('\n步骤 4: 加密不同长度的消息')
test_messages = [
    b'A',                           # 1 字节
    b'Hello',                       # 5 字节
    b'This is a longer message for testing SM2 encryption!',  # 54 字节
    '中文消息测试'.encode('utf-8'),  # UTF-8 多字节字符
]

for idx, msg in enumerate(test_messages, 1):
    engine.init(True, pub_params)
    cipher = engine.process_block(msg, 0, len(msg))
    
    engine.init(False, priv_params)
    dec = engine.process_block(cipher, 0, len(cipher))
    
    success = bytes(dec) == msg
    
    try:
        msg_str = msg.decode('utf-8')
    except:
        msg_str = msg.hex()
    
    print(f'\n测试 {idx}:')
    print(f'原文: "{msg_str}"')
    print(f'明文长度: {len(msg)}字节, 密文长度: {len(cipher)}字节')
    print(f'解密结果: {"✅ 成功" if success else "❌ 失败"}')

# 使用错误的私钥解密
print('\n步骤 5: 使用错误的私钥解密')
d2 = secrets.randbelow(curve.n)
wrong_priv_params = ECPrivateKeyParameters(d2, curve.domain_params)

try:
    engine.init(False, wrong_priv_params)
    wrong_decrypted = engine.process_block(ciphertext, 0, len(ciphertext))
    print('使用错误私钥解密:', bytes(wrong_decrypted).decode('utf-8'))
except Exception as error:
    print('使用错误私钥解密: ❌ 失败（预期）')
    print('错误信息:', str(error))

print('\n✅ SM2 公钥加密示例运行完成')
