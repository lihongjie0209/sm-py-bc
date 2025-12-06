#!/usr/bin/env python3
"""
SM2 数字签名示例
演示如何使用 SM2 进行签名和验签
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from sm_bc.crypto.signers import SM2Signer
from sm_bc.crypto.params.ec_key_parameters import ECPrivateKeyParameters, ECPublicKeyParameters
from sm_bc.math.ec.custom.sm2 import SM2P256V1Curve
import secrets

print('=== SM2 数字签名示例 ===\n')

# 初始化曲线
curve = SM2P256V1Curve()

# 生成密钥对
print('步骤 1: 生成密钥对')
d = secrets.randbelow(curve.n)
Q = curve.G.multiply(d)

d_hex = hex(d)[2:]
x_hex = hex(Q.get_affine_x_coord().to_big_integer())[2:]
print('私钥:', d_hex[:32] + '...')
print('公钥 X:', x_hex[:32] + '...')

# 签名
print('\n步骤 2: 对消息进行签名')
message = b'Hello, SM2!'
print('原始消息:', message.decode('utf-8'))

signer = SM2Signer()
priv_params = ECPrivateKeyParameters(d, curve.domain_params)
signer.init(True, priv_params)
signature = signer.generate_signature(message)

sig_bytes = signature[0].to_bytes((signature[0].bit_length() + 7) // 8, 'big') + \
            signature[1].to_bytes((signature[1].bit_length() + 7) // 8, 'big')
print('签名结果:', sig_bytes.hex())
print('签名长度:', len(sig_bytes), '字节')

# 验签
print('\n步骤 3: 验证签名')
pub_params = ECPublicKeyParameters(Q, curve.domain_params)
signer.init(False, pub_params)
is_valid = signer.verify_signature(message, signature)
print('签名验证结果:', '✅ 有效' if is_valid else '❌ 无效')

# 篡改消息后验签
print('\n步骤 4: 篡改消息后验签')
tampered_message = b'Hello, SM3!'  # 故意改错
is_valid_tampered = signer.verify_signature(tampered_message, signature)
print('篡改消息:', tampered_message.decode('utf-8'))
print('签名验证结果:', '✅ 有效' if is_valid_tampered else '❌ 无效（预期）')

# 不同密钥对验签
print('\n步骤 5: 使用不同的公钥验签')
d2 = secrets.randbelow(curve.n)
Q2 = curve.G.multiply(d2)
pub_params2 = ECPublicKeyParameters(Q2, curve.domain_params)
signer.init(False, pub_params2)
is_valid_wrong_key = signer.verify_signature(message, signature)
print('使用错误的公钥:', '✅ 有效' if is_valid_wrong_key else '❌ 无效（预期）')

# 签名不同的消息
print('\n步骤 6: 签名多条消息')
messages = [b'Message 1', b'Message 2', b'Message 3']
signer.init(True, priv_params)
for idx, msg in enumerate(messages, 1):
    sig = signer.generate_signature(msg)
    sig_len = len(sig[0].to_bytes((sig[0].bit_length() + 7) // 8, 'big') + \
                   sig[1].to_bytes((sig[1].bit_length() + 7) // 8, 'big'))
    
    signer.init(False, pub_params)
    valid = signer.verify_signature(msg, sig)
    signer.init(True, priv_params)
    
    print(f'消息 {idx}: "{msg.decode()}" -> 签名长度: {sig_len}字节, 验证: {"✅" if valid else "❌"}')

print('\n✅ SM2 数字签名示例运行完成')
