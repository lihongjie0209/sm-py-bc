#!/usr/bin/env python3
"""
SM2 密钥交换示例
演示如何使用 SM2 进行密钥协商（ECDH）
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from sm_bc.crypto.agreement import SM2KeyExchange
from sm_bc.crypto.params.sm2_key_exchange_parameters import (
    SM2KeyExchangePrivateParameters,
    SM2KeyExchangePublicParameters
)
from sm_bc.crypto.params.ec_key_parameters import ECPrivateKeyParameters, ECPublicKeyParameters
from sm_bc.math.ec.custom.sm2 import SM2P256V1Curve
import secrets

print('=== SM2 密钥交换示例 ===\n')

print('场景: Alice 和 Bob 通过 SM2 密钥交换协议协商共享密钥\n')

# 初始化曲线
curve = SM2P256V1Curve()
domain_params = curve.domain_params

# 步骤 1: Alice 生成静态密钥对
print('步骤 1: Alice 生成静态密钥对')
alice_static_d = secrets.randbelow(curve.n)
alice_static_Q = curve.G.multiply(alice_static_d)
alice_static_priv = ECPrivateKeyParameters(alice_static_d, domain_params)
alice_static_pub = ECPublicKeyParameters(alice_static_Q, domain_params)

d_hex = hex(alice_static_d)[2:]
x_hex = hex(alice_static_Q.get_affine_x_coord().to_big_integer())[2:]
print('Alice 静态私钥:', d_hex[:32] + '...')
print('Alice 静态公钥 X:', x_hex[:32] + '...')

# 步骤 2: Alice 生成临时密钥对
print('\n步骤 2: Alice 生成临时密钥对')
alice_ephemeral_d = secrets.randbelow(curve.n)
alice_ephemeral_Q = curve.G.multiply(alice_ephemeral_d)
alice_ephemeral_priv = ECPrivateKeyParameters(alice_ephemeral_d, domain_params)
alice_ephemeral_pub = ECPublicKeyParameters(alice_ephemeral_Q, domain_params)

x_hex = hex(alice_ephemeral_Q.get_affine_x_coord().to_big_integer())[2:]
print('Alice 临时公钥 X:', x_hex[:32] + '...')

# 步骤 3: Bob 生成静态密钥对
print('\n步骤 3: Bob 生成静态密钥对')
bob_static_d = secrets.randbelow(curve.n)
bob_static_Q = curve.G.multiply(bob_static_d)
bob_static_priv = ECPrivateKeyParameters(bob_static_d, domain_params)
bob_static_pub = ECPublicKeyParameters(bob_static_Q, domain_params)

d_hex = hex(bob_static_d)[2:]
x_hex = hex(bob_static_Q.get_affine_x_coord().to_big_integer())[2:]
print('Bob 静态私钥:', d_hex[:32] + '...')
print('Bob 静态公钥 X:', x_hex[:32] + '...')

# 步骤 4: Bob 生成临时密钥对
print('\n步骤 4: Bob 生成临时密钥对')
bob_ephemeral_d = secrets.randbelow(curve.n)
bob_ephemeral_Q = curve.G.multiply(bob_ephemeral_d)
bob_ephemeral_priv = ECPrivateKeyParameters(bob_ephemeral_d, domain_params)
bob_ephemeral_pub = ECPublicKeyParameters(bob_ephemeral_Q, domain_params)

x_hex = hex(bob_ephemeral_Q.get_affine_x_coord().to_big_integer())[2:]
print('Bob 临时公钥 X:', x_hex[:32] + '...')

# 步骤 5: Alice 初始化密钥交换（作为发起方）
print('\n步骤 5: Alice 初始化密钥交换（发起方）')
alice_exchange = SM2KeyExchange()
alice_priv_params = SM2KeyExchangePrivateParameters(
    True,  # initiator = True (发起方)
    alice_static_priv,
    alice_ephemeral_priv
)
alice_exchange.init(alice_priv_params)

# 步骤 6: Alice 计算共享密钥
print('\n步骤 6: Alice 计算共享密钥')
print('Alice 使用: Bob的静态公钥 + Bob的临时公钥')
bob_pub_params = SM2KeyExchangePublicParameters(bob_static_pub, bob_ephemeral_pub)
alice_shared_key = alice_exchange.calculate_key(128, bob_pub_params)  # 128位 = 16字节
print('Alice 共享密钥:', bytes(alice_shared_key).hex())

# 步骤 7: Bob 初始化密钥交换（作为响应方）
print('\n步骤 7: Bob 初始化密钥交换（响应方）')
bob_exchange = SM2KeyExchange()
bob_priv_params = SM2KeyExchangePrivateParameters(
    False,  # initiator = False (响应方)
    bob_static_priv,
    bob_ephemeral_priv
)
bob_exchange.init(bob_priv_params)

# 步骤 8: Bob 计算共享密钥
print('\n步骤 8: Bob 计算共享密钥')
print('Bob 使用: Alice的静态公钥 + Alice的临时公钥')
alice_pub_params = SM2KeyExchangePublicParameters(alice_static_pub, alice_ephemeral_pub)
bob_shared_key = bob_exchange.calculate_key(128, alice_pub_params)  # 128位 = 16字节
print('Bob 共享密钥:', bytes(bob_shared_key).hex())

# 步骤 9: 验证密钥一致性
print('\n步骤 9: 验证密钥一致性')
keys_match = bytes(alice_shared_key) == bytes(bob_shared_key)
print('密钥匹配:', '✅ 成功' if keys_match else '❌ 失败')
print('密钥长度:', len(alice_shared_key), '字节')

# 生成不同长度的共享密钥
print('\n--- 生成不同长度的共享密钥 ---')
key_lengths = [128, 192, 256]  # 位

for key_bits in key_lengths:
    # 重新生成临时密钥对
    alice2_ephemeral_d = secrets.randbelow(curve.n)
    alice2_ephemeral_Q = curve.G.multiply(alice2_ephemeral_d)
    alice2_ephemeral_priv = ECPrivateKeyParameters(alice2_ephemeral_d, domain_params)
    alice2_ephemeral_pub = ECPublicKeyParameters(alice2_ephemeral_Q, domain_params)
    
    bob2_ephemeral_d = secrets.randbelow(curve.n)
    bob2_ephemeral_Q = curve.G.multiply(bob2_ephemeral_d)
    bob2_ephemeral_priv = ECPrivateKeyParameters(bob2_ephemeral_d, domain_params)
    bob2_ephemeral_pub = ECPublicKeyParameters(bob2_ephemeral_Q, domain_params)
    
    # Alice 计算密钥
    alice_ex2 = SM2KeyExchange()
    alice_priv_params2 = SM2KeyExchangePrivateParameters(True, alice_static_priv, alice2_ephemeral_priv)
    alice_ex2.init(alice_priv_params2)
    bob_pub_params2 = SM2KeyExchangePublicParameters(bob_static_pub, bob2_ephemeral_pub)
    alice_key = alice_ex2.calculate_key(key_bits, bob_pub_params2)
    
    # Bob 计算密钥
    bob_ex2 = SM2KeyExchange()
    bob_priv_params2 = SM2KeyExchangePrivateParameters(False, bob_static_priv, bob2_ephemeral_priv)
    bob_ex2.init(bob_priv_params2)
    alice_pub_params2 = SM2KeyExchangePublicParameters(alice_static_pub, alice2_ephemeral_pub)
    bob_key = bob_ex2.calculate_key(key_bits, alice_pub_params2)
    
    print(f'\n{key_bits}位密钥 ({key_bits // 8}字节):')
    print('Alice:', bytes(alice_key).hex()[:40] + '...')
    print('Bob:  ', bytes(bob_key).hex()[:40] + '...')
    print('匹配:', '✅' if bytes(alice_key) == bytes(bob_key) else '❌')

print('\n✅ SM2 密钥交换示例运行完成')
