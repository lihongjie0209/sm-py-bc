#!/usr/bin/env python3
"""
SM2 密钥对生成示例
演示如何生成 SM2 密钥对
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from sm_bc.math.ec.custom.sm2 import SM2P256V1Curve
import secrets

print('=== SM2 密钥对生成示例 ===\n')

# 初始化 SM2 曲线
curve = SM2P256V1Curve()

# 生成密钥对
private_key = secrets.randbelow(curve.n)
public_key = curve.G.multiply(private_key)

print('私钥 (Private Key):')
print(hex(private_key)[2:])
print('\n私钥长度:', len(hex(private_key)[2:]), '个十六进制字符')

print('\n公钥 (Public Key):')
x_hex = hex(public_key.get_affine_x_coord().to_big_integer())[2:]
y_hex = hex(public_key.get_affine_y_coord().to_big_integer())[2:]
print('X 坐标:', x_hex)
print('Y 坐标:', y_hex)
print('\n公钥坐标长度:', len(x_hex), '个十六进制字符')

# 生成多个密钥对
print('\n--- 生成多个密钥对 ---')
for i in range(1, 4):
    d = secrets.randbelow(curve.n)
    Q = curve.G.multiply(d)
    
    d_hex = hex(d)[2:]
    x_hex = hex(Q.get_affine_x_coord().to_big_integer())[2:]
    y_hex = hex(Q.get_affine_y_coord().to_big_integer())[2:]
    
    print(f'\n密钥对 {i}:')
    print('私钥:', d_hex[:32] + '...')
    print('公钥 X:', x_hex[:32] + '...')
    print('公钥 Y:', y_hex[:32] + '...')

print('\n✅ SM2 密钥对生成示例运行完成')
