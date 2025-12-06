#!/usr/bin/env python3
"""
SM3 哈希示例
演示如何使用 SM3Digest 计算数据的哈希值
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from sm_bc.crypto.digests import SM3Digest

print('=== SM3 哈希示例 ===\n')

# 创建 SM3 摘要实例
digest = SM3Digest()

# 更新数据
data = 'Hello, SM3!'.encode('utf-8')
digest.update_bytes(data, 0, len(data))

# 获取哈希值
hash_output = bytearray(digest.get_digest_size())
digest.do_final(hash_output, 0)

print('输入数据:', 'Hello, SM3!')
print('SM3 Hash:', hash_output.hex())
print('哈希长度:', len(hash_output), '字节')

# 多次更新示例
print('\n--- 分段更新示例 ---')
digest2 = SM3Digest()
part1 = 'Hello, '.encode('utf-8')
part2 = 'SM3!'.encode('utf-8')

digest2.update_bytes(part1, 0, len(part1))
digest2.update_bytes(part2, 0, len(part2))

hash2 = bytearray(digest2.get_digest_size())
digest2.do_final(hash2, 0)

print('分段输入: "Hello, " + "SM3!"')
print('SM3 Hash:', hash2.hex())
print('结果一致:', hash_output == hash2)

# 空数据哈希
print('\n--- 空数据哈希 ---')
digest3 = SM3Digest()
hash3 = bytearray(digest3.get_digest_size())
digest3.do_final(hash3, 0)

print('空数据 Hash:', hash3.hex())

print('\n✅ SM3 哈希示例运行完成')
