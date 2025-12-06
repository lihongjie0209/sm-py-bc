"""
SM4 高级API测试
"""

import unittest
from sm_bc.crypto.sm4 import SM4


class TestSM4API(unittest.TestCase):
    """SM4高级API测试"""

    def test_generate_key(self):
        """测试密钥生成"""
        key1 = SM4.generate_key()
        key2 = SM4.generate_key()
        
        # 密钥长度必须是16字节
        self.assertEqual(len(key1), 16)
        self.assertEqual(len(key2), 16)
        
        # 两次生成的密钥应该不同
        self.assertNotEqual(key1, key2)

    def test_encrypt_decrypt(self):
        """测试加密解密"""
        key = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
        plaintext = b'Hello, SM4! This is a test message.'
        
        # 加密
        ciphertext = SM4.encrypt(plaintext, key)
        
        # 密文长度应该是块大小的倍数
        self.assertEqual(len(ciphertext) % 16, 0)
        
        # 密文不应该等于明文
        self.assertNotEqual(ciphertext, plaintext)
        
        # 解密
        decrypted = SM4.decrypt(ciphertext, key)
        
        # 解密后应该等于原始明文
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_empty_data(self):
        """测试加密空数据"""
        key = SM4.generate_key()
        plaintext = b''
        
        # 空数据也应该能加密（会被填充为一个完整块）
        ciphertext = SM4.encrypt(plaintext, key)
        self.assertEqual(len(ciphertext), 16)
        
        # 解密应该返回空数据
        decrypted = SM4.decrypt(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_single_block(self):
        """测试加密单个块大小的数据"""
        key = SM4.generate_key()
        plaintext = b'0123456789ABCDEF'  # 正好16字节
        
        # 应该被填充为2个块（原数据+填充块）
        ciphertext = SM4.encrypt(plaintext, key)
        self.assertEqual(len(ciphertext), 32)
        
        # 解密应该返回原数据
        decrypted = SM4.decrypt(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_block(self):
        """测试加密单个块"""
        key = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
        block = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
        
        # 加密块
        encrypted = SM4.encrypt_block(block, key)
        self.assertEqual(len(encrypted), 16)
        
        # 解密块
        decrypted = SM4.decrypt_block(encrypted, key)
        self.assertEqual(decrypted, block)

    def test_encrypt_block_invalid_size(self):
        """测试加密无效大小的块"""
        key = SM4.generate_key()
        
        # 块大小不是16字节应该抛出异常
        with self.assertRaises(ValueError) as cm:
            SM4.encrypt_block(b'short', key)
        self.assertIn('exactly 16 bytes', str(cm.exception))

    def test_decrypt_block_invalid_size(self):
        """测试解密无效大小的块"""
        key = SM4.generate_key()
        
        # 块大小不是16字节应该抛出异常
        with self.assertRaises(ValueError) as cm:
            SM4.decrypt_block(b'short', key)
        self.assertIn('exactly 16 bytes', str(cm.exception))

    def test_encrypt_invalid_key_size(self):
        """测试使用无效密钥大小加密"""
        plaintext = b'test data'
        
        # 密钥不是16字节应该抛出异常
        with self.assertRaises(ValueError) as cm:
            SM4.encrypt(plaintext, b'short')
        self.assertIn('128 bit', str(cm.exception))

    def test_decrypt_invalid_key_size(self):
        """测试使用无效密钥大小解密"""
        ciphertext = bytes(16)
        
        # 密钥不是16字节应该抛出异常
        with self.assertRaises(ValueError) as cm:
            SM4.decrypt(ciphertext, b'short')
        self.assertIn('128 bit', str(cm.exception))

    def test_decrypt_invalid_ciphertext_length(self):
        """测试解密无效长度的密文"""
        key = SM4.generate_key()
        
        # 密文长度不是块大小的倍数应该抛出异常
        with self.assertRaises(ValueError) as cm:
            SM4.decrypt(b'invalid length', key)
        self.assertIn('multiple of block size', str(cm.exception))

    def test_decrypt_invalid_padding(self):
        """测试解密无效填充的数据"""
        key = SM4.generate_key()
        
        # 创建一个有效长度但填充无效的密文
        # 先加密一个数据
        plaintext = b'test'
        ciphertext = bytearray(SM4.encrypt(plaintext, key))
        
        # 破坏填充
        ciphertext[-1] = 99  # 无效的填充值
        
        # 解密应该抛出异常
        with self.assertRaises(ValueError) as cm:
            SM4.decrypt(bytes(ciphertext), key)
        self.assertIn('padding', str(cm.exception).lower())

    def test_round_trip_various_sizes(self):
        """测试各种大小的数据往返加密"""
        key = SM4.generate_key()
        
        # 测试不同大小的数据
        test_sizes = [0, 1, 15, 16, 17, 31, 32, 33, 100, 1000]
        
        for size in test_sizes:
            with self.subTest(size=size):
                plaintext = bytes(range(256))[:size] * ((size // 256) + 1)
                plaintext = plaintext[:size]
                
                ciphertext = SM4.encrypt(plaintext, key)
                decrypted = SM4.decrypt(ciphertext, key)
                
                self.assertEqual(decrypted, plaintext)

    def test_known_vector(self):
        """测试已知测试向量"""
        # 从SM4标准中的测试向量
        key = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
        plaintext = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
        expected_ciphertext = bytes.fromhex('681EDF34D206965E86B3E94F536E4246')
        
        # 使用encrypt_block测试单块加密（无填充）
        ciphertext = SM4.encrypt_block(plaintext, key)
        
        self.assertEqual(ciphertext, expected_ciphertext)


if __name__ == '__main__':
    unittest.main()
