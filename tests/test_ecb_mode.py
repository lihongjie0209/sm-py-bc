"""
ECB模式测试
"""

import unittest
from sm_bc.crypto.engines.sm4_engine import SM4Engine
from sm_bc.crypto.modes.ecb_block_cipher import ECBBlockCipher
from sm_bc.crypto.params.key_parameter import KeyParameter


class TestECBMode(unittest.TestCase):
    """ECB模式测试"""

    def test_ecb_encryption_decryption(self):
        """测试ECB加密解密"""
        # 测试向量
        key = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
        plaintext = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
        
        # 加密
        cipher = ECBBlockCipher(SM4Engine())
        cipher.init(True, KeyParameter(key))
        
        ciphertext = bytearray(16)
        cipher.process_block(plaintext, 0, ciphertext, 0)
        
        # 解密
        decipher = ECBBlockCipher(SM4Engine())
        decipher.init(False, KeyParameter(key))
        
        decrypted = bytearray(16)
        decipher.process_block(bytes(ciphertext), 0, decrypted, 0)
        
        # 验证
        self.assertEqual(bytes(decrypted), plaintext)

    def test_ecb_algorithm_name(self):
        """测试算法名称"""
        cipher = ECBBlockCipher(SM4Engine())
        self.assertEqual(cipher.get_algorithm_name(), 'SM4/ECB')

    def test_ecb_block_size(self):
        """测试块大小"""
        cipher = ECBBlockCipher(SM4Engine())
        self.assertEqual(cipher.get_block_size(), 16)

    def test_ecb_get_underlying_cipher(self):
        """测试获取底层密码"""
        engine = SM4Engine()
        cipher = ECBBlockCipher(engine)
        self.assertIs(cipher.get_underlying_cipher(), engine)


if __name__ == '__main__':
    unittest.main()
