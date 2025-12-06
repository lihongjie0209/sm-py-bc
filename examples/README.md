# SM-PY-BC 示例代码

本目录包含 SM-PY-BC 库的完整示例代码，展示各种算法和模式的使用方法。

## 📋 示例列表

| 示例文件 | 说明 | 演示内容 |
|---------|------|---------|
| [sm3_hash.py](./sm3_hash.py) | SM3 哈希计算 | 基本哈希、分段更新、空数据处理 |
| [sm2_keypair.py](./sm2_keypair.py) | SM2 密钥对生成 | 生成密钥对、查看公私钥 |
| [sm2_sign.py](./sm2_sign.py) | SM2 数字签名 | 签名、验签、错误验证 |
| [sm2_encrypt.py](./sm2_encrypt.py) | SM2 公钥加密 | 加密、解密、不同长度消息 |
| [sm2_keyexchange.py](./sm2_keyexchange.py) | SM2 密钥交换 | ECDH 协议、密钥协商 |
| [sm4_ecb_simple.py](./sm4_ecb_simple.py) | SM4 基础加密 | ECB 模式、PKCS7 填充 |
| [sm4_modes.py](./sm4_modes.py) | SM4 多种模式 | ECB/CBC/CTR/GCM 对比 |
| [sm4_comprehensive_demo.py](./sm4_comprehensive_demo.py) | SM4 综合演示 | 所有SM4特性的完整演示 |
| [file_encryption_tool.py](./file_encryption_tool.py) | 文件加密工具 | 实用的文件加密解密工具 |

## 🚀 运行示例

### 方法 1: 直接运行单个示例

```bash
# 进入示例目录
cd examples

# 运行 SM3 哈希示例
python sm3_hash.py

# 运行 SM2 密钥对生成示例
python sm2_keypair.py

# 运行 SM2 数字签名示例
python sm2_sign.py

# 运行 SM2 公钥加密示例
python sm2_encrypt.py

# 运行 SM2 密钥交换示例
python sm2_keyexchange.py

# 运行 SM4 ECB 简单示例
python sm4_ecb_simple.py

# 运行 SM4 多种模式示例
python sm4_modes.py

# 运行 SM4 综合演示
python sm4_comprehensive_demo.py

# 运行文件加密工具
python file_encryption_tool.py --help
```

### 方法 2: 批量运行所有示例

```bash
# 运行所有示例
for file in sm3_hash.py sm2_keypair.py sm2_sign.py sm2_encrypt.py sm2_keyexchange.py sm4_ecb_simple.py sm4_modes.py; do
    echo "=== Running $file ==="
    python "$file"
    echo
done
```

### 方法 3: 使用 Make 命令（如果配置）

```bash
make examples        # 运行所有示例
make example-sm3     # 运行 SM3 示例
make example-sm2     # 运行 SM2 示例
make example-sm4     # 运行 SM4 示例
```

## 📖 示例详解

### SM3 哈希示例

演示如何使用 SM3Digest 计算哈希：

- 基本哈希计算
- 分段更新数据
- 空数据处理
- 验证哈希一致性

### SM2 密钥对生成示例

演示如何生成 SM2 密钥对：

- 生成私钥和公钥
- 查看密钥的十六进制表示
- 批量生成多个密钥对

### SM2 数字签名示例

演示完整的签名和验签流程：

- 生成密钥对
- 对消息进行签名
- 验证签名有效性
- 测试篡改消息
- 测试错误密钥

### SM2 公钥加密示例

演示 SM2 公钥加密和解密：

- 使用公钥加密消息
- 使用私钥解密消息
- 处理不同长度的消息
- 测试错误密钥解密

### SM2 密钥交换示例

演示 SM2 密钥交换协议（ECDH）：

- Alice 和 Bob 各自生成静态和临时密钥对
- 双方交换公钥
- 各自计算共享密钥
- 验证双方密钥一致
- 生成不同长度的共享密钥

### SM4 ECB 简单示例

演示 SM4 ECB 模式的基本用法：

- 生成随机密钥
- 加密和解密数据
- 处理不同长度的数据
- 单块加密（无填充）

⚠️ **注意**: ECB 模式不安全，仅用于演示

### SM4 多种模式示例

对比演示 SM4 的多种工作模式：

- **ECB 模式**: 电子密码本（不推荐）
- **CBC 模式**: 密码块链接（推荐）
- **CTR 模式**: 计数器模式（流密码）
- **GCM 模式**: 认证加密（最佳选择）

展示不同模式的：
- 初始化方式
- IV/Nonce 使用
- 加密解密过程
- 密文长度差异

## 🔧 环境要求

- **Python**: 3.10 或更高
- **依赖**: 无（纯 Python 实现）

## 💡 使用提示

1. **学习顺序**: 建议按照以下顺序学习示例：
   - SM3 哈希 → SM2 密钥对 → SM2 签名 → SM2 加密 → SM4 基础 → SM4 模式

2. **代码复用**: 所有示例都是独立的、可直接运行的脚本，可以直接复制到你的项目中

3. **安全提示**:
   - ECB 模式仅用于演示，生产环境请使用 CBC、CTR 或 GCM
   - 示例中的密钥生成使用 `secrets` 模块，适合生产环境
   - 实际应用中请妥善保管私钥

4. **错误处理**: 示例代码包含基本的错误处理，展示了常见的错误场景

5. **性能考虑**: 这是纯 Python 实现，性能适中。如需高性能，可考虑：
   - 使用 PyPy 运行
   - 集成 C/C++ 扩展
   - 使用硬件加速

## 🐛 问题反馈

如果示例代码有问题或不清楚的地方，请：

1. 查看 [主文档](../README.md)
2. 查看 [API 文档](../docs/)
3. 提交 [Issue](https://github.com/yourusername/sm-py-bc/issues)

## 📚 更多资源

- **测试代码**: `tests/unit/` - 更多的使用示例
- **API 文档**: `docs/` - 详细的 API 说明
- **开发指南**: `DEVELOPER_HANDOFF.md` - 开发者文档

## 🎯 快速参考

### SM3 哈希

```python
from sm_bc.crypto.digests import SM3Digest

digest = SM3Digest()
digest.update(data, 0, len(data))
hash_output = bytearray(32)
digest.do_final(hash_output, 0)
```

### SM2 签名

```python
from sm_bc.crypto.signers import SM2Signer

signer = SM2Signer()
signer.init(True, priv_params)
signature = signer.generate_signature(message)

signer.init(False, pub_params)
is_valid = signer.verify_signature(message, signature)
```

### SM4 加密（推荐方式）

```python
from sm_bc.crypto.cipher import create_sm4_cipher

cipher = create_sm4_cipher(mode='CBC', padding='PKCS7')
cipher.init(True, key, iv)
ciphertext = cipher.encrypt(plaintext)

cipher.init(False, key, iv)
plaintext = cipher.decrypt(ciphertext)
```

---

**祝你使用愉快！如有问题随时提问。** 🎉
