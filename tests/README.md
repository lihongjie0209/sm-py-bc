# 测试指南

## 测试分类

### 单元测试（Unit Tests）
快速的单元测试，默认运行。执行时间 < 5 秒。

### 慢速测试（Slow Tests）
耗时较长的测试，如百万次迭代。默认**不运行**。

### 性能测试（Performance Tests）
性能基准测试。默认**不运行**。

### 集成测试（Integration Tests）
跨模块集成测试。

---

## 运行测试

### 🚀 运行所有单元测试（默认，排除慢速测试）

```bash
# 快速运行，~2-3 秒
pytest tests/unit/

# 或使用简写
pytest
```

**输出示例**:
```
435 passed, 1 skipped, 2 deselected in 2.43s
```

---

### 🐌 运行慢速测试

```bash
# 仅运行慢速测试
pytest tests/unit/ -m slow

# 运行所有测试（包括慢速）
pytest tests/unit/ -m "slow or not slow"

# 或直接禁用标记过滤
pytest tests/unit/ -m ""
```

**注意**: 慢速测试大约需要 2-3 分钟。

---

### 📊 运行性能测试

```bash
# 仅运行性能测试
pytest tests/unit/ -m performance

# 运行所有测试（包括性能测试）
pytest tests/unit/ -m "performance or not performance"
```

---

### 🔍 运行特定模块测试

```bash
# 运行 SM4 测试（排除慢速）
pytest tests/unit/test_sm4_engine.py

# 运行 SM4 测试（包括慢速）
pytest tests/unit/test_sm4_engine.py -m ""

# 运行数学库测试
pytest tests/unit/math/

# 运行工具类测试
pytest tests/unit/util/

# 运行密码学测试
pytest tests/unit/crypto/
```

---

### 📝 详细输出

```bash
# 详细模式（显示每个测试）
pytest tests/unit/ -v

# 非常详细（显示输出）
pytest tests/unit/ -vv

# 显示失败的测试细节
pytest tests/unit/ --tb=short

# 显示所有输出（包括 print）
pytest tests/unit/ -s
```

---

### 📈 测试覆盖率

```bash
# 生成覆盖率报告
pytest tests/unit/ --cov=sm_bc --cov-report=html

# 查看覆盖率（终端）
pytest tests/unit/ --cov=sm_bc --cov-report=term-missing
```

---

## 测试标记（Markers）

### 可用标记

| 标记 | 用途 | 默认行为 |
|------|------|----------|
| `@pytest.mark.slow` | 耗时测试（如百万次迭代） | 排除 |
| `@pytest.mark.performance` | 性能基准测试 | 排除 |
| `@pytest.mark.integration` | 集成测试 | 包含 |

### 使用示例

```python
import pytest

@pytest.mark.slow
def test_million_iterations():
    """百万次迭代测试"""
    for i in range(1000000):
        # ...
        pass

@pytest.mark.performance
def test_encryption_speed():
    """加密性能测试"""
    # 性能基准
    pass

@pytest.mark.integration
def test_full_workflow():
    """完整工作流测试"""
    # 集成测试
    pass
```

---

## 当前测试统计

### 单元测试（默认运行）
- **总计**: 435 个测试
- **执行时间**: ~2.43 秒
- **覆盖模块**:
  - 🔐 密码学: SM2, SM3, SM4
  - 📐 数学库: ECPoint, ECFieldElement, ECCurve, ECMultiplier
  - 🛠️ 工具类: Arrays, Pack, Integers, SecureRandom
  - 🔑 密钥参数: KeyParameter, ParametersWithRandom

### 慢速测试（手动运行）
- **总计**: 2 个测试
- **执行时间**: ~165 秒（2分45秒）
- **测试内容**:
  - SM4 百万次加密迭代
  - SM4 百万次解密迭代

---

## CI/CD 配置建议

### GitHub Actions 示例

```yaml
name: Tests

on: [push, pull_request]

jobs:
  fast-tests:
    name: Fast Unit Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - run: pip install -e ".[test]"
      - run: pytest tests/unit/  # 默认排除慢速测试
  
  slow-tests:
    name: Slow Tests
    runs-on: ubuntu-latest
    # 仅在主分支运行慢速测试
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - run: pip install -e ".[test]"
      - run: pytest tests/unit/ -m slow
```

---

## 开发建议

### 编写新测试时

1. **快速测试优先**: 大多数测试应该 < 0.1 秒
2. **标记慢速测试**: 任何 > 1 秒的测试应标记为 `@pytest.mark.slow`
3. **避免循环**: 尽量减少大循环，使用更小的测试数据
4. **隔离性能测试**: 性能基准应该单独标记为 `@pytest.mark.performance`

### 测试命名规范

```python
# ✅ 好的命名
def test_should_encrypt_16_byte_block():
    """Should encrypt a 16-byte block correctly."""
    pass

# ❌ 避免的命名
def test1():
    pass
```

---

## 故障排查

### 测试运行太慢？

```bash
# 查看最慢的 10 个测试
pytest tests/unit/ --durations=10
```

### 标记未定义警告？

确保 `pyproject.toml` 中定义了所有标记：

```toml
[tool.pytest.ini_options]
markers = [
    "slow: marks tests as slow (deselected by default)",
    "performance: marks tests as performance benchmarks",
]
```

### 想要运行所有测试？

```bash
# 忽略标记过滤
pytest tests/unit/ -m ""
```

---

## 更多信息

- **Pytest 文档**: https://docs.pytest.org/
- **测试对齐追踪**: `TEST_ALIGNMENT_TRACKER.md`
- **测试进度日志**: `TEST_PROGRESS_LOG.md`
- **开发文档**: `docs/`
