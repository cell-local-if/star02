# Forgetting Evidence Service

这是一个面向后端系统的机器遗忘证据服务，用于记录删除请求、执行状态和可验证回执。当前基线只提供可运行的 Python 包与健康检查入口，尚未实现业务 API、持久化或证据编排能力。

运行健康检查：

```bash
PYTHONPATH=src python3 -m forgetting_evidence health
```

运行基础测试：

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

服务必须保持后端接口可自动验证，并避免在日志或回执中泄露待删除的原始数据。

## 可信证据锚定

`RequestStore` 支持两个可选的具名参数，用于把审计链锚定到 SQLite 之外：

```python
store = RequestStore(db_path, anchor_path=anchor_path, integrity_key=key)
```

- `integrity_key` 必须由调用方保存在 SQLite 与旁车（sidecar）之外；密钥本身、可替代密钥的材料和哈希链计算原文永远不会写入数据库、旁车、回执、异常或日志。
- `anchor_path` 指向一个仅追加的旁车文件。每次受理或实际状态迁移都按「prepare（旁车追加并 fsync）→ SQLite 提交并 fsync → commit（旁车追加并 fsync）」的可恢复提交协议关联链头与受密钥保护的锚点；任一步失败都不会返回成功。
- 重建实例后正常一致的数据仍可验证；旁车缺失、损坏、锚点与数据库不符、旧库缺少可信锚定或提交中断时，`verify_evidence` 返回 `False`。
- 只读的 `recover()` 仅报告 `"valid"`、`"invalid"` 或 `"incomplete"`，不会修复、回填或写入任何证据。

