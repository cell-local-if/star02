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

## 审计证据的外部可信锚定

每条状态事件的 `chain_hash` 以及请求链头锚点均为受密钥保护的 HMAC-SHA256
标签；密钥与链头账本保存在 SQLite 数据库之外：

- 默认在数据库旁自动生成 `0600` 权限的 `<db>.integrity.key`（密钥）与
  `<db>.integrity.heads`（仅含标签输出的链头账本），重建 `RequestStore(db_path)`
  后仍可验证同一数据库。
- 也可通过构造参数 `integrity_key`、`integrity_key_file`、`integrity_anchor`
  （自定义 `IntegrityAnchor`，如 HSM/签名服务），或环境变量
  `FORGETTING_EVIDENCE_INTEGRITY_KEY`、
  `FORGETTING_EVIDENCE_INTEGRITY_KEY_FILE` 显式提供信任根。
- 密钥材料、派生原文及可伪造锚定状态均不写入 SQLite、回执、异常或日志。
- 即使攻击者重算数据库内全部事件、链头与锚定字段，只要缺少外部密钥与账本，
  `verify_evidence` 一律返回 `False`；该方法只读不写，绝不修复或回填证据。
- 升级前的旧库仅做加列式迁移：旧请求 `verify_evidence` 返回 `False`，
  `evidence`/`transition` 抛出 `LegacyEvidenceUnsupported`，`audit`/`get`
  仍可读取，且既有审计记录不会被覆盖或回填。

