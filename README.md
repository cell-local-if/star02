# Forgetting Evidence Service

这是一个面向后端系统的机器遗忘证据服务，用于记录删除请求、执行状态和可验证回执。

运行健康检查：

```bash
PYTHONPATH=src python3 -m forgetting_evidence health
```

运行基础测试：

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 可信证据锚定

`RequestStore` 的状态事件本身是一条 SHA-256 哈希链，但链与链头都存放在可被改写的
SQLite 中，单凭库内数据无法防止"重算全部事件和链头"的伪造。要让证据可信，必须在构造
时传入调用方在 SQLite 与旁车之外自行保管的密钥：

```python
store = RequestStore(
    db_path,
    integrity_key=caller_held_secret,     # str/bytes，仅驻内存，绝不落盘
    anchor_path="evidence.db.anchor",     # 可选，默认 <db>.anchor
)
```

- 每次提交与真实状态迁移都遵循可判定的提交协议：先在 SQLite 事务内完成行写入，再把
  HMAC-SHA256 密封的锚定帧追加并 fsync 到旁车，最后提交 SQLite。
- 旁车是只增、全局成链、逐帧认证的日志；帧绑定租户、请求、事件序号与事件摘要。没有
  调用方密钥就无法删改、插入、调序、跨请求或跨租户替换事件，也无法重算并替换全部
  SQLite 与旁车公开内容而通过校验。
- `verify_evidence()` 仅在存在可验证密钥、旁车完整认证且与 SQLite 全局一致、链重算
  全部通过时返回 `True`。无密钥、旁车缺失/损坏、旧库无可信锚定、提交中断或任何篡改
  一律返回 `False`；正常重建后仍可验证。
- `recover()` 只读返回 `{"status": ...}`：`consistent`（唯一有效）、`no_key`、
  `no_sidecar`、`corrupt_anchor`、`interrupted`、`diverged`。恢复绝不修复、回填或
  改写证据。
- 密钥、可替代密钥的材料以及链计算原文不会写入 SQLite、旁车、回执、异常或日志。

不传 `integrity_key` 时保留全部读写、状态机与回执行为，但链没有可信锚，
`verify_evidence()` 恒为 `False`。

服务必须保持后端接口可自动验证，并避免在日志或回执中泄露待删除的原始数据。
