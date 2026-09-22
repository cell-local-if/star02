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

## 审计证据与外部锚定

`RequestStore` 在 SQLite 之外用一个旁车锚点文件（默认 `<数据库>.anchor`）
为整库状态提供防整体重算的外部证据：

- 构造器可选 `anchor_path`（必须位于数据库文件之外）与 `integrity_key`；
  未给路径时使用数据库旁车文件，未给密钥时首次生成随机密钥且仅保存于旁车，
  重建实例无需提供密钥即可继续验证。
- 每次 `submit` 或实际 `transition` 都以可恢复的两阶段提交同时推进
  SQLite 与旁车（暂存签名 intent → 提交 SQLite → 原子替换旁车），
  旁车更新一律走临时文件加 `os.replace`。任一环节失败都不会返回成功。
- `recover()` 严格只读，返回 `"valid"` / `"invalid"` / `"incomplete"`：
  一致为 valid，锚点与数据库不符为 invalid，旁车缺失/损坏/提交未完成为
  incomplete；后两者都会让 `verify_evidence` 返回 `False`，且 `recover`
  本身从不修复或回填（中断提交仅在下一次成功写入时前滚或回滚）。
- 旧的无锚定数据库不会被静默信任（打开即为 `incomplete` 且禁止写入），
  除非以显式 `integrity_key` 采纳；加列升级从不改写既有审计记录。
