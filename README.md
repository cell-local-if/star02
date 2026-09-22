# Forgetting Evidence Service

这是一个面向后端系统的机器遗忘证据服务，用于记录删除请求、执行状态和可验证回执。

运行健康检查：

```bash
PYTHONPATH=src python3 -m forgetting_evidence health
```

运行测试：

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

服务必须保持后端接口可自动验证，并避免在日志或回执中泄露待删除的原始数据。

## 请求存储与审计链

`forgetting_evidence.requests.RequestStore` 以 SQLite 持久化删除请求与只增的状态时间线：

- `submit` / `get` / `transition` / `audit` / `evidence` / `verify_evidence`；
- 每个事件带 SHA-256 链哈希，绑定租户、请求、序号、状态、时间与前驱哈希；
- 事件与请求行在同一事务中写入；删改、插入、调序、跨请求或跨租户替换事件都会被
  `verify_evidence` 拒绝。

## 外部锚定（sidecar anchor）

每条链哈希都存放在它所证明的数据库内部，拥有文件写权限的人理论上可以在伪造后重算全部
哈希。为此存储额外维护一个位于 **SQLite 之外** 的旁车锚点：

```python
RequestStore(db_path)                              # 旁车默认在数据库旁
RequestStore(db_path, anchor_path=path)            # 自定义旁车路径
RequestStore(db_path, integrity_key=key)           # 显式 32 字节密钥（bytes 或 64 位 hex）
```

- 未给 `anchor_path` 时使用数据库同目录的隐藏旁车文件；未给 `integrity_key` 时首次创建
  随机密钥，密钥仅保存在旁车文件中，重建实例后仍可验证；显式提供的密钥永不落盘。
- 旁车记录覆盖全库内容（两张表的全部行、`sqlite_master`）以及 SQLite 文件头版本计数的
  全局 root，并以 HMAC-SHA-256 加封；整体重算数据库、VACUUM 重写、替换数据库文件或旁车
  文件均无法匹配。
- 每次新请求或实际状态迁移都是 SQLite 与旁车之间的**可恢复提交**：先提交并 fsync
  SQLite，再经临时文件原子替换到 pending 名称，最后原子替换正式旁车；任一步失败都不会
  返回成功。旁车更新一律使用临时文件 + 原子替换。

### `recover()`

新增的只读恢复检查，返回三个状态之一：

| 返回值 | 含义 |
| --- | --- |
| `"valid"` | 旁车与数据库当前文件版本完全一致，无未完成提交 |
| `"invalid"` | 旁车可解析且认证通过，但 root/文件身份与数据库不符 |
| `"incomplete"` | 旁车缺失、损坏，或存在未完成的 pending 提交 |

`"invalid"` 与 `"incomplete"` 都会使 `verify_evidence` 返回 `False` 并拒绝新的写入
（`AnchorUnavailable`）；`recover()` 本身**绝不修复、回填或重新加封**。旧的无锚定数据库
不会被静默信任，旧版（无链哈希列）数据库仅执行一次纯追加迁移，迁移不覆盖既有审计记录，
之后才加封。
