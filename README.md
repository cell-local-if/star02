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

## 审计证据的可信锚定

`RequestStore` 在 SQLite 中维护请求行与仅追加的状态事件链（SHA-256 链）。
由于链本身完全存于可改写的 SQLite 内，单独重算链不能提供可信校验。可信
证据必须依赖调用方在 SQLite 与旁车之外保管的对称密钥：

```python
from forgetting_evidence.requests import RequestStore

store = RequestStore(
    "evidence.db",
    integrity_key=key_held_out_of_band,   # str | bytes；禁止落库、入日志或随回执返回
    anchor_path="evidence.db.anchors",    # 可选，默认位于数据库旁
)
receipt = store.submit("tenant-a", "subject-1", ["email"], "idempotency-key")
store.transition("tenant-a", receipt["request_id"], "processing")
store.verify_evidence("tenant-a", receipt["request_id"])  # True
```

- 旁车是仅追加的 HMAC-SHA256 锚点日志，每个事件序号一条记录，并带覆盖整个
  记录集合的摘要 MAC；密钥、可替代密钥的材料及链明文原文永不写入 SQLite、
  旁车、回执、异常或日志。
- 提交遵循可判定的两阶段协议：SQLite 提交前将锚点置为 `prepared`，提交后
  才翻转为 `committed`。任一阶段失败，调用都不会返回成功；重建实例后可通过
  `verify_evidence`（返回 `False`）与只读的 `recover()`（报告
  `committed`/`prepared`/`unanchored`/`inconsistent`/`corrupt`，后四者均为
  非有效状态）识别未完成或不一致的提交。`recover()` 从不修复、回填或改写证据。
- 失败关闭：未提供可验证密钥、旁车缺失或损坏、旧库无可信锚定、或提交中断时
  `verify_evidence` 一律返回 `False`。旧库升级只回填 SQLite 内的普通链链接，
  绝不伪造可信锚点；之后的密钥化迁移也不会回溯赋予信任。
- 删改/插入/调序事件、跨请求或跨租户替换事件与锚点、重算并替换 SQLite 与
  旁车公开内容、截断仅追加日志，均无法验证为真。正常重建后证据仍可验证；
  同状态重放、非法迁移、参数错误、缺失及跨租户访问不改变证据。

信任边界：密钥与（如需防御整库历史快照回滚的）单调计数器/密钥纪元必须由调用
方在两个文件之外保管；任何仅依赖文件自身内容的方案都无法识别“把两个文件同时
还原到某个曾经一致的历史快照”。
