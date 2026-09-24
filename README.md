# Forgetting Evidence Service

这是一个面向后端系统的机器遗忘证据服务，用于记录删除请求、执行状态和可验证回执。当前基线提供可运行的 Python 包、健康检查入口以及删除请求的受理与查询 HTTP API（SQLite 持久化），尚未实现删除执行、状态机推进或证据编排能力。

运行健康检查：

```bash
PYTHONPATH=src python3 -m forgetting_evidence health
```

启动 HTTP 服务（以数据库路径、监听地址和端口启动；启动时自动创建所需表）：

```bash
PYTHONPATH=src python3 -m forgetting_evidence serve ./data/evidence.db 0.0.0.0 8080
# 也可使用命名参数
PYTHONPATH=src python3 -m forgetting_evidence serve --db ./data/evidence.db --host 0.0.0.0 --port 8080
```

业务入口（仅两个）：

- `POST /requests`：受理删除请求。请求体为 JSON：`tenant_id`、`subject_id`、`idempotency_key` 均为非空字符串，`scopes` 为元素互异的非空字符串数组。
  成功返回单行 JSON，依次含 `request_id`（UUID）、`status`（`accepted`）、`created_at`（UTC RFC3339），并以换行结尾。
  同租户同幂等键同主体、同范围集合（与顺序无关）的重复提交返回首次回执；主体或范围集合不同返回 `409 {"error":"idempotency_conflict"}`。
- `GET /requests/{request_id}`：按请求编号查询本租户回执。租户通过 `X-Tenant-Id` 请求头或 `tenant_id` 查询参数指定，命中时返回与受理时完全一致的回执。

错误响应均为只含 `error` 字段的单行 JSON，使用稳定错误码：

| HTTP | error |
| --- | --- |
| 400 | `invalid_request`（非法 JSON、空值/非字符串、空范围或重复范围） |
| 404 | `not_found`（缺失请求、非法编号、跨租户查询、未知路径） |
| 405 | `method_not_allowed`（不支持的请求方法） |
| 409 | `idempotency_conflict`（同键不同主体或范围集合） |
| 503 | `storage_unavailable`（数据库不可创建、读写失败或内容损坏） |

受理在响应返回前已完成事务提交；关闭服务并用同一数据库重启后，查询结果保持字节一致。响应、日志与异常只暴露稳定错误码，不包含主体、范围、幂等键、SQL 原文或文件路径。

运行基础测试：

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

服务必须保持后端接口可自动验证，并避免在日志或回执中泄露待删除的原始数据。
