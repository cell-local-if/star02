# Forgetting Evidence Service

这是一个面向后端系统的机器遗忘证据服务，用于记录删除请求、执行状态和可验证回执。当前基线只提供可运行的 Python 包与健康检查入口，尚未实现业务 API、持久化或证据编排能力。

运行健康检查：

```bash
PYTHONPATH=src python3 -m forgetting_evidence health
```

启动删除请求受理与查询服务（SQLite 持久化，启动时自动建表）：

```bash
PYTHONPATH=src python3 -m forgetting_evidence serve \
    --db ./data/evidence.db --host 127.0.0.1 --port 8080
```

HTTP 层只提供两个业务入口：

- `POST /requests`：受理删除请求。请求体为 JSON，字段 `tenant_id`、`subject_id`、`idempotency_key` 均为非空字符串，`scopes` 为元素互异的非空字符串数组。查询侧可通过 `X-Tenant-ID` 请求头或 `tenant_id` 查询参数指定租户（同时提供时必须一致）。
- `GET /requests/<request_id>`：在同一租户下按请求编号查询回执。

成功响应为单行 JSON（末尾带换行），字段依次为 `request_id`（UUID）、`status`（`accepted`）、`created_at`（UTC RFC3339）。同租户同幂等键且主体、范围集合一致时始终返回首次回执；范围顺序不参与比较；主体或范围不同返回 `409 {"error":"idempotency_conflict"}`。

错误响应只含 `error` 字段，稳定错误码包括：`invalid_request`（400，非法 JSON、空值、非字符串、空范围或重复范围，且不写库）、`not_found`（404，缺失请求、非法编号、跨租户查询、未知路径）、`method_not_allowed`（405）、`storage_unavailable`（503，存储不可创建、读写失败或内容损坏）。响应、日志与异常只暴露这些错误码，不泄露主体、范围、幂等键、SQL 原文或文件路径。

运行基础测试：

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

服务必须保持后端接口可自动验证，并避免在日志或回执中泄露待删除的原始数据。
