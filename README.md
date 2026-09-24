# Forgetting Evidence Service

这是一个面向后端系统的机器遗忘证据服务，用于记录删除请求、执行状态和可验证回执。当前提供可运行的 Python 包、健康检查入口、删除请求的受理与查询 HTTP API（SQLite 持久化），以及请求存储层上的可持久化状态机（状态推进与状态查询）。状态推进与状态查询只在存储层开放，HTTP 仍只提供受理与受理回执查询两个端点，暂不实现删除执行编排能力。

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

业务入口（HTTP 仅两个）：

- `POST /requests`：受理删除请求。请求体为 JSON：`tenant_id`、`subject_id`、`idempotency_key` 均为非空字符串，`scopes` 为元素互异的非空字符串数组。
  成功返回单行 JSON，依次含 `request_id`（UUID）、`status`（`accepted`）、`created_at`（UTC RFC3339），并以换行结尾。
  同租户同幂等键同主体、同范围集合（与顺序无关）的重复提交返回首次回执；主体或范围集合不同返回 `409 {"error":"idempotency_conflict"}`。
- `GET /requests/{request_id}`：按请求编号查询本租户的**受理回执**。租户通过 `X-Tenant-Id` 请求头或 `tenant_id` 查询参数指定，命中时返回与受理时完全一致的回执；该回执在状态推进后保持不变，始终为受理时的 `accepted` 记录（请求编号与受理时间也保持首次值）。

存储层状态机（`RequestStore`，不经 HTTP 开放）：

- 生命周期固定为 `accepted -> processing -> {completed, failed}` 以及 `accepted -> failed`；受理记录自 `accepted` 开始，`completed` 与 `failed` 为终态。
- `transition(tenant_id, request_id, target_status)`：按迁移图推进。重复推进到当前状态是幂等空操作，返回当前状态记录且不追加状态、不改首次受理时间/编号/幂等回执。
- `get_status(tenant_id, request_id)`：按租户和请求编号返回当前状态记录，结构、字段顺序与受理回执一致（`request_id`、`status`、`created_at`），但 `status` 为最新状态、`created_at` 仍为首次受理时间；实例重建后结果一致。
- 并发推进同一请求时，仅允许迁移图允许的最终结果，底层锁冲突不会作为调用方错误泄露。

错误语义（存储层异常类型稳定，回执、返回值与日志只暴露请求编号、状态、时间与稳定错误类型，不含主体、范围、幂等键、其他租户信息、SQL 原文或路径）：

- 受理、推进或查询中，除请求编号外的参数非法、范围为空或重复、目标状态越界：抛 `ValueError` 且不写库。
- 请求编号非法、请求不存在、跨租户访问或尚未受理：统一抛 `RequestNotFound`，不区分记录是否存在。
- 已定义状态之间发生非法迁移（含从终态继续推进）：抛 `InvalidStatusTransition`，原状态不变。
- 同一幂等键提交不同主体或范围集合：抛 `IdempotencyConflict`，首次受理回执不变。
- 存储路径为空或非字符串：抛 `ValueError`；数据库不可创建、目录不可写、读写失败或内容损坏：统一抛固定文案的 `OSError`，状态写入失败时不返回半成状态。

HTTP 错误响应均为只含 `error` 字段的单行 JSON，使用稳定错误码：

| HTTP | error |
| --- | --- |
| 400 | `invalid_request`（非法 JSON、空值/非字符串、空范围或重复范围） |
| 404 | `not_found`（缺失请求、非法编号、跨租户查询、未知路径） |
| 405 | `method_not_allowed`（不支持的请求方法；HTTP 不提供状态推进端点） |
| 409 | `idempotency_conflict`（同键不同主体或范围集合） |
| 503 | `storage_unavailable`（数据库不可创建、读写失败或内容损坏） |

受理在响应返回前已完成事务提交；关闭服务并用同一数据库重启后，受理回执字节一致、当前状态记录一致。健康命令、HTTP 错误码与回执格式保持兼容。响应、日志与异常只暴露稳定错误码，不包含主体、范围、幂等键、SQL 原文或文件路径。

运行基础测试：

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

服务必须保持后端接口可自动验证，并避免在日志或回执中泄露待删除的原始数据。
