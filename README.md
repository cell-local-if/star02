# Forgetting Evidence Service

这是一个面向后端系统的机器遗忘证据服务，用于记录删除请求、执行状态和可验证回执。当前提供可运行的 Python 包、健康检查入口、删除请求的受理与查询 HTTP API（SQLite 持久化）、请求存储层上的可持久化状态机（状态推进与状态查询）、存储层上的删除执行编排（领取-租约-完成与执行记录），以及存储层上的删除回执生成与核验。状态推进、状态查询、执行编排与回执能力只在存储层开放，HTTP 仍只提供受理与受理回执查询两个端点，不新增任何执行或回执相关 HTTP 入口。

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

存储层执行编排（`RequestStore`，不经 HTTP 开放）：

- `claim_next(tenant_id, worker_id, lease_seconds)`：原子领取下一个可执行请求。`tenant_id`、`worker_id` 为非空字符串，`lease_seconds` 为 1 至 3600 的非布尔整数秒。候选为 `accepted` 请求及最新租约已过期的 `processing` 请求，按受理时间再按请求编号取最前者；首次领取使请求进入 `processing` 并开始第 1 次尝试，过期重领开始下一次尝试且不改变首次受理时间、编号或当前状态。同一请求同一时刻只有一个 worker 持有有效租约。成功返回恰好三个字段：`request_id`、不可预测的 `claim_token`、UTC RFC3339 的 `lease_expires_at`；无候选返回 `None`。worker 身份只校验不持久化，领取凭证只返回一次、绝不入库（仅存散列）或出现在日志中。
- `finish_claim(tenant_id, request_id, claim_token, result)`：以终态完成当前租约。`result` 只接受 `completed` 或 `failed`。凭证必须对应该租户该请求当前未过期、未释放的租约；终态状态与审计链事件、尝试结果记录、凭证释放在同一事务提交。返回状态记录（`request_id`、`status`、`created_at`）。
- `get_execution_log(tenant_id, request_id)`：按租户与请求编号返回执行尝试列表，按尝试序号（从 1 递增）排列。每条恰含 `attempt_number`（正整数）、`claimed_at` 与 `lease_expires_at`（UTC RFC3339 字符串）、`result` 与 `completed_at`（完成后为终态与完成时间，进行中或被过期放弃的尝试为空值）。返回值只含字符串、整数与空值，不含 worker 或领取凭证。
- `reconcile_execution(tenant_id, request_id)`：按租户和请求编号对账执行结果，返回既有状态记录（`request_id`、`status`、`created_at`）。
  - `accepted`（含无任何执行尝试）时只返回现状：不创建记录、尝试或回执，也不产生任何变化。
  - 仍有有效租约的 `processing` 请求保留进行中尝试，不提前写终态、不生成新尝试。
  - `completed` 或 `failed` 的重复对账幂等：保留首次终态结果与同一状态记录；执行记录中存在多个终态时保留最早完成的结果，后续重复终态记为 `failed` 且不改请求状态。
  - 最新租约已过期且无其他有效租约（含无结果且无租约、或无任何可解释尝试）的 `processing` 请求，在同一事务内把全部未完成尝试补偿为 `failed`（完成时间为 UTC RFC3339，且每条只写一次），并把请求状态收敛为 `failed`；执行记录已含终态尝试时，以最早完成结果收敛，死租约凭证随补偿一并释放。
- `claim_next` 的领取边界收紧：仍按受理时间再按请求编号竞争可执行请求；候选仅为 `accepted`，以及具有可解释的已过期租约历史（至少存在一次尝试、最新租约已过期、且不存在仍在租期内的未完成尝试）的 `processing` 请求，过期重领生成递增的新尝试。无可解释租约或尝试的 `processing` 请求不得领取，交由 `reconcile_execution` 收敛。
- `reconcile_batch(tenant_id, cursor=None, limit=None)`：按租户批量对账待收敛请求，可携带可选游标与批次上限（缺省 100，1 至 1000 的非布尔整数），不经 HTTP 开放。首次调用（无游标）创建持久化批次并按受理时间再按请求编号稳定扫描；携带游标时恢复该游标对应的持久化批次，从已提交位置续跑，同一游标重试沿用同一批次标识。返回恰好四个字段：`batch_id`（字符串）、`next_cursor`（结束时为空值，否则为字符串游标）、`finished`（布尔，表示是否已扫完全部行）与 `items`（逐项记录列表，按扫描顺序稳定排列；每项恰含 `request_id` 与 `status`）。返回值中时间与游标只用字符串、计数与尝试序号只用整数、空值保持空值，不出现浮点数、负零或非有限数。
  - 批次首次扫描跳过 `accepted` 请求：不创建尝试、回执或额外状态事件，但游标位置仍向前推进，使该请求不会被重复扫描。
  - 仍有有效租约的 `processing` 请求保持处理中，不提前完成也不生成新尝试；租约过期、无结果或无可解释租约的 `processing` 请求按 `reconcile_execution` 既有规则在同事务内补偿为 `failed`（执行记录已含终态时以最早完成结果收敛）。
  - 可恢复游标持久化在数据库中：重复扫描、对账或服务重启后，同游标重试从持久化位置续跑，已落定的逐项状态不重复写入。每项的状态、尝试、租约、批次逐项记录与游标位置在同一事务落定，提交失败不返回半成结果、不留下半成记录。
- 服务重启后租约与尝试记录继续有效；并发领取、完成与对账都在同一事务原子提交状态、尝试与租约，不会形成两个同时有效的租约，锁冲突不泄露底层数据库错误。

存储层删除回执（`RequestStore`，不经 HTTP 开放）：

- `generate_receipt(tenant_id, request_id, key)`：为已完成删除且执行记录落定的请求生成外部可核验的删除回执。只有状态为 `completed` 且最早终态尝试记录为 `completed` 的请求可取得回执；`accepted`、`processing`、`failed` 或无落定执行记录的请求统一抛 `ReceiptUnavailable`。多个终态尝试存在时回执关联最早完成的执行结果，后续重复终态不改变回执内容。
  - 回执为单行紧凑 JSON（固定字段顺序，恰好一个末尾换行），依次含 `tenant_id`、`request_id`、`created_at`（首次受理时间）、`completed_at`（最终完成时间）、`scope_digest`（范围承诺摘要）、`attempt_digest`（完成尝试摘要）与 `tag`（认证标签）；时间为 UTC RFC3339，摘要与标签均为 64 位小写十六进制。回执只含业务字段，不暴露主体、原始范围、幂等键、worker、领取凭证、SQL 或路径。
  - 认证标签使用调用方在数据库之外保管的密钥 `key`（非空字符串）以 HMAC-SHA256 计算；密钥材料绝不进入数据库、回执、异常或日志。
  - 首次生成原子提交，不留半份记录，也不改变状态、尝试、租约或审计记录；同一请求重复生成（无论是否同一密钥）返回字节一致的首次回执，并发生成只落一份，实例重建或服务重启后内容不变。回执记录损坏或存储不可用时抛固定文案 `OSError`，绝不回填、重算或覆盖已有回执。
- `verify_receipt(receipt_text, key)`：核验回执文本与密钥。仅当文本格式合法、与已落定回执记录逐字段完全一致、且认证标签在所给密钥下重算一致时返回 `True`；字段、认证标签、时间、请求或租户关联被替换，或格式合法但认证不匹配时一律返回 `False`——请求记录存在不能替代认证结果，请求或回执不存在同样只返回 `False`。核验不写入或修复任何数据。
- 回执错误语义：生成入口的租户、请求编号或密钥为空、类型或格式非法抛 `ValueError` 且不写库；请求不存在、跨租户或尚未受理统一抛 `RequestNotFound`，不区分记录是否存在；请求尚未完成删除抛 `ReceiptUnavailable`；核验入口参数非法抛 `ValueError`，存储不可用或回执记录损坏抛固定文案 `OSError`。

执行编排错误语义（在既有错误语义基础上补充）：

- 入口参数、租期或终态不满足值域：抛 `ValueError` 且不写库。
- 领取凭证不存在、过期、已释放或跨租户/跨请求使用，或对无有效租约的请求完成（含对账释放死租约后再用旧凭证完成）：抛 `ClaimConflict` 且不改变状态、尝试或证据。
- 执行记录查询与对账中请求编号缺失、空、非字符串、非法、不存在或跨租户：统一抛 `RequestNotFound`，不区分记录是否存在；对账租户为空或非字符串抛 `ValueError`，不改变状态、尝试或回执。
- 批量入口 `reconcile_batch` 的租户为空或非字符串、上限非 1 至 1000 的非布尔整数、游标为空/非字符串/格式未知/指向不存在或跨租户批次：统一抛 `ValueError` 且不写库（未知游标格式也按非法处理，不区分批次是否存在）；数据库不可读写、批次或执行记录损坏或批次提交失败：统一抛固定文案的 `OSError`，不返回半成结果。
- `finish_claim` 在请求编号未知或跨租户、且凭证同时无效（未知、已释放或过期）时，稳定先抛 `RequestNotFound`；对确实存在的请求使用无效凭证仍抛 `ClaimConflict`，合法有效凭证跨请求/跨租户使用仍抛 `ClaimConflict`，且不改变状态、尝试或证据。
- 数据库不可创建、读写失败、执行记录损坏或补偿提交失败：统一抛固定文案的 `OSError`，不返回半成结果、不留下半成记录。

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
