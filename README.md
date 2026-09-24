# Forgetting Evidence Service

这是一个面向后端系统的机器遗忘证据服务，用于记录删除请求、执行状态和可验证回执。当前提供可运行的 Python 包、健康检查入口、删除请求的受理与查询 HTTP API（SQLite 持久化）、请求存储层上的可持久化状态机（状态推进与状态查询），以及存储层上的删除执行编排（领取-租约-完成、执行记录、单请求对账与按租户的可恢复游标批量对账）。状态推进、状态查询与执行编排只在存储层开放，HTTP 仍只提供受理与受理回执查询两个端点，不新增任何执行相关 HTTP 入口。

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
- `reconcile_batch(tenant_id, cursor=None, max_items=None)`：按租户批量执行对账，可携带可选游标与批次上限，不新增任何 HTTP 入口。
  - 参数校验通过后按受理时间再按请求编号的稳定顺序扫描本租户待收敛请求：`accepted` 请求首次扫描即跳过，不创建尝试、回执或额外状态事件；仍有有效租约的 `processing` 保持处理中（不提前完成、不生成新尝试）；租约过期、无结果或无可解释租约的 `processing` 按既有 `reconcile_execution` 规则在同一事务补偿为 `failed`；`completed`/`failed` 为幂等空操作。
  - 返回恰含 `batch_id`、`next_cursor`（仍有后续时为字符串游标，结束时为空值）、`finished`（布尔）与 `items`；`items` 按请求顺序稳定排列，每项只含 `request_id` 与 `status`。时间与游标只用字符串，计数与尝试序号只用整数，空值保持空值，不出现浮点数、负零或非有限数。
  - 每项的状态、尝试、租约与游标推进在同一事务落定；批次被中断后凭游标从持久化位置续跑，重复扫描、对账与重启幂等：同一游标重试沿用同一 `batch_id` 并回放同一窗口（相同项、相同状态与顺序）。游标为不透明字符串，格式未知或令牌无法识别均按非法处理。
  - 同一请求并发扫描、对账或领取只形成一个合法终态，已落定尝试不重复写入；并发竞争不泄露底层锁错误。
- 服务重启后租约、尝试与批次记录继续有效；并发领取、完成、单请求对账与批量对账都在同一事务原子提交状态、尝试、租约与游标，不会形成两个同时有效的租约，锁冲突不泄露底层数据库错误。

执行编排错误语义（在既有错误语义基础上补充）：

- 入口参数、租期或终态不满足值域：抛 `ValueError` 且不写库。
- 领取凭证不存在、过期、已释放，或对本租户可见但无有效租约的请求完成（含对账释放死租约后再用旧凭证完成）：抛 `ClaimConflict` 且不改变状态、尝试或证据。
- 执行记录查询与对账中请求编号缺失、空、非字符串、非法、不存在或跨租户：统一抛 `RequestNotFound`，不区分记录是否存在；对账租户为空或非字符串抛 `ValueError`，不改变状态、尝试或回执。
- `finish_claim` 遇请求编号未知、非法或对本租户不可见（跨租户）且凭证不是该坐标当前有效租约时，稳定先抛 `RequestNotFound`，无论凭证如何读取都不改变状态、尝试或证据；仅当请求对本租户可见而凭证无效时才抛 `ClaimConflict`。
- 批量对账的租户非法、游标为空/非字符串/格式未知/令牌无法识别（含跨租户游标）、上限不是 1 至 1000 的非布尔整数：抛 `ValueError` 且不写库。
- 数据库不可创建、读写失败、执行记录或批次记录损坏或批次提交失败：统一抛固定文案的 `OSError`，不返回半成结果、不留下半成记录。

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
