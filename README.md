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

服务必须保持后端接口可自动验证，并避免在日志或回执中泄露待删除的原始数据。

## 审计证据与受保护锚定

`RequestStore` 在 SQLite 中保存删除请求与只增的状态事件链，每个事件的
`chain_hash` 将租户、请求、序号、状态、发生时间与前一事件哈希绑定；请求行保存
链头。仅凭数据库内哈希只能做到“可发现篡改”：能改写整个数据库的攻击者同样可以
重算全部摘要。

为此，完整性判断额外依赖**不存放在 SQLite 中**的受保护锚定材料：

- 默认在数据库旁自动配置两个 `0600` 文件：
  - `<db_path>.anchor.key`：256 位主密钥（`secrets.token_bytes` 自动生成，
    跨实例重建时复用）；
  - `<db_path>.anchor`：锚定日志，原子改写（同目录临时文件 + `os.replace` +
    `fsync`）。每个请求在新建与每次实际状态迁移时，随请求行/事件行在同一数据库
    写事务内写入一条对 `(tenant_id, request_id, 链头)` 的 HMAC-SHA256。
- 校验时重算事件链并把链头与库外锚定日志中的 HMAC 比对。攻击者即使删改、插入、
  调序、跨请求或跨租户替换事件，并重算替换全部 SQLite 内容（包括库内任何伪造的
  锚定字段），没有主密钥仍无法通过 `verify_evidence`。
- 主密钥、密钥派生原文与可伪造锚定状态从不写入 SQLite、回执、异常消息或日志；
  锚定日志只包含非敏感的 `(租户, 请求)` 坐标与 HMAC。
- `verify_evidence` 只读，不修复、不回填、不重写。缺失受保护材料或来自无锚定
  旧版本的数据库会以固定文案抛出 `EvidenceNotAnchored`，旧审计记录保持原样、
  绝不被静默认定可信，也不会被升级覆盖。

默认构造 `RequestStore(db_path)` 即可获得上述全部行为；同一数据库在重建实例后
仍可验证新建请求。需要显式注入密钥或更换文件位置时，可用具名可选配置：

```python
from forgetting_evidence.anchors import AnchorConfig
from forgetting_evidence.requests import RequestStore

# 注入密钥（跨实例/跨机器共享同一受保护材料）
RequestStore(db_path, anchor_config=AnchorConfig(key=b"shared-secret"))
# 或使用独立密钥文件、十六进制密钥、自定义锚定日志位置
AnchorConfig(key_file="/etc/forgetting/master.key")
AnchorConfig(key_hex="...")
AnchorConfig(anchor_file="/var/lib/forgetting/anchors.json")
# auto_init=False 时不自动创建任何受保护文件（无法锚定的写入直接失败）
AnchorConfig(auto_init=False)
```

跨实例迁移验证能力时必须同时复制数据库、锚定日志与主密钥文件；只复制数据库
永远无法通过验证。
