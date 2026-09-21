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

## 受保护的证据锚定

审计事件链与请求链头本身存放在 SQLite 中，任何能改写该数据库的人都可以
重新计算普通哈希。为防止此类“全库重写”攻击，`RequestStore` 在数据库之外
维护受保护锚定材料：

- 主密钥文件（默认 `<db>.key`，权限 `0600`）：首次启动自动生成，可跨实例
  复用；不会写入 SQLite、回执、异常或日志。
- 追加式锚定日志（默认 `<db>.anchorlog`，权限 `0600`）：每次新建请求和
  每次实际状态迁移都会在 SQLite 提交前原子追加一条 HMAC 记录，记录全局
  串联并绑定租户、请求、序号、状态、时间戳、最终链头以及事件/链头 MAC。
- 数据库内的 `anchor_mac` 列保存由外部密钥计算的 HMAC，脱离密钥无法伪造。

`verify_evidence` 为纯只读校验：普通哈希链、库内 HMAC、请求头 MAC 与外部
锚定日志必须全部一致。删改/插入/调序/跨请求或跨租户替换事件、篡改链头，
乃至攻击者重算并替换 SQLite 内全部内容，都会返回 `False`。

可选命名参数（默认 `RequestStore(db_path)` 调用方式不变）：

```python
RequestStore(
    db_path,
    anchor_key=b"..."            # 直接注入主密钥（外部托管，不落盘）
    # 或 anchor_key_file="/secure/master.key",
    # anchor_journal_file="/secure/anchors.log",
)
```

部署须知：密钥文件与锚定日志必须与数据库文件分开保护（独立权限/备份/
介质）。仅复制数据库而不携带受保护材料时，其中任何请求都无法通过验证。
受保护锚定出现之前创建的旧库会以附加列方式升级，但旧记录不会被回填
锚点，因而不会被静默采信——`verify_evidence` 对其返回 `False`，原有审计
记录保持原样不被覆盖。

