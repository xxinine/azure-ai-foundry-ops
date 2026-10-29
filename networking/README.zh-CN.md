# Foundry IP 白名单

[English](README.md)

使用 Python 标准库和 Azure CLI，为 Microsoft Foundry（`AIServices`）和 Azure OpenAI
（`OpenAI`）资源设置 IP 防火墙规则。无需安装额外的 pip 包。
以下示例均在仓库根目录执行。

## 前置条件

- Python 3.9 或更高版本，以及 Azure CLI。使用 `az login --tenant <tenant-id>` 登录目标租户。
- 对每个目标资源具有读取权限；实际修改还需要
  `Microsoft.CognitiveServices/accounts/write` 权限，例如 Cognitive Services Contributor 角色。
- 按管理组发现资源时，需要在所选管理组上具有
  `Microsoft.Management/managementGroups/descendants/read` 权限，
  并能够列出其下每个订阅中的资源。
- 使用订阅 **ID**、管理组 **ID**（不是显示名称），以及资源账户级别的完整资源 ID。
  不支持将子项目、模型部署或旧版 Azure ML Hub 作为目标，它们的网络模型不同。

脚本使用 Azure CLI 当前云环境的 ARM 地址，并为订阅级请求显式指定订阅上下文，
不会调用 `az account set` 切换默认订阅。涉及不同租户时，请分别登录对应租户后运行。

## 管理组下的全部订阅

包括嵌套子管理组中的订阅。管理组后代枚举和资源发现都会处理 ARM 分页。

```bash
python3 networking/set_foundry_ip_allowlist.py \
  --management-group <management-group-id> \
  --ip <office-public-ip> \
  --ip <office-public-cidr>
```

默认只预览。检查输出的资源 ID、`before` 原始配置快照和拟提交的 PATCH 请求体后，
在相同命令后追加 `--apply --yes` 才会实际修改。

## 指定订阅中的全部 Foundry/OpenAI 资源

重复使用 `--subscription` 可选择多个订阅：

```bash
python3 networking/set_foundry_ip_allowlist.py \
  --subscription <subscription-id-1> \
  --subscription <subscription-id-2> \
  --ip <office-public-ip>
```

确认预览结果后追加 `--apply` 执行修改。

## 指定 Foundry 资源

重复使用 `--resource-id` 可指定多个资源，也可跨订阅选择：

```bash
python3 networking/set_foundry_ip_allowlist.py \
  --resource-id /subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<foundry-name> \
  --ip <office-public-ip>
```

确认预览结果后追加 `--apply` 执行修改。
三种目标范围参数互斥，不能混用。完整资源 ID 可以避免不同订阅或资源组中同名资源的歧义。

## IP 文件与替换模式

`--ip-file` 从文件读取规则，每行一个公网 IPv4 地址或 CIDR，忽略空行和 `#` 注释。
可以同时使用 `--ip-file` 和多个 `--ip` 参数。

```bash
python3 networking/set_foundry_ip_allowlist.py \
  --subscription <subscription-id> \
  --ip-file ./allowed-ips.txt \
  --replace \
  --apply
```

默认在现有 IP 规则上**追加**。`--replace` 只替换 IP 规则，
不会删除已有 VNet 规则或修改可信 Azure 服务绕过配置。

只接受公网 IPv4。CIDR 必须使用网络地址，带有非零主机位的输入会被拒绝。
`/32` 会转换为一条单 IP 规则，`/31` 会转换为两条单 IP 规则。
最终白名单必须包含 1 至 100 条规则；完全重复的规则会被去重。

## 允许所有网络并移除 IP 白名单

使用明确的 `--allow-all-networks` 模式，无需提供 IP 参数：

```bash
python3 networking/set_foundry_ip_allowlist.py \
  --resource-id /subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<foundry-name> \
  --allow-all-networks
```

检查预览后追加 `--apply` 执行。此模式将 `networkAcls.defaultAction` 设为 `Allow`，
清空 `ipRules`，并显式将 `publicNetworkAccess` 设为 `Enabled`，即使原先禁用了公网也会开启。
保留 VNet 规则、可信服务绕过配置和专用终结点，访问仍需通过身份认证。
不会修改网络安全边界关联，其策略仍可能独立限制访问。

此模式不能与 `--ip`、`--ip-file`、`--replace` 或 `--enable-public-network` 混用。
仍支持三种目标范围；管理组范围写入仍需 `--yes`。
备份、并发变更检查和回读验证机制保持不变。
**此操作会移除资源自身基于 IP 的网络访问限制。**

## 安全机制与网络行为

- 不指定 `--apply` 时，资源发现和预览均为只读操作，也不会生成备份文件。
- 白名单模式将 `networkAcls.defaultAction` 设置为 `Deny`，否则 IP 白名单不会限制访问。
  **未包含在允许规则中的现有客户端可能因此断开连接。**
- 保留已有 VNet 规则和可信 Azure 服务绕过配置。发现 `bypass=AzureServices` 时会警告。
  不修改专用终结点。这不是“仅允许指定 IP”的严格隔离策略，已有的其他允许路径仍然保留。
- 白名单模式对公网访问状态为 `Disabled`、`SecuredByPerimeter` 或其他非 `Enabled` 值的资源，
  默认拒绝修改。只有明确希望为白名单 IP 开启公网访问时，才使用 `--enable-public-network`。
  脚本不会配置或移除网络安全边界（Network Security Perimeter）关联，边界策略仍可能独立阻止访问。
- 首次写入前会对**所有**发现的资源进行预检。任一发现或预检操作失败，整批均不写入，
  不会静默跳过无权访问的订阅。因此，已禁用或不可访问的订阅可能阻止管理组范围的运行；
  此时可改为显式指定符合条件的订阅。
- 写入前，将原始网络配置、ETag、资源 ID 和拟执行的修改保存到新的
  `foundry-network-backup-<UTC时间戳>.json` 文件，文件权限为 `0600`。
  可用 `--backup-file PATH` 自定义路径，不会覆盖已有文件。
  备份包含网络信息，不含密钥，应避免提交到版本控制。
  备份用于手动恢复，不是自动回滚命令；恢复旧配置前应先检查当前资源状态。
- 每个资源提交 PATCH 前都会重新读取配置；如果 ETag 或网络设置与预检时不同，
  则中止该资源的修改。Azure 返回 ETag 时会附带 `If-Match` 请求头。
  更新接口文档没有保证强制执行条件写入，因此应避免并发修改网络配置；
  如果服务忽略该请求头，前置比较无法完全消除竞态。
- PATCH 仅提交网络属性，不提交身份、模型部署、标签、SKU、认证或专用终结点配置。
- 每次写入后轮询资源状态，回读验证 IP 规则、默认动作、VNet 规则、绕过配置和公网访问状态。
  `--wait-seconds` 默认为每个资源 300 秒；每次 Azure CLI 调用另有 120 秒超时。
  ARM 配置验证不等于数据面连通性测试，防火墙传播和 DNS 更新仍可能需要时间。
- 执行阶段按资源报告失败，并继续处理其他已通过预检的资源。
  不提供跨资源事务或自动回滚。失败或超时的 PATCH 仍可能已到达 Azure，
  重新运行前应检查实际状态。脚本不会自动重试写入，任一失败均以非零退出码结束。

请确保包含所有必要客户端的**出口公网 IP**。
网络白名单不能替代 Entra ID/RBAC 或 API 密钥认证。
Azure Policy 拒绝规则和资源锁可能阻止更新，脚本不会绕过这些限制。

## 离线测试

```bash
python3 -m unittest discover -s networking -p 'test_*.py' -v
```

## 参考资料

- [网络防火墙行为与 IP 限制](https://learn.microsoft.com/azure/ai-services/cognitive-services-virtual-networks)
- [Accounts Update REST API](https://learn.microsoft.com/rest/api/aiservices/accountmanagement/accounts/update?view=rest-aiservices-accountmanagement-2024-10-01)
- [管理组 REST API](https://learn.microsoft.com/rest/api/managementgroups/)