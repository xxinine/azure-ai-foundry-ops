# Foundry IP Allowlist

[中文文档](README.zh-CN.md)

Set IP firewall rules for Microsoft Foundry (`AIServices`) and Azure OpenAI
(`OpenAI`) accounts using Python's standard library and Azure CLI. No pip
packages are required. Run examples from the repository root.

## Prerequisites

- Python 3.9 or later and Azure CLI, authenticated using `az login --tenant <tenant-id>`.
- Read access to each target account and `Microsoft.CognitiveServices/accounts/write`
  for changes (for example, Cognitive Services Contributor).
- For management group discovery, permission for
  `Microsoft.Management/managementGroups/descendants/read` on the selected group,
  and permission to list accounts in every descendant subscription.
- Use subscription **IDs**, management group **IDs** (not display names), and
  account-level resource IDs. Child projects/deployments and legacy Azure ML hubs
  are not supported targets; their network models differ.

The script uses the current Azure CLI cloud's ARM endpoint and passes an explicit
subscription context on subscription-scoped requests. It never calls `az account
set`. Run separately for different tenants with the appropriate CLI login.

## Management Group: All Descendant Subscriptions

Includes subscriptions nested under child management groups. ARM pagination is
followed for both descendants and account discovery.

```bash
python3 networking/set_foundry_ip_allowlist.py \
  --management-group <management-group-id> \
  --ip <office-public-ip> \
  --ip <office-public-cidr>
```

Review the printed resource IDs, `before` snapshots, and proposed PATCH bodies.
To execute, rerun with the same options plus `--apply --yes`.

## Selected Subscriptions: All Foundry/OpenAI Accounts

Repeat `--subscription` to select multiple subscriptions:

```bash
python3 networking/set_foundry_ip_allowlist.py \
  --subscription <subscription-id-1> \
  --subscription <subscription-id-2> \
  --ip <office-public-ip>
```

Append `--apply` after reviewing the preview.

## Selected Foundry Accounts

Repeat `--resource-id` for multiple accounts, including accounts across subscriptions:

```bash
python3 networking/set_foundry_ip_allowlist.py \
  --resource-id /subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<foundry-name> \
  --ip <office-public-ip>
```

The three scope selectors are mutually exclusive. Exact IDs prevent ambiguity
when names repeat in different subscriptions or resource groups.

## IP Files and Replacement

`--ip-file` reads one public IPv4 address or CIDR per line. Blank lines and `#`
comments are ignored. It can be combined with repeatable `--ip` options.

```bash
python3 networking/set_foundry_ip_allowlist.py \
  --subscription <subscription-id> \
  --ip-file ./allowed-ips.txt \
  --replace \
  --apply
```

By default, IPs are **appended** to existing IP rules. `--replace` replaces only
the IP rules; VNet rules and trusted-services bypass remain unchanged.
Only public IPv4 is accepted. CIDRs must use the network address (host bits are
rejected); `/32` becomes one address and `/31` becomes two individual rules.
The final allowlist must contain 1 to 100 rules. Duplicate rules are removed.

## Allow All Networks and Remove the IP Allowlist

Use the explicit `--allow-all-networks` mode instead of supplying IP options:

```bash
python3 networking/set_foundry_ip_allowlist.py \
  --resource-id /subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<foundry-name> \
  --allow-all-networks
```

Review the preview, then append `--apply` to execute. This sets
`networkAcls.defaultAction=Allow`, clears `ipRules`, and explicitly sets
`publicNetworkAccess=Enabled`, including for previously disabled public access.
It preserves VNet rules, trusted-services bypass, and private endpoints. Authentication
is still required. Network Security Perimeter associations are not changed and may
independently restrict access.

This mode cannot be combined with `--ip`, `--ip-file`, `--replace`, or
`--enable-public-network`. All three target scopes remain supported; management-group
writes still require `--yes`. Backups, concurrency checks, and read-back verification
apply as usual. **This removes the account's network-based IP restriction.**

## Safety and Network Semantics

- Without `--apply`, discovery and preview are read-only and no backup is written.
- In IP allowlist mode, sets `networkAcls.defaultAction=Deny`, otherwise an IP allowlist has no effect.
  **This can disconnect existing clients whose outbound IPs are not allowed.**
- Preserves VNet rules and the trusted Azure services bypass, if present. Warns
  when `bypass=AzureServices`. Private endpoints remain untouched. This is not an
  IP-only isolation policy: these existing alternative paths remain allowed.
- In IP allowlist mode, refuses accounts whose public access is `Disabled`, `SecuredByPerimeter`, or
  any other non-Enabled value. Use `--enable-public-network` only when intentionally
  enabling public access for the listed IPs. It does not configure or remove
  Network Security Perimeter associations, which may independently block access.
- Preflights **every** discovered resource before the first write. Any discovery
  or preflight failure prevents all writes; inaccessible subscriptions are not
  silently skipped. Disabled/inaccessible subscriptions may therefore block a
  management-group run; select eligible subscriptions explicitly in that case.
- Saves original network configuration, ETags, resource IDs, and intended changes
  in a new `foundry-network-backup-<UTC timestamp>.json` file before writing. File
  permissions are `0600`; `--backup-file PATH` customizes its location and existing
  files are never overwritten. Backup files contain network details, not secrets;
  keep them outside source control. The backup is for manual recovery, not an
  automatic rollback command. Review current state before restoring old settings.
- Re-reads each account before PATCH and aborts that account if its ETag or network
  settings changed. Sends `If-Match` when an ETag is supplied. The documented update
  API does not promise conditional-write enforcement; avoid concurrent network
  administration. The comparison cannot eliminate all races if Azure ignores it.
- PATCH sends only network properties, not identity, model deployments, tags, SKU,
  authentication, or private endpoint configuration.
- Polls account state and verifies IP rules, default action, VNet rules, bypass,
  and public access after each write. `--wait-seconds` defaults to 300 per account;
  each Azure CLI call has a separate 120-second timeout. ARM verification is not a
  data-plane connectivity test; firewall propagation and DNS may still take time.
- During execution, per-account failures are reported and other ready accounts
  continue. There is no cross-account transaction or automatic rollback. A failed
  or timed-out PATCH may still have reached Azure; inspect current state before
  rerunning. Writes are not automatically retried. Any failure exits nonzero.

Ensure all required client **outbound public IPs** are included. Network allowlisting
does not replace Entra ID/RBAC or API key authentication. Azure Policy deny rules
and resource locks can prevent updates; the script does not bypass either.

## Offline Tests

```bash
python3 -m unittest discover -s networking -p 'test_*.py' -v
```

## References

- [Network firewall behavior and IP restrictions](https://learn.microsoft.com/azure/ai-services/cognitive-services-virtual-networks)
- [Accounts Update REST API](https://learn.microsoft.com/rest/api/aiservices/accountmanagement/accounts/update?view=rest-aiservices-accountmanagement-2024-10-01)
- [Management group descendants REST API](https://learn.microsoft.com/rest/api/managementgroups/)