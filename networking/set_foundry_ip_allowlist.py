#!/usr/bin/env python3
"""Preview or apply IP allowlists or all-network access to Foundry/OpenAI accounts."""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import quote, urlsplit


API_VERSION = "2024-10-01"
KINDS = {"aiservices", "openai"}
NON_PUBLIC_RANGES = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4",
))
ACCOUNT_ID = re.compile(
    r"^/subscriptions/([^/]+)/resourceGroups/[^/]+"
    r"/providers/Microsoft\.CognitiveServices/accounts/[^/]+$", re.IGNORECASE
)


def run_az(arguments: Sequence[str]) -> Any:
    completed = subprocess.run(
        ["az", *arguments, "--only-show-errors", "--output", "json"],
        capture_output=True, text=True, check=False, timeout=120,
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    return json.loads(completed.stdout) if completed.stdout.strip() else None


class ArmClient:
    def __init__(self, endpoint: str) -> None:
        self.endpoint = endpoint.rstrip("/")

    def request(
        self, method: str, url: str, body: dict[str, Any] | None = None,
        etag: str | None = None,
    ) -> Any:
        if url.startswith("/"):
            url = self.endpoint + url
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != urlsplit(self.endpoint).netloc:
            raise ValueError(f"Refusing non-ARM URL: {url}")
        arguments = ["rest", "--method", method, "--url", url]
        match = re.match(r"/subscriptions/([^/]+)/", parsed.path, re.IGNORECASE)
        if match:
            arguments.extend(("--subscription", match.group(1)))
        if body is not None:
            arguments.extend(("--body", json.dumps(body, separators=(",", ":"))))
        if etag:
            arguments.extend(("--headers", f"If-Match={etag}"))
        return run_az(arguments)

    def list_all(self, url: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        visited: set[str] = set()
        while url:
            if url in visited:
                raise RuntimeError("ARM returned a repeated pagination link")
            visited.add(url)
            page = self.request("get", url)
            if not isinstance(page, dict) or not isinstance(page.get("value"), list):
                raise RuntimeError("Unexpected ARM list response")
            items.extend(page["value"])
            url = page.get("nextLink") or ""
        return items

    def account(self, resource_id: str) -> dict[str, Any]:
        account = self.request("get", f"{resource_id}?api-version={API_VERSION}")
        if not isinstance(account, dict) or not isinstance(account.get("properties"), dict):
            raise RuntimeError(f"Invalid account response: {resource_id}")
        if str(account.get("kind", "")).casefold() not in KINDS:
            raise ValueError(f"Not an AIServices/OpenAI account: {resource_id}")
        return account


def unique(values: Sequence[str]) -> list[str]:
    return list({value.casefold(): value for value in values}.values())


def normalize_ips(values: Sequence[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        network = ipaddress.ip_network(value.strip(), strict=True)
        if network.version != 4:
            raise ValueError(f"Only IPv4 is supported: {value}")
        if not network.is_global or any(
            network.overlaps(reserved) for reserved in NON_PUBLIC_RANGES
        ):
            raise ValueError(f"Only public, non-reserved IPv4 ranges are allowed: {value}")
        if network.prefixlen >= 31:
            result.extend(str(address) for address in network)
        else:
            result.append(str(network))
    return unique(result)


def discover(client: ArmClient, args: argparse.Namespace) -> list[str]:
    if args.resource_id:
        resources = unique([value.rstrip("/") for value in args.resource_id])
        for resource_id in resources:
            if not ACCOUNT_ID.fullmatch(resource_id):
                raise ValueError(f"Expected a CognitiveServices account ID: {resource_id}")
        return resources
    subscriptions = list(args.subscription or [])
    if args.management_group:
        group = quote(args.management_group, safe="")
        descendants = client.list_all(
            f"/providers/Microsoft.Management/managementGroups/{group}/descendants"
            "?api-version=2020-05-01"
        )
        subscriptions = [
            item["name"] for item in descendants
            if str(item.get("type", "")).casefold()
            == "microsoft.management/managementgroups/subscriptions"
        ]
    resources = []
    for subscription in unique(subscriptions):
        print(f"Discovering subscription {subscription}...", flush=True)
        accounts = client.list_all(
            f"/subscriptions/{quote(subscription, safe='')}/providers/"
            f"Microsoft.CognitiveServices/accounts?api-version={API_VERSION}"
        )
        resources.extend(
            account["id"] for account in accounts
            if str(account.get("kind", "")).casefold() in KINDS
        )
    return unique(resources)


def snapshot(account: dict[str, Any]) -> dict[str, Any]:
    properties = account["properties"]
    return copy.deepcopy({
        name: properties.get(name)
        for name in ("networkAcls", "publicNetworkAccess")
    })


def build_body(
    account: dict[str, Any], ips: list[str], replace: bool, enable_public: bool,
    allow_all: bool = False,
) -> dict[str, Any]:
    properties = account["properties"]
    public = properties.get("publicNetworkAccess", "Enabled")
    if allow_all and (ips or replace or enable_public):
        raise ValueError("All-network access cannot be combined with IP allowlist options")
    if public != "Enabled" and not (enable_public or allow_all):
        raise ValueError(
            f"publicNetworkAccess={public}; refusing to open/reconfigure this endpoint. "
            "Use --enable-public-network only if intentionally enabling public IP access."
        )
    acls = properties.get("networkAcls") or {}
    existing = [rule["value"] for rule in acls.get("ipRules") or []]
    desired = [] if allow_all else normalize_ips(ips if replace else existing + ips)
    if not allow_all and (not desired or len(desired) > 100):
        raise ValueError("The resulting IP allowlist must contain 1 to 100 rules")
    network: dict[str, Any] = {
        "defaultAction": "Allow" if allow_all else "Deny",
        "ipRules": [{"value": value} for value in desired],
        "virtualNetworkRules": [
            {name: rule[name] for name in ("id", "ignoreMissingVnetServiceEndpoint") if name in rule}
            for rule in acls.get("virtualNetworkRules") or []
        ],
    }
    if acls.get("bypass") is not None:
        network["bypass"] = acls["bypass"]
    body: dict[str, Any] = {"properties": {"networkAcls": network}}
    if enable_public or allow_all:
        body["properties"]["publicNetworkAccess"] = "Enabled"
    return body


def matches(account: dict[str, Any], body: dict[str, Any], before: dict[str, Any]) -> bool:
    actual = account["properties"]
    desired = body["properties"]
    acls = actual.get("networkAcls") or {}
    expected = desired["networkAcls"]
    actual_ips = normalize_ips([rule["value"] for rule in acls.get("ipRules") or []])
    expected_ips = [rule["value"] for rule in expected["ipRules"]]
    actual_vnets = {
        (rule["id"].casefold(), rule.get("ignoreMissingVnetServiceEndpoint", False))
        for rule in acls.get("virtualNetworkRules") or []
    }
    expected_vnets = {
        (rule["id"].casefold(), rule.get("ignoreMissingVnetServiceEndpoint", False))
        for rule in expected["virtualNetworkRules"]
    }
    return (
        acls.get("defaultAction") == expected["defaultAction"]
        and set(actual_ips) == set(expected_ips)
        and actual_vnets == expected_vnets
        and (acls.get("bypass") or "None") == (expected.get("bypass") or "None")
        and (actual.get("publicNetworkAccess") or "Enabled")
        == (desired.get("publicNetworkAccess") or before.get("publicNetworkAccess") or "Enabled")
    )


def apply_plan(client: ArmClient, plan: dict[str, Any], wait_seconds: int) -> None:
    resource_id = plan["resourceId"]
    current = client.account(resource_id)
    if snapshot(current) != plan["before"] or current.get("etag") != plan["etag"]:
        raise RuntimeError("Account changed since preview; rerun to create a fresh plan")
    if current["properties"].get("provisioningState") != "Succeeded":
        raise RuntimeError("Account is not in Succeeded provisioning state")
    if matches(current, plan["body"], plan["before"]):
        print(f"UNCHANGED {resource_id}", flush=True)
        return
    client.request(
        "patch", f"{resource_id}?api-version={API_VERSION}", plan["body"], current.get("etag")
    )
    deadline = time.monotonic() + wait_seconds
    while True:
        updated = client.account(resource_id)
        state = updated["properties"].get("provisioningState")
        if state in ("Failed", "Canceled", "Deleting"):
            raise RuntimeError(f"Update ended in provisioning state {state}")
        if state == "Succeeded" and matches(updated, plan["body"], plan["before"]):
            print(f"VERIFIED {resource_id}", flush=True)
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("Verification timed out; inspect Azure state before retrying")
        time.sleep(min(5, max(0, deadline - time.monotonic())))


def save_backup(path: Path, plans: list[dict[str, Any]]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({"createdAt": datetime.now(timezone.utc).isoformat(), "plans": plans}, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--management-group", help="Management group ID (not display name); recursive.")
    scope.add_argument("--subscription", action="append", help="Subscription ID; repeatable.")
    scope.add_argument("--resource-id", action="append", help="Exact account resource ID; repeatable.")
    parser.add_argument("--ip", action="append", default=[], help="Public IPv4 or CIDR; repeatable.")
    parser.add_argument("--ip-file", type=Path, help="One IPv4/CIDR per line; # comments allowed.")
    parser.add_argument("--replace", action="store_true", help="Replace IP rules instead of appending.")
    parser.add_argument("--enable-public-network", action="store_true", help="Explicitly enable public access.")
    parser.add_argument(
        "--allow-all-networks", action="store_true",
        help="Enable public access from all networks and clear IP rules; incompatible with IP options.",
    )
    parser.add_argument("--apply", action="store_true", help="Write changes; default is read-only preview.")
    parser.add_argument("--yes", action="store_true", help="Required for management-group-wide writes.")
    parser.add_argument("--backup-file", type=Path, help="New backup file; never overwritten.")
    parser.add_argument("--wait-seconds", type=int, default=300, help="Verification timeout per account.")
    args = parser.parse_args(argv)
    if args.management_group and not re.fullmatch(r"[A-Za-z0-9_().-]{1,90}", args.management_group):
        parser.error("--management-group must be a management group ID, not a resource ID")
    if args.apply and args.management_group and not args.yes:
        parser.error("--management-group --apply also requires --yes")
    if args.wait_seconds <= 0:
        parser.error("--wait-seconds must be positive")
    if args.allow_all_networks and (args.ip or args.ip_file or args.replace or args.enable_public_network):
        parser.error("--allow-all-networks cannot be combined with --ip, --ip-file, --replace, or --enable-public-network")
    values = list(args.ip)
    if args.ip_file:
        values.extend(
            value for line in args.ip_file.read_text(encoding="utf-8-sig").splitlines()
            if (value := line.split("#", 1)[0].strip())
        )
    try:
        args.ips = normalize_ips(values)
        if not args.allow_all_networks and (not args.ips or len(args.ips) > 100):
            parser.error("Provide 1 to 100 public IP rules using --ip and/or --ip-file")
    except ValueError as error:
        parser.error(str(error))
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not shutil.which("az"):
        raise RuntimeError("Azure CLI is required; install it and run az login first")
    if args.allow_all_networks:
        print("WARNING: All-network mode enables public access from any IP; authentication is still required.", file=sys.stderr)
    cloud = run_az(("cloud", "show"))
    client = ArmClient(cloud["endpoints"]["resourceManager"])
    resources = discover(client, args)
    if not resources:
        raise RuntimeError("No Foundry/OpenAI accounts found; no changes made")
    plans = []
    failures = 0
    for resource_id in resources:
        try:
            account = client.account(resource_id)
            body = build_body(
                account, args.ips, args.replace, args.enable_public_network, args.allow_all_networks,
            )
            if account["properties"].get("provisioningState") != "Succeeded":
                raise RuntimeError("Account is not in Succeeded provisioning state")
            plans.append({
                "resourceId": resource_id, "etag": account.get("etag"),
                "before": snapshot(account), "body": body,
            })
            print(json.dumps(plans[-1], indent=2), flush=True)
            if body["properties"]["networkAcls"].get("bypass") == "AzureServices":
                print("WARNING: Existing trusted Azure services bypass is preserved.", file=sys.stderr)
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
            failures += 1
            print(f"FAILED preflight {resource_id}: {error}", file=sys.stderr)
    print(f"Preflight: selected={len(resources)}, ready={len(plans)}, failed={failures}.", flush=True)
    if failures or not args.apply:
        print("No changes made.", flush=True)
        return 1 if failures else 0
    backup = args.backup_file or Path(
        f"foundry-network-backup-{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}.json"
    )
    save_backup(backup, plans)
    print(f"Backup saved: {backup.resolve()}", flush=True)
    for plan in plans:
        try:
            apply_plan(client, plan, args.wait_seconds)
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
            failures += 1
            print(f"FAILED {plan['resourceId']}: {error}", file=sys.stderr)
    print(f"Summary: processed={len(plans)}, failed={failures}.", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1) from None