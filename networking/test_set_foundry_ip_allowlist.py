import argparse
import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import set_foundry_ip_allowlist as firewall


RESOURCE_ID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/foundry"


def account():
    return {
        "id": RESOURCE_ID, "kind": "AIServices", "etag": "version1",
        "properties": {
            "provisioningState": "Succeeded", "publicNetworkAccess": "Enabled",
            "networkAcls": {
                "defaultAction": "Allow", "bypass": "AzureServices",
                "ipRules": [{"value": "8.8.8.8"}],
                "virtualNetworkRules": [{"id": "/subnet", "state": "Succeeded"}],
            },
        },
    }


class FirewallTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(
            firewall.normalize_ips(["8.8.8.8/32", "8.8.8.8", "1.1.1.0/31"]),
            ["8.8.8.8", "1.1.1.0", "1.1.1.1"],
        )

    def test_reject_invalid_ranges(self):
        for value in ("::1", "10.0.0.1", "127.0.0.1", "0.0.0.0/0", "100.64.0.0/10",
                      "224.0.0.1", "8.8.8.1/24", "garbage", "192.168.0.0/16",
                      "8.0.0.0/6", "192.0.0.0/8"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                firewall.normalize_ips([value])

    def test_append_preserves_networks_and_bypass_without_mutating(self):
        source = account()
        original = copy.deepcopy(source)
        body = firewall.build_body(source, ["1.1.1.1"], False, False)
        acls = body["properties"]["networkAcls"]
        self.assertEqual(acls["ipRules"], [{"value": "8.8.8.8"}, {"value": "1.1.1.1"}])
        self.assertEqual(acls["virtualNetworkRules"], [{"id": "/subnet"}])
        self.assertEqual(acls["bypass"], "AzureServices")
        self.assertEqual(acls["defaultAction"], "Deny")
        self.assertEqual(set(body["properties"]), {"networkAcls"})
        self.assertEqual(source, original)

    def test_replace(self):
        body = firewall.build_body(account(), ["1.1.1.1"], True, False)
        self.assertEqual(body["properties"]["networkAcls"]["ipRules"], [{"value": "1.1.1.1"}])

    def test_allow_all_clears_ips_enables_public_and_preserves_other_settings(self):
        source = account()
        source["properties"]["publicNetworkAccess"] = "Disabled"
        original = copy.deepcopy(source)
        body = firewall.build_body(source, [], False, False, allow_all=True)
        self.assertEqual(body["properties"], {
            "publicNetworkAccess": "Enabled",
            "networkAcls": {
                "defaultAction": "Allow", "ipRules": [],
                "virtualNetworkRules": [{"id": "/subnet"}], "bypass": "AzureServices",
            },
        })
        self.assertEqual(source, original)

    def test_allow_all_apply_verifies_and_is_idempotent(self):
        source = account()
        source["properties"]["networkAcls"]["defaultAction"] = "Deny"
        body = firewall.build_body(source, [], False, False, allow_all=True)
        plan = {"resourceId": RESOURCE_ID, "etag": source["etag"],
                "before": firewall.snapshot(source), "body": body}
        updated = copy.deepcopy(source)
        updated["properties"].update(copy.deepcopy(body["properties"]))
        client = Mock()
        client.account.side_effect = [source, updated]
        firewall.apply_plan(client, plan, 1)
        self.assertEqual(client.request.call_args.args[2], body)
        client.reset_mock()
        client.account.side_effect = None
        client.account.return_value = updated
        plan["before"] = firewall.snapshot(updated)
        firewall.apply_plan(client, plan, 1)
        client.request.assert_not_called()
        updated["properties"]["networkAcls"]["defaultAction"] = "Deny"
        self.assertFalse(firewall.matches(updated, body, plan["before"]))
        updated["properties"]["networkAcls"]["defaultAction"] = "Allow"
        updated["properties"]["networkAcls"]["ipRules"] = [{"value": "1.1.1.1"}]
        self.assertFalse(firewall.matches(updated, body, plan["before"]))

    def test_allow_all_cli_rejects_conflicting_options(self):
        args = firewall.parse_args(["--resource-id", RESOURCE_ID, "--allow-all-networks"])
        self.assertEqual(args.ips, [])
        self.assertFalse(args.apply)
        for options in (["--ip", "1.1.1.1"], ["--ip-file", "missing.txt"],
                        ["--replace"], ["--enable-public-network"]):
            with self.subTest(options=options), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                firewall.parse_args(["--resource-id", RESOURCE_ID, "--allow-all-networks", *options])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            firewall.parse_args(["--management-group", "root", "--allow-all-networks", "--apply"])

    def test_allow_all_dry_run_never_writes_or_backs_up(self):
        with patch.object(firewall.shutil, "which", return_value="az"), \
             patch.object(firewall, "run_az", return_value={"endpoints": {"resourceManager": "https://management.azure.com/"}}), \
             patch.object(firewall.ArmClient, "account", return_value=account()), \
             patch.object(firewall.ArmClient, "request") as request, \
             patch.object(firewall, "save_backup") as backup:
            self.assertEqual(firewall.main(["--resource-id", RESOURCE_ID, "--allow-all-networks"]), 0)
            request.assert_not_called()
            backup.assert_not_called()

    def test_disabled_or_secured_endpoint_needs_explicit_opt_in(self):
        for state in ("Disabled", "SecuredByPerimeter"):
            source = account()
            source["properties"]["publicNetworkAccess"] = state
            with self.assertRaises(ValueError):
                firewall.build_body(source, ["1.1.1.1"], False, False)
            body = firewall.build_body(source, ["1.1.1.1"], False, True)
            self.assertEqual(body["properties"]["publicNetworkAccess"], "Enabled")

    def test_rule_limit(self):
        with self.assertRaises(ValueError):
            firewall.build_body(account(), [f"8.8.4.{number}" for number in range(101)], True, False)

    def test_pagination_and_origin_guard(self):
        client = firewall.ArmClient("https://management.azure.com")
        with patch.object(client, "request", side_effect=[
            {"value": [{"id": "first"}], "nextLink": "/page2"},
            {"value": [{"id": "second"}]},
        ]):
            self.assertEqual(client.list_all("/page1"), [{"id": "first"}, {"id": "second"}])
        with self.assertRaises(ValueError):
            client.request("get", "https://untrusted.example/page")

    def test_management_group_descendants(self):
        client = Mock()
        client.list_all.side_effect = [
            [{"name": "nested", "type": "Microsoft.Management/managementGroups"},
             {"name": "sub", "type": "Microsoft.Management/managementGroups/subscriptions"}],
            [{"id": RESOURCE_ID, "kind": "AIServices"},
             {"id": RESOURCE_ID + "other", "kind": "SpeechServices"}],
        ]
        args = argparse.Namespace(resource_id=None, subscription=None, management_group="root")
        self.assertEqual(firewall.discover(client, args), [RESOURCE_ID])
        self.assertIn("/root/descendants?api-version=2020-05-01", client.list_all.call_args_list[0].args[0])

    def test_stale_plan_prevents_write(self):
        original = account()
        plan = self.plan(original)
        client = Mock()
        changed = copy.deepcopy(original)
        changed["etag"] = "version2"
        client.account.return_value = changed
        with self.assertRaisesRegex(RuntimeError, "changed since preview"):
            firewall.apply_plan(client, plan, 1)
        client.request.assert_not_called()

    def plan(self, source):
        return {
            "resourceId": RESOURCE_ID, "etag": source.get("etag"),
            "before": firewall.snapshot(source),
            "body": firewall.build_body(source, ["1.1.1.1"], False, False),
        }

    def test_apply_polls_and_verifies(self):
        source = account()
        plan = self.plan(source)
        pending = copy.deepcopy(source)
        pending["properties"]["provisioningState"] = "Updating"
        updated = copy.deepcopy(source)
        updated["properties"].update(plan["body"]["properties"])
        client = Mock()
        client.account.side_effect = [source, pending, updated]
        with patch.object(firewall.time, "sleep"):
            firewall.apply_plan(client, plan, 10)
        self.assertEqual(client.request.call_args.args[0], "patch")
        self.assertEqual(client.request.call_args.args[3], "version1")

    def test_idempotent(self):
        source = account()
        source["properties"].update(self.plan(source)["body"]["properties"])
        client = Mock()
        client.account.return_value = source
        firewall.apply_plan(client, self.plan(source), 1)
        client.request.assert_not_called()

    def test_verification_detects_lost_vnet_and_public_changes(self):
        source = account()
        plan = self.plan(source)
        updated = copy.deepcopy(source)
        updated["properties"].update(copy.deepcopy(plan["body"]["properties"]))
        self.assertTrue(firewall.matches(updated, plan["body"], plan["before"]))
        updated["properties"]["networkAcls"]["virtualNetworkRules"] = []
        self.assertFalse(firewall.matches(updated, plan["body"], plan["before"]))
        updated["properties"].update(copy.deepcopy(plan["body"]["properties"]))
        updated["properties"]["publicNetworkAccess"] = "Disabled"
        self.assertFalse(firewall.matches(updated, plan["body"], plan["before"]))

    def test_failed_or_unverified_update_is_reported_without_replay(self):
        source = account()
        for state in ("Failed", "Succeeded"):
            updated = copy.deepcopy(source)
            updated["properties"]["provisioningState"] = state
            client = Mock()
            client.account.side_effect = [source, updated]
            with self.subTest(state=state), patch.object(firewall.time, "monotonic", side_effect=[0, 2]), self.assertRaises(RuntimeError):
                firewall.apply_plan(client, self.plan(source), 1)
            self.assertEqual(client.request.call_count, 1)

    def test_explicit_subscription_context_is_passed_without_account_set(self):
        client = firewall.ArmClient("https://management.azure.com")
        with patch.object(firewall, "run_az", return_value={}) as run:
            client.request("patch", RESOURCE_ID + "?api-version=2024-10-01", {"properties": {}})
            arguments = run.call_args.args[0]
            self.assertEqual(arguments[arguments.index("--subscription") + 1], "sub")
            self.assertEqual(arguments[0], "rest")

    def test_backup_is_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / "backup.json"
            firewall.save_backup(backup, [self.plan(account())])
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(backup.read_text())["plans"][0]["resourceId"], RESOURCE_ID)
            with self.assertRaises(FileExistsError):
                firewall.save_backup(backup, [])

    def test_dry_run_never_writes_or_backs_up(self):
        with patch.object(firewall.shutil, "which", return_value="az"), \
             patch.object(firewall, "run_az", return_value={"endpoints": {"resourceManager": "https://management.azure.com/"}}), \
             patch.object(firewall.ArmClient, "account", return_value=account()), \
             patch.object(firewall.ArmClient, "request") as request, \
             patch.object(firewall, "save_backup") as backup:
            self.assertEqual(firewall.main(["--resource-id", RESOURCE_ID, "--ip", "1.1.1.1"]), 0)
            request.assert_not_called()
            backup.assert_not_called()

    def test_preflight_failure_blocks_entire_batch(self):
        with patch.object(firewall.shutil, "which", return_value="az"), \
             patch.object(firewall, "run_az", return_value={"endpoints": {"resourceManager": "https://management.azure.com/"}}), \
             patch.object(firewall, "discover", return_value=[RESOURCE_ID, RESOURCE_ID + "2"]), \
             patch.object(firewall.ArmClient, "account", side_effect=[account(), RuntimeError("denied")]), \
             patch.object(firewall, "apply_plan") as apply, \
             patch.object(firewall, "save_backup") as backup:
            self.assertEqual(firewall.main(["--subscription", "sub", "--ip", "1.1.1.1", "--apply"]), 1)
            apply.assert_not_called()
            backup.assert_not_called()

    def test_cli_guards_and_ip_file(self):
        for arguments in (["--ip", "1.1.1.1"], ["--subscription", "sub"],
                          ["--management-group", "root", "--apply", "--ip", "1.1.1.1"],
                          ["--subscription", "sub", "--resource-id", RESOURCE_ID, "--ip", "1.1.1.1"]):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                firewall.parse_args(arguments)
        with tempfile.TemporaryDirectory() as directory:
            ip_file = Path(directory) / "ips.txt"
            ip_file.write_text("# office\n8.8.8.8 # primary\n\n1.1.1.1\n", encoding="utf-8")
            args = firewall.parse_args(["--subscription", "sub", "--ip-file", str(ip_file)])
            self.assertEqual(args.ips, ["8.8.8.8", "1.1.1.1"])


if __name__ == "__main__":
    unittest.main()