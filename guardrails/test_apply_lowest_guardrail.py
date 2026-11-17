import argparse
import copy
import unittest
from contextlib import ExitStack
from unittest.mock import patch

import apply_lowest_guardrail as guardrail


class DisabledPolicyTests(unittest.TestCase):
    def test_disables_known_and_inherited_filters(self):
        inherited = [
            {"name": "PII", "source": "Completion", "enabled": True, "blocking": True},
            {"name": "Hate", "source": "Prompt", "severityThreshold": "Medium"},
        ]
        original = copy.deepcopy(inherited)
        policy = guardrail.build_policy("Microsoft.DefaultV2", "disabled", inherited)
        filters = policy["properties"]["contentFilters"]
        keys = [(item["name"], item["source"]) for item in filters]
        self.assertIn(("PII", "Completion"), keys)
        self.assertEqual(len(keys), len(set(keys)))
        self.assertTrue(all(item["enabled"] is False for item in filters))
        self.assertTrue(all(item["blocking"] is False for item in filters))
        self.assertEqual(inherited, original)
        guardrail.verify_disabled_policy(policy, filters)

    def test_existing_modes_keep_detection_enabled(self):
        for mode in ("annotate-only", "high-only"):
            with self.subTest(mode=mode):
                filters = guardrail.build_policy("Microsoft.Default", mode)[
                    "properties"
                ]["contentFilters"]
                self.assertTrue(all(item["enabled"] is True for item in filters))
                for item in filters:
                    self.assertEqual(
                        item["blocking"],
                        mode == "high-only" and item["name"] in guardrail.CORE_CATEGORIES,
                    )

    def test_verification_rejects_remaining_or_unverifiable_filters(self):
        expected = guardrail.build_policy("Microsoft.Default", "disabled")[
            "properties"
        ]["contentFilters"]
        for change in (
            "enabled", "blocking", "unknown", "missing", "empty",
            "omitted", "missing-enabled", "blocklist",
        ):
            with self.subTest(change=change):
                policy = {"properties": {"contentFilters": copy.deepcopy(expected)}}
                properties = policy["properties"]
                filters = properties["contentFilters"]
                if change in {"enabled", "blocking"}:
                    filters[0][change] = True
                elif change == "unknown":
                    filters.append(
                        {"name": "DefenderForAI", "source": "Prompt", "enabled": True}
                    )
                elif change == "missing":
                    filters.pop()
                elif change == "empty":
                    filters.clear()
                elif change == "omitted":
                    del properties["contentFilters"]
                elif change == "missing-enabled":
                    del filters[0]["enabled"]
                else:
                    properties["customBlocklists"] = [{"blocklistName": "existing"}]
                with self.assertRaises(RuntimeError):
                    guardrail.verify_disabled_policy(policy, expected)

    def test_disable_all_is_exclusive_with_core_mode(self):
        with patch("sys.argv", ["script", "--resource-id", "id", "--disable-all"]):
            self.assertTrue(guardrail.parse_args().disable_all)
        with (
            patch("sys.argv", [
                "script", "--resource-id", "id", "--disable-all",
                "--core-mode", "high-only",
            ]),
            patch("sys.stderr"),
            self.assertRaises(SystemExit) as error,
        ):
            guardrail.parse_args()
        self.assertEqual(error.exception.code, 2)


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.account = guardrail.Account.from_resource_id(
            "/subscriptions/sub/resourceGroups/rg/"
            "providers/Microsoft.CognitiveServices/accounts/account"
        )
        self.args = argparse.Namespace(
            api_version=guardrail.DEFAULT_API_VERSION,
            base_policy=None,
            policy_name="LowestBlock",
            apply=True,
            disable_all=True,
            core_mode="auto",
        )
        self.base = guardrail.build_policy("Microsoft.Default", "high-only")
        self.base["properties"]["contentFilters"].append(
            {"name": "Profanity", "source": "Prompt", "enabled": True}
        )
        self.existing = guardrail.build_policy("Microsoft.Default", "high-only")
        self.existing["properties"]["contentFilters"].append(
            {"name": "PII", "source": "Completion", "enabled": True}
        )
        self.effective = None
        self.assigned = False
        self.puts = []
        self.retained_filter = False
        self.reject_put = False
        self.drift = False
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(guardrail, "run_az"))
        stack.enter_context(patch.object(guardrail, "log"))
        stack.enter_context(patch.object(guardrail, "warn"))
        stack.enter_context(patch.object(
            guardrail, "get_policies", return_value=[
                {"name": "Microsoft.DefaultV2", **self.base},
                {"name": "LowestBlock", **self.existing},
            ],
        ))
        stack.enter_context(patch.object(
            guardrail, "get_deployments", side_effect=lambda *args: [{
                "name": "model",
                "properties": {
                    "raiPolicyName": "LowestBlock" if self.assigned else "other",
                },
            }],
        ))
        self.assign = stack.enter_context(patch.object(
            guardrail, "assign_policy", side_effect=self.assign_policy,
        ))
        self.arm = stack.enter_context(patch.object(
            guardrail, "arm_request", side_effect=self.arm_request,
        ))

    def assign_policy(self, *args):
        self.assigned = True

    def arm_request(self, method, resource_id, api_version, body=None):
        if resource_id == self.account.resource_id:
            return {"kind": "AIServices"}
        if method == "put":
            self.puts.append(copy.deepcopy(body))
            if self.reject_put:
                raise guardrail.AzureCliError(["az"], 1, "Permission denied")
            self.effective = copy.deepcopy(body)
            return body
        if resource_id.endswith("/Microsoft.DefaultV2"):
            raise guardrail.AzureCliError(["az"], 1, "NotFound: Microsoft.DefaultV2")
        if self.effective is None:
            return self.existing
        response = copy.deepcopy(self.effective)
        if self.retained_filter or (self.drift and self.assigned):
            response["properties"]["contentFilters"].append(
                {"name": "DefenderForAI", "source": "Prompt", "enabled": True}
            )
        return response

    def test_disable_all_assigns_and_verifies_inherited_filters(self):
        self.assertEqual(
            guardrail.process_account(self.account, self.args), (1, 0, "disabled")
        )
        self.assertEqual(len(self.puts), 1)
        filters = self.puts[0]["properties"]["contentFilters"]
        self.assertIn(
            {"name": "PII", "source": "Completion", "enabled": False, "blocking": False},
            filters,
        )
        self.assertIn(
            {"name": "Profanity", "source": "Prompt", "enabled": False, "blocking": False},
            filters,
        )
        self.assign.assert_called_once()

    def test_missing_listed_filter_details_fail_before_write(self):
        del self.base["properties"]["contentFilters"]
        with self.assertRaisesRegex(RuntimeError, "Cannot discover content filters"):
            guardrail.process_account(self.account, self.args)
        self.assertEqual(self.puts, [])
        self.assign.assert_not_called()

    def test_retained_detection_fails_before_assignment(self):
        self.retained_filter = True
        with self.assertRaisesRegex(RuntimeError, "DefenderForAI"):
            guardrail.process_account(self.account, self.args)
        self.assign.assert_not_called()
        self.assertEqual(len(self.puts), 1)

    def test_rejection_does_not_fall_back(self):
        self.reject_put = True
        with self.assertRaises(guardrail.AzureCliError):
            guardrail.process_account(self.account, self.args)
        self.assertEqual(len(self.puts), 1)
        self.assign.assert_not_called()

    def test_final_verification_rejects_reenabled_detection(self):
        self.drift = True
        with self.assertRaisesRegex(RuntimeError, "DefenderForAI"):
            guardrail.process_account(self.account, self.args)
        self.assign.assert_called_once()

    def test_dry_run_does_not_write_or_assign(self):
        self.args.apply = False
        self.assertEqual(
            guardrail.process_account(self.account, self.args), (1, 0, "dry-run")
        )
        self.assertEqual(self.puts, [])
        self.assign.assert_not_called()
        self.assertEqual(self.arm.call_count, 1)

    def test_default_auto_still_falls_back(self):
        self.args.disable_all = False
        with patch.object(guardrail, "put_policy", side_effect=[
            guardrail.AzureCliError(["az"], 1, "Approval required"), self.base,
        ]) as put_policy:
            self.assertEqual(
                guardrail.process_account(self.account, self.args), (1, 0, "high-only")
            )
        self.assertEqual(
            [call.args[3] for call in put_policy.call_args_list],
            ["annotate-only", "high-only"],
        )


if __name__ == "__main__":
    unittest.main()
