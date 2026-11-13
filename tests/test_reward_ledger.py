import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import execution_ledger
import reward_rules


class RewardRulesTests(unittest.TestCase):
    def test_registry_loads_and_all_rules_have_sources(self):
        data = reward_rules.load_rules()
        self.assertEqual(data["schema_version"], 1)
        ids = [r["rule_id"] for r in data["rules"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("qoder-cn-daily-personal", ids)
        self.assertIn("trae-cn-daily-member", ids)
        self.assertEqual(reward_rules.get_rule("trae-cn-daily-free")["reward"]["amount"], 150)
        self.assertEqual(reward_rules.get_rule("trae-cn-daily-member")["reward"]["amount"], 200)
        wb = reward_rules.get_rule("workbuddy-cn-daily-checkin")
        self.assertEqual(wb["status"], "secondary_verified_needs_official_confirmation")
        self.assertIsNone(wb["reward"]["amount"])

    def test_duplicate_rule_ids_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bad.json"
            base = {
                "schema_version": 1,
                "rules": [
                    {"rule_id":"x","provider_id":"p","status":"official_verified",
                     "reward":{"amount":1},"sources":[{"url":"https://example.com"}]},
                    {"rule_id":"x","provider_id":"p","status":"official_verified",
                     "reward":{"amount":1},"sources":[{"url":"https://example.com"}]}
                ]
            }
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaises(reward_rules.RewardRulesError):
                reward_rules.load_rules(str(path))


class ExecutionLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="autocheckin-ledger-")
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "ledger" / "claims.jsonl")
        self.key_patch = patch.object(execution_ledger, "_identity_key", return_value=bytes(range(32)))
        self.key_patch.start()
        self.addCleanup(self.key_patch.stop)

    def test_append_claim_and_deduplicate(self):
        uid = "synthetic-account-secret-uuid"
        first = execution_ledger.append_claim(
            "qoder-cn", uid, "qoder-cn-daily-personal",
            "campaign-2026-11-11", amount=100,
            evidence="state_reverified", path=self.path)
        second = execution_ledger.append_claim(
            "qoder-cn", uid, "qoder-cn-daily-personal",
            "campaign-2026-11-11", amount=100,
            evidence="state_reverified", path=self.path)
        self.assertTrue(first)
        self.assertFalse(second)
        events = execution_ledger.read_events(self.path)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["amount"], 100)
        self.assertEqual(events[0]["outcome"], "claimed")
        self.assertNotIn(uid, Path(self.path).read_text(encoding="utf-8"))
        self.assertNotIn(uid, str(events[0]))
        legacy_ref = hashlib.sha256(("qoder-cn\0" + uid).encode("utf-8")).hexdigest()
        self.assertNotEqual(events[0]["account_ref"], legacy_ref[:16])

    def test_already_outcome_is_not_counted_as_a_new_claim(self):
        execution_ledger.append_claim(
            "workbuddy-cn", "synthetic-user", "workbuddy-cn-daily-checkin", "2026-11-11",
            amount=100, evidence="state_reverified", outcome="already", path=self.path)
        event = execution_ledger.read_events(self.path)[0]
        self.assertEqual(event["outcome"], "already")
        self.assertEqual(event["evidence"], "state_reverified")

    def test_cached_state_evidence_is_limited_to_already(self):
        with self.assertRaises(execution_ledger.LedgerError):
            execution_ledger.append_claim(
                "trae-cn", "synthetic-user", "trae-cn-daily-unknown-tier", "2026-11-11",
                evidence="local_state", outcome="claimed", path=self.path)

    def test_account_and_window_form_distinct_idempotency_keys(self):
        execution_ledger.append_claim(
            "trae-cn", "account-a", "trae-cn-daily-free", "2026-11-11",
            amount=150, path=self.path)
        execution_ledger.append_claim(
            "trae-cn", "account-a", "trae-cn-daily-free", "2026-11-12",
            amount=150, path=self.path)
        execution_ledger.append_claim(
            "trae-cn", "account-b", "trae-cn-daily-free", "2026-11-11",
            amount=150, path=self.path)
        self.assertEqual(len(execution_ledger.read_events(self.path)), 3)

    def test_reject_negative_amount(self):
        with self.assertRaises(execution_ledger.LedgerError):
            execution_ledger.append_claim(
                "qoder-cn", "account", "qoder-cn-daily-personal", "window",
                amount=-1, path=self.path)

    def test_legacy_sha256_event_is_still_deduplicated(self):
        uid = "synthetic-legacy-account"
        legacy_id = execution_ledger._legacy_event_id(
            "qoder-cn", uid, "qoder-cn-daily-personal", "2026-11-11")
        Path(self.path).parent.mkdir(parents=True)
        Path(self.path).write_text(json.dumps({"event_id": legacy_id}) + "\n", encoding="utf-8")
        created = execution_ledger.append_claim(
            "qoder-cn", uid, "qoder-cn-daily-personal", "2026-11-11",
            amount=100, path=self.path)
        self.assertFalse(created)
        self.assertEqual(len(execution_ledger.read_events(self.path)), 1)

    def test_reject_nonfinite_amount(self):
        for amount in (float("nan"), float("inf")):
            with self.subTest(amount=amount), self.assertRaises(execution_ledger.LedgerError):
                execution_ledger.append_claim(
                    "qoder-cn", "account", "qoder-cn-daily-personal", "window",
                    amount=amount, path=self.path)

    def test_provider_rule_mismatch_rejected(self):
        with self.assertRaises(execution_ledger.LedgerError):
            execution_ledger.append_claim(
                "trae-cn", "account", "qoder-cn-daily-personal", "window",
                amount=100, path=self.path)

    def test_corrupt_ledger_fails_closed(self):
        Path(self.path).parent.mkdir(parents=True)
        Path(self.path).write_text('{"no_event_id":true}\n', encoding="utf-8")
        with self.assertRaises(execution_ledger.LedgerError):
            execution_ledger.append_claim(
                "qoder-cn", "account", "qoder-cn-daily-personal", "window",
                amount=100, path=self.path)


if __name__ == "__main__":
    unittest.main()
