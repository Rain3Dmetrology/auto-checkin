import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))
import account_controls


class AccountControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="autocheckin-controls-")
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "controls.dpapi")
        self.patch = patch.object(account_controls, "CONTROL_FILE", self.path)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_freeze_persists_only_hashed_identity(self):
        uid = "synthetic-user-uid"
        key = account_controls.freeze_account("trae", uid, "AUTH_REJECTED")
        self.assertTrue(account_controls.is_frozen("trae", uid))
        raw = Path(self.path).read_bytes()
        self.assertNotIn(uid.encode(), raw)
        self.assertEqual(len(key), 12)

    def test_freeze_is_provider_scoped(self):
        account_controls.freeze_account("trae", "same-id", "AUTH_REJECTED")
        self.assertTrue(account_controls.is_frozen("trae", "same-id"))
        self.assertFalse(account_controls.is_frozen("qoder", "same-id"))

    def test_unfreeze_provider_only(self):
        account_controls.freeze_account("trae", "trae-user", "AUTH_REJECTED")
        account_controls.freeze_account("qoder", "qoder-user", "AUTH_REJECTED")
        removed = account_controls.unfreeze_accounts("trae")
        self.assertEqual(len(removed), 1)
        self.assertFalse(account_controls.is_frozen("trae", "trae-user"))
        self.assertTrue(account_controls.is_frozen("qoder", "qoder-user"))

    def test_unfreeze_one_account(self):
        account_controls.freeze_account("trae", "one", "AUTH_REJECTED")
        account_controls.freeze_account("trae", "two", "AUTH_REJECTED")
        account_controls.unfreeze_accounts("trae", "one")
        self.assertFalse(account_controls.is_frozen("trae", "one"))
        self.assertTrue(account_controls.is_frozen("trae", "two"))

    def test_list_frozen_never_returns_raw_identity(self):
        account_controls.freeze_account("workbuddy", "synthetic-private-id", "AUTH_REJECTED")
        found = account_controls.list_frozen()
        self.assertEqual(found[0]["provider"], "workbuddy")
        self.assertNotIn("synthetic-private-id", str(found))

    def test_corrupt_store_fails_closed(self):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.path).write_bytes(b"AUTOCHECKIN-DPAPI-V1\ncorrupt")
        with self.assertRaises(Exception):
            account_controls.is_frozen("trae", "user")


if __name__ == "__main__":
    unittest.main()
