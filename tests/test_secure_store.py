import json
import os
from pathlib import Path
import sys
import tempfile
import urllib.error
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "qoder"))
sys.path.insert(0, str(ROOT / "trae"))

import secure_store
import execution_ledger
import qoder_checkin
import trae_checkin


class SecureStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="autocheckin-secure-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "secure" / "cache.dpapi"
        self.secret = "SYNTHETIC_ACCESS_TOKEN_7cbe"
        self.value = {
            "accessToken": self.secret,
            "refreshToken": "SYNTHETIC_REFRESH_TOKEN_91ad",
            "expiresAt": 1900000000,
        }

    def test_round_trip_and_no_plaintext_on_windows(self):
        secure_store.write_secure_json(str(self.target), self.value)
        raw = self.target.read_bytes()
        self.assertEqual(secure_store.read_json_with_migration(str(self.target)), self.value)
        if os.name == "nt":
            self.assertTrue(raw.startswith(secure_store.MAGIC_DPAPI))
            self.assertNotIn(self.secret.encode("ascii"), raw)
        else:
            self.assertTrue(raw.startswith(secure_store.MAGIC_LOCAL))
            self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.target.parent.stat().st_mode & 0o777, 0o700)

    def test_ledger_identity_key_is_protected_and_stable(self):
        credential_root = self.root / "appdata" / "AutoCheckin" / "credentials"
        with patch.object(execution_ledger, "credential_dir", return_value=str(credential_root)):
            first = execution_ledger._identity_key()
            second = execution_ledger._identity_key()
        target = credential_root / "ledger-account-hash.dpapi"
        self.assertEqual(first, second)
        self.assertEqual(len(first), 32)
        raw = target.read_bytes()
        if os.name == "nt":
            self.assertTrue(raw.startswith(secure_store.MAGIC_DPAPI))
            self.assertNotIn(first.hex().encode("ascii"), raw)

    def test_legacy_file_migrates_then_deletes_source(self):
        legacy = self.root / "legacy.json"
        legacy.write_text(json.dumps(self.value), encoding="utf-8")
        got = secure_store.read_json_with_migration(
            str(self.target), [str(legacy)]
        )
        self.assertEqual(got, self.value)
        self.assertTrue(self.target.is_file())
        self.assertFalse(legacy.exists())
        raw = self.target.read_bytes()
        if os.name == "nt":
            self.assertTrue(raw.startswith(secure_store.MAGIC_DPAPI))
            self.assertNotIn(self.secret.encode("ascii"), raw)

    def test_migration_failure_preserves_legacy_source(self):
        legacy = self.root / "legacy.json"
        legacy.write_text(json.dumps(self.value), encoding="utf-8")
        with patch.object(
            secure_store, "write_secure_json",
            side_effect=secure_store.CredentialStoreError("synthetic write failure"),
        ):
            with self.assertRaises(secure_store.CredentialStoreError):
                secure_store.read_json_with_migration(
                    str(self.target), [str(legacy)]
                )
        self.assertTrue(legacy.exists())
        self.assertFalse(self.target.exists())

    def test_corrupt_cache_fails_closed(self):
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(secure_store.MAGIC_DPAPI + b"not-valid-ciphertext")
        with self.assertRaises(secure_store.CredentialStoreError):
            secure_store.read_json_with_migration(str(self.target))

    def test_wrong_top_level_type_is_rejected(self):
        path = self.root / "list.json"
        path.write_text("[1,2,3]", encoding="utf-8")
        with self.assertRaises(secure_store.CredentialStoreError):
            secure_store.read_json_with_migration(str(path))

    def test_qoder_legacy_state_migrates_outside_repo(self):
        legacy = self.root / "qoder-state.json"
        target = self.root / "appdata" / "qoder-token-cache.dpapi"
        legacy.write_text(json.dumps(self.value), encoding="utf-8")
        with patch.object(qoder_checkin, "STATE_FILE", str(target)), \
             patch.object(qoder_checkin, "LEGACY_STATE_FILE", str(legacy)):
            got = qoder_checkin.load_state()
        self.assertEqual(got, self.value)
        self.assertFalse(legacy.exists())
        self.assertTrue(target.exists())
        self.assertNotEqual(Path(qoder_checkin.STATE_FILE).resolve().parent, ROOT / "qoder")

    def test_qoder_refresh_http_auth_rejection_is_classified(self):
        error1 = urllib.error.HTTPError("https://openapi.qoder.com.cn", 401, "unauthorized", {}, None)
        error2 = urllib.error.HTTPError("https://gateway.qoder.com.cn", 403, "forbidden", {}, None)
        with patch.object(qoder_checkin.urllib.request, "urlopen", side_effect=[error1, error2]):
            result = qoder_checkin.refresh_token_pair("synthetic-refresh")
        self.assertIsNone(result)
        self.assertTrue(qoder_checkin._REFRESH_AUTH_REJECTED)

    def test_qoder_explicit_refresh_auth_failure_freezes_account(self):
        with patch.object(qoder_checkin, "ensure_token", side_effect=RuntimeError("refresh rejected")), \
             patch.object(qoder_checkin, "_REFRESH_AUTH_REJECTED", True), \
             patch.object(qoder_checkin, "_LAST_REFRESH_UID", "synthetic-qoder-user"), \
             patch.object(qoder_checkin, "freeze_account") as freeze, \
             patch.object(qoder_checkin, "log_line"), \
             patch("sys.argv", ["qoder_checkin.py", "--json"]):
            with self.assertRaises(SystemExit) as exit_info:
                qoder_checkin.main()
        self.assertEqual(exit_info.exception.code, qoder_checkin.EXIT_AUTH)
        freeze.assert_called_once_with("qoder", "synthetic-qoder-user", "AUTH_REJECTED")

    def test_qoder_frozen_account_blocks_refresh_before_network(self):
        with patch.object(qoder_checkin, "pick_credential", return_value=(
                "", "synthetic-refresh", 0, "synthetic-qoder-user", "synthetic", {})), \
             patch.object(qoder_checkin, "is_frozen", return_value=True), \
             patch.object(qoder_checkin, "refresh_token_pair") as refresh, \
             patch.object(qoder_checkin, "_LAST_REFRESH_UID", None):
            with self.assertRaises(qoder_checkin.AccountFrozenError):
                qoder_checkin.ensure_token()
        refresh.assert_not_called()

    def test_qoder_save_state_uses_protected_store(self):
        target = self.root / "qoder" / "qoder-token-cache.dpapi"
        with patch.object(qoder_checkin, "STATE_FILE", str(target)):
            qoder_checkin.save_state(
                self.secret, "SYNTHETIC_REFRESH_TOKEN_91ad", 1900000000
            )
        raw = target.read_bytes()
        self.assertEqual(
            secure_store.read_json_with_migration(str(target))["accessToken"],
            self.secret,
        )
        if os.name == "nt":
            self.assertNotIn(self.secret.encode("ascii"), raw)

    def test_trae_legacy_cache_override_isolates_migration_source(self):
        isolated = str(self.root / "isolated-legacy.json")
        with patch.dict(os.environ, {"TRAE_LEGACY_TOKEN_CACHE": isolated}):
            self.assertEqual(trae_checkin._legacy_cache_paths(), [isolated])

    def test_trae_cache_migrates_and_writes_securely(self):
        legacy = self.root / "trae-old-cache.json"
        target = self.root / "appdata" / "trae-token-cache.dpapi"
        legacy.write_text(json.dumps({"synthetic-user": self.value}), encoding="utf-8")
        with patch.object(trae_checkin, "_cache_path", return_value=str(target)), \
             patch.object(trae_checkin, "_legacy_cache_paths", return_value=[str(legacy)]):
            got = trae_checkin.load_cache()
            self.assertEqual(got["synthetic-user"], self.value)
            self.assertFalse(legacy.exists())
            trae_checkin.save_cache(got)
        raw = target.read_bytes()
        if os.name == "nt":
            self.assertNotIn(self.secret.encode("ascii"), raw)
        self.assertEqual(secure_store.read_json_with_migration(str(target)), got)

    def test_trae_http_401_is_auth_code(self):
        with patch.object(trae_checkin, "_post", return_value=(401, '{"error":"unauthorized"}')):
            result = trae_checkin.status_of("synthetic-token", "1234567890123456")
        self.assertEqual(result[3], 401)

    def test_trae_http_401_non_json_is_auth_code(self):
        with patch.object(trae_checkin, "_post", return_value=(401, "unauthorized")):
            status = trae_checkin.status_of("synthetic-token", "1234567890123456")
        self.assertEqual(status[3], 401)
        with patch.object(trae_checkin, "_post", return_value=(401, "unauthorized")):
            result = trae_checkin.claim("synthetic-token", "1234567890123456")
        self.assertEqual(result[1], 401)

    def test_trae_initial_refresh_rejection_freezes(self):
        account = {
            "uid": "synthetic-trae-user",
            "name": "synthetic",
            "refreshToken": "synthetic-refresh",
        }
        with patch.object(trae_checkin, "ensure_token", return_value=(False, "refresh http=401 unauthorized")), \
             patch.object(trae_checkin, "freeze_account") as freeze, \
             patch("builtins.print"):
            result = trae_checkin.checkin_account(account, {})
        self.assertEqual(result["status"], "鉴权失败")
        freeze.assert_called_once_with("trae", "synthetic-trae-user", "AUTH_REJECTED")

    def test_trae_http_429_is_rate_code(self):
        with patch.object(trae_checkin, "_post", return_value=(429, '{"code":-1}')):
            result = trae_checkin.status_of("synthetic-token", "1234567890123456")
        self.assertEqual(result[3], trae_checkin.RATE_CODE)
        with patch.object(trae_checkin, "_post", return_value=(429, '{"code":-1}')):
            status, code, message, points = trae_checkin.claim("synthetic-token", "1234567890123456")
        self.assertEqual(status, 429)
        self.assertEqual(code, trae_checkin.RATE_CODE)

    def test_trae_claim_rate_limit_is_not_retried(self):
        account = {"accessToken":"synthetic-access", "deviceId":"1234567890123456"}
        with patch.object(trae_checkin, "claim", return_value=(429, trae_checkin.RATE_CODE, "rate limited", None)) as send:
            ok, code, message, points = trae_checkin.claim_with_retry(account, {})
        self.assertFalse(ok)
        self.assertEqual(code, trae_checkin.RATE_CODE)
        send.assert_called_once()

    def test_trae_transient_refresh_failure_does_not_freeze(self):
        account = {
            "uid": "synthetic-trae-user",
            "name": "synthetic",
            "accessToken": "synthetic-access",
            "refreshToken": "synthetic-refresh",
        }
        with patch.object(trae_checkin, "device_id_for", return_value="1234567890123456"), \
             patch.object(trae_checkin, "status_of", return_value=(None, None, None, 401, "unauthorized")), \
             patch.object(trae_checkin, "ensure_token", return_value=(False, "refresh http=-1 no network")), \
             patch.object(trae_checkin, "freeze_account") as freeze, \
             patch.object(trae_checkin, "log_head"), patch("builtins.print"):
            result = trae_checkin.checkin_account(account, {})
        self.assertEqual(result["status"], "待重试")
        freeze.assert_not_called()

    def test_trae_refresh_auth_rejection_freezes(self):
        account = {
            "uid": "synthetic-trae-user",
            "name": "synthetic",
            "accessToken": "synthetic-access",
            "refreshToken": "synthetic-refresh",
        }
        with patch.object(trae_checkin, "device_id_for", return_value="1234567890123456"), \
             patch.object(trae_checkin, "status_of", return_value=(None, None, None, 401, "unauthorized")), \
             patch.object(trae_checkin, "ensure_token", return_value=(False, "refresh http=401 unauthorized")), \
             patch.object(trae_checkin, "freeze_account") as freeze, \
             patch.object(trae_checkin, "log_head"), patch("builtins.print"):
            result = trae_checkin.checkin_account(account, {})
        self.assertEqual(result["status"], "鉴权失败")
        freeze.assert_called_once_with("trae", "synthetic-trae-user", "AUTH_REJECTED")

    def test_trae_9074_does_not_rotate_device_identifier(self):
        account = {
            "uid": "synthetic-trae-user",
            "name": "synthetic",
            "accessToken": "synthetic-access",
            "refreshToken": "synthetic-refresh",
        }
        with patch.dict(os.environ, {"TRAE_ROTATE": "1"}), \
             patch.object(trae_checkin, "device_id_for", return_value="1234567890123456") as did, \
             patch.object(trae_checkin, "status_of", return_value=(False, 0, True, 0, {})), \
             patch.object(trae_checkin, "claim_with_retry", return_value=(False, trae_checkin.RATE_CODE, "limited", None)) as claim, \
             patch.object(trae_checkin, "set_cooldown") as cooldown, \
             patch.object(trae_checkin, "log_head"), \
             patch("builtins.print"):
            result = trae_checkin.checkin_account(account, {})
        self.assertEqual(result["status"], "待重试")
        did.assert_called_once()
        claim.assert_called_once()
        cooldown.assert_called_once()
        self.assertFalse(hasattr(trae_checkin, "rotate_device_id"))


if __name__ == "__main__":
    unittest.main()
