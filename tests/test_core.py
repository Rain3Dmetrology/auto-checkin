#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""核心逻辑单元测试（零依赖，python -m unittest tests.test_core）。

覆盖四类关键契约：
  1. Trae 退出码契约（summarize_results）：软限流不算失败，鉴权失败必须非 0
  2. pick_batch 轮签（TRAE_BATCH 数字解析；历史缺陷：size 未定义导致 NameError）
  3. run_all 失败分类（classify_outcome）与连续失败计数（update_health）
  4. 手写 AES（CBC-128 / GCM-256）NIST 已知向量防回归
"""

import datetime as _dt
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "trae"))
sys.path.insert(0, os.path.join(HERE, "qoder"))

import run_all        # noqa: E402
import trae_checkin   # noqa: E402
import qoder_checkin  # noqa: E402


def _mk_result(status, name="t", detail=""):
    return {"name": name, "uid": "1", "icon": "?", "status": status,
            "credits": "-", "detail": detail}


# ── Trae：退出码契约 ──────────────────────────────────────────
# 0=成功/已签/软限流/未开放；非0=硬失败或需人工处理（鉴权失败）
class TestTraeExitCode(unittest.TestCase):
    def test_all_success_exit_zero(self):
        st = trae_checkin.summarize_results([_mk_result("签到成功")])
        self.assertEqual(st["exit"], 0)

    def test_already_counts_as_ok(self):
        st = trae_checkin.summarize_results([_mk_result("已签到")])
        self.assertEqual(st["exit"], 0)

    def test_soft_rate_limit_not_failure(self):
        # 9074 限流是设计内的瞬时状态：记冷却后由下轮计划任务补签
        st = trae_checkin.summarize_results([_mk_result("待重试")])
        self.assertEqual(st["exit"], 0)

    def test_not_open_not_failure(self):
        # enable=false 是服务端常态，人工无法处理，且当日状态已去重
        st = trae_checkin.summarize_results([_mk_result("未开放")])
        self.assertEqual(st["exit"], 0)

    def test_auth_failure_exits_nonzero(self):
        st = trae_checkin.summarize_results([_mk_result("鉴权失败")])
        self.assertEqual(st["exit"], 1)

    def test_hard_failure_exits_nonzero(self):
        st = trae_checkin.summarize_results([_mk_result("失败")])
        self.assertEqual(st["exit"], 1)

    def test_exception_exits_nonzero(self):
        st = trae_checkin.summarize_results([_mk_result("异常")])
        self.assertEqual(st["exit"], 1)

    def test_mixed_counts(self):
        st = trae_checkin.summarize_results([
            _mk_result("签到成功"), _mk_result("已签到"), _mk_result("待重试"),
            _mk_result("鉴权失败"), _mk_result("失败")])
        self.assertEqual(st["exit"], 1)
        self.assertEqual((st["ok"], st["already"], st["soft"]), (1, 1, 1))


# ── Trae：pick_batch 轮签 ─────────────────────────────────────
class TestPickBatch(unittest.TestCase):
    def setUp(self):
        self.pend = [{"uid": str(i)} for i in range(5)]

    def test_default_all(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TRAE_BATCH", None)
            with mock.patch.object(trae_checkin, "in_peak_hour", return_value=False):
                self.assertEqual(len(trae_checkin.pick_batch(self.pend)), 5)

    def test_numeric_batch(self):
        with mock.patch.dict(os.environ, {"TRAE_BATCH": "2"}):
            with mock.patch.object(trae_checkin, "in_peak_hour", return_value=False):
                self.assertEqual(len(trae_checkin.pick_batch(self.pend)), 2)

    def test_numeric_exceeds_pending(self):
        with mock.patch.dict(os.environ, {"TRAE_BATCH": "10"}):
            with mock.patch.object(trae_checkin, "in_peak_hour", return_value=False):
                self.assertEqual(len(trae_checkin.pick_batch(self.pend[:3])), 3)

    def test_invalid_value_falls_back_to_all(self):
        # 历史缺陷：TRAE_BATCH=abc 时 size 未定义，直接 NameError 崩掉整轮
        with mock.patch.dict(os.environ, {"TRAE_BATCH": "abc"}):
            with mock.patch.object(trae_checkin, "in_peak_hour", return_value=False):
                self.assertEqual(len(trae_checkin.pick_batch(self.pend)), 5)

    def test_peak_hour_signs_all(self):
        with mock.patch.dict(os.environ, {"TRAE_BATCH": "1"}):
            with mock.patch.object(trae_checkin, "in_peak_hour", return_value=True):
                self.assertEqual(len(trae_checkin.pick_batch(self.pend)), 5)

    def test_empty_pending(self):
        with mock.patch.dict(os.environ, {"TRAE_BATCH": "2"}):
            with mock.patch.object(trae_checkin, "in_peak_hour", return_value=False):
                self.assertEqual(trae_checkin.pick_batch([]), [])


# ── run_all：失败三态分类 ─────────────────────────────────────
class TestClassifyOutcome(unittest.TestCase):
    def test_zero_code_is_ok(self):
        for n in ("workbuddy", "trae", "qoder"):
            self.assertEqual(run_all.classify_outcome(n, 0, ""), run_all.OUTCOME_OK)

    # workbuddy
    def test_wb_no_session_human(self):
        self.assertEqual(run_all.classify_outcome(
            "workbuddy", 1, '"result": "NO_SESSION", "report": "登录态已失效"'),
            run_all.OUTCOME_HUMAN)

    def test_wb_network_retry(self):
        self.assertEqual(run_all.classify_outcome(
            "workbuddy", 1, '"result": "NETWORK"'), run_all.OUTCOME_RETRY)

    def test_wb_timeout_retry(self):
        self.assertEqual(run_all.classify_outcome(
            "workbuddy", 1, '"result": "TIMEOUT"'), run_all.OUTCOME_RETRY)

    def test_wb_no_auth_ok(self):
        self.assertEqual(run_all.classify_outcome(
            "workbuddy", 2, '"result": "NO_AUTH", "report": "未找到 WorkBuddy 登录凭据"'),
            run_all.OUTCOME_OK)

    def test_wb_corrupt_credential_human(self):
        self.assertEqual(run_all.classify_outcome(
            "workbuddy", 2, '"result": "ERROR", "report": "登录凭据文件不是合法 JSON"'),
            run_all.OUTCOME_HUMAN)

    # trae
    def test_trae_auth_human(self):
        self.assertEqual(run_all.classify_outcome(
            "trae", 1, "🔑 t(1): 鉴权失败 | token 无效且自动续期失败"),
            run_all.OUTCOME_HUMAN)

    def test_trae_hard_retry(self):
        self.assertEqual(run_all.classify_outcome(
            "trae", 1, "❌ [结果] 签到失败: connect timeout"), run_all.OUTCOME_RETRY)

    # qoder
    def test_qoder_not_installed_ok(self):
        self.assertEqual(run_all.classify_outcome(
            "qoder", 2, '{"result": "AUTH_FAIL", "error": "找不到 Qoder CN 凭据"}'),
            run_all.OUTCOME_OK)

    def test_qoder_decrypt_fail_human(self):
        self.assertEqual(run_all.classify_outcome(
            "qoder", 2, '{"result": "AUTH_FAIL", "error": "解密 auth.v1.dat 失败"}'),
            run_all.OUTCOME_HUMAN)

    def test_qoder_token_dead_human(self):
        self.assertEqual(run_all.classify_outcome(
            "qoder", 3, '{"result": "AUTH_FAIL", "error": "续期失败（refreshToken 也失效）"}'),
            run_all.OUTCOME_HUMAN)

    def test_qoder_claim_fail_retry(self):
        self.assertEqual(run_all.classify_outcome(
            "qoder", 4, '{"result": "CLAIM_FAIL", "error": "HTTP 503"}'),
            run_all.OUTCOME_RETRY)

    def test_unknown_task_retry(self):
        self.assertEqual(run_all.classify_outcome("other", 1, ""),
                         run_all.OUTCOME_RETRY)


# ── run_all：连续失败计数（health） ───────────────────────────
class TestUpdateHealth(unittest.TestCase):
    def test_ok_resets_counter(self):
        s = {"trae": {"outcome": "RETRY", "consecutive_failures": 3,
                      "last_success": "旧", "last_failure": "旧", "last_error": "x"}}
        run_all.update_health(s, "trae", run_all.OUTCOME_OK)
        self.assertEqual(s["trae"]["consecutive_failures"], 0)
        self.assertNotEqual(s["trae"]["last_success"], "旧")

    def test_retry_increments(self):
        s = {}
        run_all.update_health(s, "qoder", run_all.OUTCOME_RETRY, "HTTP 503")
        self.assertEqual(s["qoder"]["consecutive_failures"], 1)
        run_all.update_health(s, "qoder", run_all.OUTCOME_RETRY, "HTTP 503")
        self.assertEqual(s["qoder"]["consecutive_failures"], 2)
        self.assertEqual(s["qoder"]["last_error"], "HTTP 503")

    def test_human_increments(self):
        s = {}
        run_all.update_health(s, "workbuddy", run_all.OUTCOME_HUMAN, "登录态已失效")
        self.assertEqual(s["workbuddy"]["consecutive_failures"], 1)
        self.assertEqual(s["workbuddy"]["outcome"], run_all.OUTCOME_HUMAN)

    def test_success_timestamp_kept_across_failures(self):
        s = {"trae": {"outcome": "RETRY", "consecutive_failures": 1,
                      "last_success": "2026-09-19 00:23:01",
                      "last_failure": "", "last_error": ""}}
        run_all.update_health(s, "trae", run_all.OUTCOME_RETRY)
        self.assertEqual(s["trae"]["last_success"], "2026-09-19 00:23:01")

    def test_health_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            orig = run_all.LOG_DIR, run_all.HEALTH_FILE
            run_all.LOG_DIR = tmp
            run_all.HEALTH_FILE = os.path.join(tmp, "health.json")
            try:
                s = {}
                run_all.update_health(s, "trae", run_all.OUTCOME_OK)
                run_all.save_health(s)
                loaded = run_all.load_health()
                self.assertEqual(loaded["trae"]["consecutive_failures"], 0)
            finally:
                run_all.LOG_DIR, run_all.HEALTH_FILE = orig


# ── run_all：失败完整输出落盘 ─────────────────────────────────
class TestFailureDump(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig = run_all.LOG_DIR
        run_all.LOG_DIR = self.tmp

    def tearDown(self):
        run_all.LOG_DIR = self._orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dump_written_with_full_output(self):
        run_all._write_failure_dump("trae", "line1\nline2\nline3\n",
                                     timestamp="2026-09-20 00:00:00")
        files = os.listdir(self.tmp)
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].startswith("fail_trae_2"))
        with open(os.path.join(self.tmp, files[0]), encoding="utf-8") as fh:
            content = fh.read()
        for ln in ("line1", "line2", "line3", "2026-09-20 00:00:00"):
            self.assertIn(ln, content)


# ── Qoder：_parse_expires 边界 ─────────────────────────────────
class TestParseExpires(unittest.TestCase):
    def test_epoch_millis(self):
        self.assertEqual(qoder_checkin._parse_expires(1758307200000), 1758307200)

    def test_epoch_seconds(self):
        self.assertEqual(qoder_checkin._parse_expires(1758307200), 1758307200)

    def test_numeric_string_millis(self):
        self.assertEqual(qoder_checkin._parse_expires("1758307200000"), 1758307200)

    def test_rfc3339(self):
        expected = int(_dt.datetime(2026, 9, 20, 0, 0, 0).timestamp())
        self.assertEqual(qoder_checkin._parse_expires("2026-09-20T00:00:00Z"), expected)

    def test_rfc3339_millis(self):
        v = qoder_checkin._parse_expires("2026-09-20T12:34:56.789Z")
        base = int(_dt.datetime(2026, 9, 20, 12, 34, 56).timestamp())
        self.assertTrue(base <= v < base + 1)

    def test_invalid_returns_zero(self):
        self.assertEqual(qoder_checkin._parse_expires("not-a-date"), 0)

    def test_empty_returns_zero(self):
        self.assertEqual(qoder_checkin._parse_expires(""), 0)
        self.assertEqual(qoder_checkin._parse_expires(None), 0)


# ── AES 已知向量（防手写密码学回归） ──────────────────────────
class TestAesVectors(unittest.TestCase):
    # NIST SP 800-38A F.2.1 CBC-AES128
    CBC_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    CBC_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    CBC_PT = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                           "ae2d8a571e03ac9c9eb76fac45af8e51")
    CBC_CT = bytes.fromhex("7649abac8119b246cee98e9b12e9197d"
                           "5086cb9b507219ee95db113a917678b2")

    def test_aes128_cbc_decrypt_nist(self):
        self.assertEqual(run_all.aes128_cbc_decrypt(self.CBC_KEY, self.CBC_IV,
                                                    self.CBC_CT), self.CBC_PT)

    # McGrew-Viega GCM 测试用例 16 输入（AES-256、64B 明文、无 AAD）。
    # 历史缺陷：最初误抄了用例 6（AES-128 且带 AAD）的 tag，与 AES-256
    # 无 AAD 场景双重错配，误报 "GCM authentication failed"。
    # CT/TAG 值均经 cryptography 49.0.0（OpenSSL 3.0.2）独立实算仲裁。
    GCM_KEY = bytes.fromhex(
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
    GCM_IV = bytes.fromhex("cafebabefacedbaddecaf888")
    GCM_PT = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
    GCM_CT = bytes.fromhex(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad")
    GCM_TAG = bytes.fromhex("b094dac5d93471bdec1a502270e3cc6c")

    # 60B 非 16 倍数用例：公开向量无此形态（用例 17 带 AAD），值同样经
    # cryptography 交叉验证。覆盖 GHASH 尾块零填充 + CTR 部分块异或路径。
    GCM60_CT = bytes.fromhex(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662")
    GCM60_TAG = bytes.fromhex("eb9f796c8d356fc31a8433884b696f4f")

    def test_gcm_decrypt_known_vector(self):
        self.assertEqual(qoder_checkin.aes_gcm_decrypt(
            self.GCM_KEY, self.GCM_IV, self.GCM_CT + self.GCM_TAG), self.GCM_PT)

    def test_gcm_partial_block(self):
        self.assertEqual(qoder_checkin.aes_gcm_decrypt(
            self.GCM_KEY, self.GCM_IV, self.GCM60_CT + self.GCM60_TAG),
            self.GCM_PT[:60])

    def test_gcm_empty_plaintext(self):
        # McGrew-Viega 测试用例 13（全零 key/iv、空明文）：tag 与公开值及
        # cryptography 实算一致；覆盖 sealed 仅剩 16B tag 的空载荷边界
        out = qoder_checkin.aes_gcm_decrypt(
            b"\x00" * 32, b"\x00" * 12,
            bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b"))
        self.assertEqual(out, b"")

    def test_gcm_bad_tag_raises(self):
        sealed = self.GCM_CT + bytes(b ^ 0x01 for b in self.GCM_TAG)
        with self.assertRaises(ValueError):
            qoder_checkin.aes_gcm_decrypt(self.GCM_KEY, self.GCM_IV, sealed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
