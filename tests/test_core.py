#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""核心逻辑单元测试（零依赖，python -m unittest tests.test_core）。

覆盖六类关键契约：
  1. Trae 退出码契约（summarize_results）：软限流不算失败，鉴权失败/未开放必须非 0
  2. pick_batch 轮签（TRAE_BATCH 数字解析；历史缺陷：size 未定义导致 NameError）
  3. run_all 失败分类（classify_outcome）与连续失败计数（update_health）
  4. 手写 AES（CBC-128 / GCM-256）NIST 已知向量防回归
  5. GBK 管道 UTF-8 防护（D1：计划任务 pythonw 下 emoji 输出崩溃）
  6. 部署体检（check_workbuddy 凭据结构）与 ps1 BOM（D2/D3/D4）
"""

import datetime as _dt
import io
import json
import os
import shutil
import subprocess
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
import check          # noqa: E402


def _mk_result(status, name="t", detail=""):
    return {"name": name, "uid": "1", "icon": "?", "status": status,
            "credits": "-", "detail": detail}


# ── Trae：退出码契约 ──────────────────────────────────────────
# 0=成功/已签/软限流；非0=硬失败/需人工处理（鉴权失败）/未开放（可重试）
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

    def test_not_open_exits_nonzero(self):
        # enable=false 是服务端临时状态：不记 done、退出非 0，run_all 判 RETRY，
        # 下轮计划任务在开放后继续签（历史缺陷：enable=false 被 mark_done 记成
        # "当天已完成"封死全天重试，且 exit 0 造成假绿）。
        st = trae_checkin.summarize_results([_mk_result("未开放")])
        self.assertEqual(st["exit"], 1)

    def test_source_never_marks_done_on_not_open(self):
        # 回归守卫：enable=false 分支绝不能 mark_done(未开放)，否则封死全天重试。
        src = os.path.join(HERE, "trae", "trae_checkin.py")
        with open(src, encoding="utf-8") as fh:
            text = fh.read()
        seg = text.split("if enable is False", 1)[1].split("result['_claimed']", 1)[0]
        self.assertNotIn("mark_done", seg)

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

    def test_qoder_no_campaign_retry(self):
        # campaigns 里暂时没有每日 100 活动：多为未到 10:00 窗口/传播延迟，
        # 归 RETRY 让后续 12:37/19:07/22:37 档兜底；连续多次仍无由 health 计数暴露。
        self.assertEqual(run_all.classify_outcome(
            "qoder", 4, '{"result": "NO_CAMPAIGN", "error": "未找到目标活动"}'),
            run_all.OUTCOME_RETRY)

    def test_qoder_schema_fail_needs_human(self):
        # 响应结构异常/未知 claimStatus = 疑似 API 改版，重试无意义，立即暴露排查。
        self.assertEqual(run_all.classify_outcome(
            "qoder", 4, '{"result": "SCHEMA_FAIL", "error": "claimStatus=WEIRD"}'),
            run_all.OUTCOME_HUMAN)

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
        # Z 后缀是 UTC，必须按 UTC 解析（历史 bug：曾当本地时间，差一个时区偏移）
        expected = int(_dt.datetime(2026, 9, 20, 0, 0, 0,
                                    tzinfo=_dt.timezone.utc).timestamp())
        self.assertEqual(qoder_checkin._parse_expires("2026-09-20T00:00:00Z"), expected)

    def test_rfc3339_millis(self):
        v = qoder_checkin._parse_expires("2026-09-20T12:34:56.789Z")
        base = int(_dt.datetime(2026, 9, 20, 12, 34, 56,
                                tzinfo=_dt.timezone.utc).timestamp())
        self.assertTrue(base <= v < base + 1)

    def test_rfc3339_no_offset_treated_as_local(self):
        # 无 Z/偏移的裸时间保持本地语义（与桌面端一致）
        expected = int(_dt.datetime(2026, 9, 20, 0, 0, 0).timestamp())
        self.assertEqual(qoder_checkin._parse_expires("2026-09-20T00:00:00"), expected)

    def test_invalid_returns_zero(self):
        self.assertEqual(qoder_checkin._parse_expires("not-a-date"), 0)

    def test_empty_returns_zero(self):
        self.assertEqual(qoder_checkin._parse_expires(""), 0)
        self.assertEqual(qoder_checkin._parse_expires(None), 0)


# ── Qoder：campaigns 协议（daily-check-in 已退役） ──────────────
# 真实抓取（2026-09-21，只读 GET /sash/api/v1/me/campaigns）确认：
#   - 旧 daily-check-in 端点已退役，服务端只回 legacy DISABLED；
#   - 必须带 Cosy-ClientType:10 头，否则 campaigns 返回空数组；
#   - 同账号同时存在多个 CLAIM_BENEFIT 活动（每日 100 + 一次性致歉 500），
#     必须按 amount==100 严格过滤，否则会领错。
DAILY_100 = {
    "campaignId": "01a0bb11-5645-728e-9a10-cc86e7678e1a",
    "campaignKey": "act-20260920-044", "actionType": "CLAIM_BENEFIT",
    "startAt": 1789869600, "endAt": 1789955940, "claimStatus": "CLAIMED",
    "benefit": {"kind": "CREDITS", "amount": 100,
                "modelScope": {"modelSeries": {"key": "ALL_MODELS"}},
                "validity": {"mode": "RELATIVE_DAYS", "days": 30}},
}
APOLOGY_500 = {
    "campaignId": "01a05bee-5bf0-7906-b53a-f50fec136fc8",
    "campaignKey": "act-20260901-900", "actionType": "CLAIM_BENEFIT",
    "startAt": 1788192000, "endAt": 1790783940, "claimStatus": "CLAIMED",
    "benefit": {"kind": "CREDITS", "amount": 500,
                "modelScope": {"modelSeries": {"key": "ALL_MODELS"}},
                "validity": {"mode": "FIXED_END", "fixedEnd": "2026-09-30T15:59:00Z"}},
}
VIEW_ONLY = {
    "campaignId": "01a05bbf-5668-7031-83d6-91545f97ec05",
    "campaignKey": "act-20260901-922", "actionType": "VIEW_DETAILS",
    "startAt": 1788243600, "endAt": 1790783940, "claimStatus": "CLAIMED",
}


def _camp(claim_status, amount=100, action_type="CLAIM_BENEFIT",
          kind="CREDITS", series="ALL_MODELS", cid="cid-daily",
          key="act-daily", start=1789869600):
    c = {"campaignId": cid, "campaignKey": key, "actionType": action_type,
         "claimStatus": claim_status, "startAt": start}
    if kind is not None:
        c["benefit"] = {"kind": kind, "amount": amount,
                        "modelScope": {"modelSeries": {"key": series}}}
    return c


class TestFindTargetCampaign(unittest.TestCase):
    """严格过滤：只认 CLAIM_BENEFIT + CREDITS + amount==100 + ALL_MODELS。"""

    def test_selects_daily_100_from_real_payload(self):
        target = qoder_checkin.find_target_campaign(
            [VIEW_ONLY, APOLOGY_500, DAILY_100])
        self.assertIsNotNone(target)
        self.assertEqual(target["campaignId"], DAILY_100["campaignId"])

    def test_ignores_500_apology_and_view_only(self):
        # 只有致歉 500 包与 VIEW_DETAILS：没有每日 100 目标
        self.assertIsNone(
            qoder_checkin.find_target_campaign([VIEW_ONLY, APOLOGY_500]))

    def test_empty_list_returns_none(self):
        self.assertIsNone(qoder_checkin.find_target_campaign([]))

    def test_prefers_claimable_over_claimed(self):
        claimed = _camp("CLAIMED", cid="c-claimed", start=100)
        claimable = _camp("CLAIMABLE", cid="c-claimable", start=200)
        target = qoder_checkin.find_target_campaign([claimed, claimable])
        self.assertEqual(target["campaignId"], "c-claimable")

    def test_prefers_newest_window_over_older_claimable(self):
        # 最新窗口优先：昨天残留的 CLAIMABLE 不应盖过今天（最新 startAt）的活动，
        # 否则会去 POST 一个已过期窗口。claimable 仅作同窗口内的次级排序键。
        older_claimable = _camp("CLAIMABLE", cid="c-old", start=100)
        newer = _camp("CLAIMED", cid="c-new", start=200)
        target = qoder_checkin.find_target_campaign([older_claimable, newer])
        self.assertEqual(target["campaignId"], "c-new")

    def test_amount_100_required(self):
        self.assertIsNone(qoder_checkin.find_target_campaign(
            [_camp("CLAIMABLE", amount=200)]))

    def test_non_credit_kind_rejected(self):
        self.assertIsNone(qoder_checkin.find_target_campaign(
            [_camp("CLAIMABLE", kind="GIFT_CARD")]))

    def test_view_details_action_rejected(self):
        self.assertIsNone(qoder_checkin.find_target_campaign(
            [_camp("CLAIMABLE", action_type="VIEW_DETAILS", kind=None)]))


class TestCampaignHeaders(unittest.TestCase):
    """发现的关键 gate：缺 Cosy-ClientType 时服务端返回空 campaigns。"""

    def test_headers_include_cosy_clienttype(self):
        h = qoder_checkin._headers("dt-token", "uid1")
        self.assertEqual(h.get("Cosy-ClientType"), "10")
        self.assertEqual(h["Authorization"], "Bearer dt-token")

    def test_headers_include_cosy_version_and_ua(self):
        h = qoder_checkin._headers("dt-token", "uid1")
        self.assertTrue(h.get("Cosy-Version"))
        self.assertEqual(h.get("User-Agent"), "Qoder")


class TestRetiredEndpointGuard(unittest.TestCase):
    """回归守卫（对齐 caigee/cli2api 的断言）：源码绝不退回 daily-check-in。"""

    def test_source_has_no_daily_check_in(self):
        src = os.path.join(HERE, "qoder", "qoder_checkin.py")
        with open(src, encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("daily-check-in", text)

    def test_campaigns_path_constant(self):
        self.assertEqual(qoder_checkin.PATH_CAMPAIGNS,
                         "/sash/api/v1/me/campaigns")

    def test_claim_path_builder(self):
        self.assertEqual(qoder_checkin.claim_path("abc-123"),
                         "/sash/api/v1/me/campaigns/abc-123/claim")

    def test_claim_path_escapes_id(self):
        # campaignId 来自服务端（信任边界），含路径分隔符/空格也必须转义，
        # 否则会拼出畸形或越界的 claim URL。
        self.assertEqual(qoder_checkin.claim_path("a/b c"),
                         "/sash/api/v1/me/campaigns/a%2Fb%20c/claim")


class TestApiNoCrossHostFallback(unittest.TestCase):
    """P0：campaigns 的 GET/POST 只走 OPENAPI_BASE，绝不跨 host fallback。
    有副作用的 claim POST 若在网络模糊失败后自动改打第二个 host，会绕过
    do_checkin 的复查恢复——第一枪可能已领取成功，却被第二次的 4xx 覆盖成 CLAIM_FAIL。"""

    def _raiser(self, exc):
        seen = []

        def fake_urlopen(req, timeout=None):
            seen.append(req.full_url)
            raise exc
        return seen, fake_urlopen

    def test_post_failure_does_not_retry_second_host(self):
        seen, fake = self._raiser(RuntimeError("connection reset"))
        with mock.patch.object(qoder_checkin.urllib.request, "urlopen", fake):
            with self.assertRaises(RuntimeError):
                qoder_checkin._api(qoder_checkin.claim_path("cid-1"), "POST",
                                   "dt-x", "uid1", body=b"{}")
        self.assertEqual(len(seen), 1, "claim POST 失败后不得改打第二个 host")
        self.assertTrue(seen[0].startswith(qoder_checkin.OPENAPI_BASE))
        self.assertNotIn("gateway.qoder.com.cn", seen[0])

    def test_get_campaigns_uses_single_openapi_host(self):
        seen, fake = self._raiser(RuntimeError("timed out"))
        with mock.patch.object(qoder_checkin.urllib.request, "urlopen", fake):
            with self.assertRaises(RuntimeError):
                qoder_checkin._api(qoder_checkin.PATH_CAMPAIGNS, "GET",
                                   "dt-x", "uid1")
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0].startswith(qoder_checkin.OPENAPI_BASE))


class TestClaimSucceededStrict(unittest.TestCase):
    """P1：只认真正的状态证据。金额/积分字段不算成功——否则
    {"status":"FAILED","benefit":{"amount":100}} 会被误判为已领取，违背 fail-close。"""

    def test_success_true(self):
        self.assertTrue(qoder_checkin._claim_succeeded({"success": True}))

    def test_claimed_status(self):
        self.assertTrue(qoder_checkin._claim_succeeded({"status": "CLAIMED"}))
        self.assertTrue(qoder_checkin._claim_succeeded({"claimStatus": "CLAIMED_TODAY"}))

    def test_replayed_true(self):
        self.assertTrue(qoder_checkin._claim_succeeded({"replayed": True}))

    def test_failed_with_amount_is_not_success(self):
        self.assertFalse(qoder_checkin._claim_succeeded(
            {"status": "FAILED", "benefit": {"amount": 100}}))

    def test_amount_only_is_not_success(self):
        self.assertFalse(qoder_checkin._claim_succeeded({"benefit": {"amount": 100}}))

    def test_reward_credits_only_is_not_success(self):
        self.assertFalse(qoder_checkin._claim_succeeded({"rewardCredits": 100}))

    def test_empty_dict_not_success(self):
        self.assertFalse(qoder_checkin._claim_succeeded({}))



class TestFetchCampaigns(unittest.TestCase):
    """fetch_campaigns -> (state, payload)；state ∈ OK/AUTH/HTTP/SCHEMA。"""

    def _fetch(self, api_ret):
        with mock.patch.object(qoder_checkin, "_api", lambda *a, **k: api_ret):
            return qoder_checkin.fetch_campaigns("dt-x", "uid1")

    def test_top_level_campaigns(self):
        state, payload = self._fetch(
            (200, {"showCampaign": True, "claimable": False,
                   "campaignUrl": "u", "campaigns": [DAILY_100]}))
        self.assertEqual(state, "OK")
        self.assertEqual(len(payload["campaigns"]), 1)

    def test_unwraps_data_envelope(self):
        state, payload = self._fetch(
            (200, {"data": {"campaigns": [DAILY_100]}}))
        self.assertEqual(state, "OK")
        self.assertEqual(payload["campaigns"][0]["campaignId"],
                         DAILY_100["campaignId"])

    def test_401_is_auth_state(self):
        state, _ = self._fetch((401, {"error": "unauthorized"}))
        self.assertEqual(state, "AUTH")

    def test_500_is_http_state(self):
        state, _ = self._fetch((503, "boom"))
        self.assertEqual(state, "HTTP")

    def test_missing_campaigns_field_is_schema(self):
        state, _ = self._fetch((200, {"showCampaign": True}))
        self.assertEqual(state, "SCHEMA")

    def test_non_dict_is_schema(self):
        state, _ = self._fetch((200, "not-json"))
        self.assertEqual(state, "SCHEMA")


class TestQoderCampaignFlow(unittest.TestCase):
    """do_checkin 状态机（campaigns 驱动，fail-close 不变量保留）。"""

    OK, FAIL, TOKEN = (qoder_checkin.EXIT_OK, qoder_checkin.EXIT_FAIL,
                       qoder_checkin.EXIT_TOKEN)

    def _ok(self, campaigns):
        return ("OK", {"showCampaign": True, "claimable": True,
                       "campaignUrl": "u", "campaigns": campaigns})

    def _run(self, fetch_seq, claim_resp):
        calls = {"fetch": 0, "claim": 0}

        def fake_fetch(token, uid):
            i = min(calls["fetch"], len(fetch_seq) - 1)
            calls["fetch"] += 1
            return fetch_seq[i]

        def fake_api(path, method, token, uid, body=None, timeout=20):
            if method == "POST":
                calls["claim"] += 1
                self.assertIn("/claim", path)
                if isinstance(claim_resp, Exception):
                    raise claim_resp
            return claim_resp

        with mock.patch.object(qoder_checkin, "fetch_campaigns", fake_fetch), \
                mock.patch.object(qoder_checkin, "_api", fake_api):
            code, result = qoder_checkin.do_checkin("dt-x", "uid1")
        return code, result, calls

    def test_claimed_returns_already_without_posting(self):
        code, res, calls = self._run(
            [self._ok([_camp("CLAIMED")])], (200, {}))
        self.assertEqual(code, self.OK)
        self.assertEqual(res["result"], "ALREADY")
        self.assertEqual(calls["claim"], 0)

    def test_claimable_explicit_success_no_reverify(self):
        code, res, calls = self._run(
            [self._ok([_camp("CLAIMABLE")])], (200, {"success": True}))
        self.assertEqual(code, self.OK)
        self.assertEqual(res["result"], "OK")
        self.assertFalse(res.get("verified"))
        self.assertEqual(calls["fetch"], 1)

    def test_claimable_ambiguous_reverify_confirms(self):
        code, res, calls = self._run(
            [self._ok([_camp("CLAIMABLE")]), self._ok([_camp("CLAIMED")])],
            (200, {}))
        self.assertEqual(code, self.OK)
        self.assertEqual(res["result"], "OK")
        self.assertTrue(res.get("verified"))
        self.assertEqual(calls["fetch"], 2)

    def test_claimable_ambiguous_reverify_still_claimable_fails(self):
        code, res, calls = self._run(
            [self._ok([_camp("CLAIMABLE")]), self._ok([_camp("CLAIMABLE")])],
            (200, {}))
        self.assertEqual(code, self.FAIL)
        self.assertEqual(res["result"], "CLAIM_FAIL")
        self.assertEqual(calls["fetch"], 2)

    def test_picks_daily_100_not_apology_500(self):
        # 同时有可领的 500 致歉包和 100 每日：必须 POST 100 的 campaignId
        daily = _camp("CLAIMABLE", amount=100, cid="cid-daily")
        apology = _camp("CLAIMABLE", amount=500, cid="cid-apology")
        code, res, _ = self._run(
            [self._ok([apology, daily])], (200, {"success": True}))
        self.assertEqual(code, self.OK)
        self.assertEqual(res["campaign_id"], "cid-daily")

    def test_no_target_campaign_is_retryable_fail(self):
        code, res, calls = self._run([self._ok([])], (200, {}))
        self.assertEqual(code, self.FAIL)
        self.assertEqual(res["result"], "NO_CAMPAIGN")
        self.assertEqual(calls["claim"], 0)

    def test_only_apology_500_is_no_campaign(self):
        code, res, _ = self._run([self._ok([APOLOGY_500, VIEW_ONLY])], (200, {}))
        self.assertEqual(code, self.FAIL)
        self.assertEqual(res["result"], "NO_CAMPAIGN")

    def test_unknown_claim_status_fails_close(self):
        code, res, calls = self._run([self._ok([_camp("EXPIRED")])], (200, {}))
        self.assertEqual(code, self.FAIL)
        self.assertEqual(res["result"], "SCHEMA_FAIL")
        self.assertEqual(calls["claim"], 0)

    def test_claim_409_reverify_claimed_is_already(self):
        # 409 不再裸判 ALREADY：复查确认该 campaignId 真变 CLAIMED 才认已领取
        code, res, calls = self._run(
            [self._ok([_camp("CLAIMABLE")]), self._ok([_camp("CLAIMED")])],
            (409, {"error": "ALREADY_CLAIMED"}))
        self.assertEqual(code, self.OK)
        self.assertEqual(res["result"], "ALREADY")
        self.assertEqual(calls["fetch"], 2)

    def test_claim_409_other_conflict_still_claimable_fails(self):
        # 409 只是 Conflict，不等价"已领取"。复查仍 CLAIMABLE -> 必须 FAIL，不得假绿
        code, res, calls = self._run(
            [self._ok([_camp("CLAIMABLE")]), self._ok([_camp("CLAIMABLE")])],
            (409, {"error": "OTHER_CONFLICT"}))
        self.assertEqual(code, self.FAIL)
        self.assertEqual(res["result"], "CLAIM_FAIL")
        self.assertEqual(calls["fetch"], 2)

    def test_empty_campaign_id_is_schema_fail(self):
        # campaignId 缺失/空时不得拼出 /campaigns//claim 去 POST，直接 SCHEMA_FAIL
        code, res, calls = self._run(
            [self._ok([_camp("CLAIMABLE", cid="")])], (200, {"success": True}))
        self.assertEqual(code, self.FAIL)
        self.assertEqual(res["result"], "SCHEMA_FAIL")
        self.assertEqual(calls["claim"], 0)

    def test_claim_response_amount_only_triggers_reverify(self):
        # 2xx 但响应只有金额、无状态证据：不算成功，触发复查；复查未确认 -> FAIL
        code, res, calls = self._run(
            [self._ok([_camp("CLAIMABLE")]), self._ok([_camp("CLAIMABLE")])],
            (200, {"status": "FAILED", "benefit": {"amount": 100}}))
        self.assertEqual(code, self.FAIL)
        self.assertEqual(res["result"], "CLAIM_FAIL")
        self.assertEqual(calls["fetch"], 2)

    def test_claim_http_error_is_retryable_fail(self):
        code, res, _ = self._run(
            [self._ok([_camp("CLAIMABLE")])], (503, "boom"))
        self.assertEqual(code, self.FAIL)
        self.assertEqual(res["result"], "CLAIM_FAIL")

    def test_post_timeout_reverify_recovers(self):
        # POST 超时/连接中断：服务端可能已记账但响应丢失。复查发现已 CLAIMED → OK(recovered)
        code, res, calls = self._run(
            [self._ok([_camp("CLAIMABLE")]), self._ok([_camp("CLAIMED")])],
            RuntimeError("connection reset"))
        self.assertEqual(code, self.OK)
        self.assertEqual(res["result"], "OK")
        self.assertTrue(res.get("verified"))
        self.assertTrue(res.get("recovered"))
        self.assertEqual(calls["fetch"], 2)

    def test_post_timeout_reverify_still_claimable_fails(self):
        code, res, calls = self._run(
            [self._ok([_camp("CLAIMABLE")]), self._ok([_camp("CLAIMABLE")])],
            RuntimeError("timed out"))
        self.assertEqual(code, self.FAIL)
        self.assertEqual(res["result"], "CLAIM_FAIL")
        self.assertEqual(calls["fetch"], 2)

    def test_post_500_reverify_recovers(self):
        # 5xx 同样可能是"已记账但网关报错"，先复查再判失败
        code, res, _ = self._run(
            [self._ok([_camp("CLAIMABLE")]), self._ok([_camp("CLAIMED")])],
            (500, "internal error"))
        self.assertEqual(code, self.OK)
        self.assertEqual(res["result"], "OK")
        self.assertTrue(res.get("recovered"))

    def test_post_400_no_reverify_fails(self):
        # 4xx（非 401/403/409）是明确客户端错误，不必复查，直接可重试失败
        code, res, calls = self._run(
            [self._ok([_camp("CLAIMABLE")])], (400, "bad request"))
        self.assertEqual(code, self.FAIL)
        self.assertEqual(res["result"], "CLAIM_FAIL")
        self.assertEqual(calls["fetch"], 1)

    def test_campaigns_auth_error_maps_to_token_exit(self):
        code, res, _ = self._run([("AUTH", None)], (200, {}))
        self.assertEqual(code, self.TOKEN)
        self.assertEqual(res["result"], "AUTH_FAIL")

    def test_campaigns_http_error_is_fail(self):
        code, res, _ = self._run([("HTTP", "HTTP 503 boom")], (200, {}))
        self.assertEqual(code, self.FAIL)
        self.assertEqual(res["result"], "CAMPAIGNS_HTTP_FAIL")

    def test_campaigns_schema_error_is_fail(self):
        code, res, _ = self._run([("SCHEMA", "campaigns 字段缺失")], (200, {}))
        self.assertEqual(code, self.FAIL)
        self.assertEqual(res["result"], "SCHEMA_FAIL")


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


# ── D1 回归：GBK 管道 UTF-8 防护（计划任务 pythonw 场景） ──────
class TestGbkPipeUtf8Guard(unittest.TestCase):
    """历史缺陷 D1：计划任务以 pythonw + 管道运行时，子进程 stdio 走 locale
    编码（中文 Windows = GBK），脚本大量 emoji 输出直接 UnicodeEncodeError
    崩掉整轮签到；本地直跑因宿主注入 PYTHONUTF8=1 而假绿。
    run_all.py 按 UTF-8 解码子进程输出且把 stderr 合并入 stdout 管道，
    故子进程必须在 main() 入口强制 stdio 走 UTF-8（与 qoder/check.py 同款）。

    复现方式：子进程设 PYTHONIOENCODING=gbk（等价于无控制台管道 + ACP=936）。
    通过当日"已签"状态文件构造零网络路径，无需任何真实凭据。"""

    def _run_under_gbk(self, extra_env=None):
        # 把 home/APPDATA 隔离到空临时目录：否则 find_storage_json() 会探测到
        # 本机真实 Trae 安装并加载真实账号，使"无凭据→exit1"路径不可达，
        # 测试随机器是否装 Trae 而漂移（曾在已装机上假绿/假红）。
        iso = tempfile.mkdtemp(prefix="trae_gbk_iso_")
        try:
            env = {k: v for k, v in os.environ.items()
                   if not (k.startswith("TRAE_")
                           or k in ("PYTHONUTF8", "PYTHONIOENCODING",
                                    "PLUSPLUS_TOKEN"))}
            env["PYTHONIOENCODING"] = "gbk"
            for var in ("HOME", "USERPROFILE", "HOMEPATH", "APPDATA"):
                env[var] = iso
            env["HOMEDRIVE"] = (os.path.splitdrive(iso)[0] or "C:")
            env.update(extra_env or {})
            return subprocess.run(
                [sys.executable, os.path.join(HERE, "trae", "trae_checkin.py")],
                cwd=os.path.join(HERE, "trae"), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        finally:
            shutil.rmtree(iso, ignore_errors=True)

    def test_stdout_emoji_survives_gbk_pipe(self):
        # D1 原始崩溃点：log_title/☑️/✅ 摘要全走 stdout
        key = "gbktest"
        backup = None
        if os.path.isfile(trae_checkin.STATE_FILE):
            with open(trae_checkin.STATE_FILE, encoding="utf-8") as fh:
                backup = fh.read()
        try:
            with open(trae_checkin.STATE_FILE, "w", encoding="utf-8") as fh:
                json.dump({"date": trae_checkin.today_str(),
                           "done": {key: {"status": "已签到", "credits": "-",
                                          "at": "test"}},
                           "cooldown": {}}, fh)
            proc = self._run_under_gbk({
                "TRAE_UID": key, "TRAE_ACCESS_TOKEN": "dummy",
                "TRAE_JITTER": "0"})
        finally:
            if backup is None:
                if os.path.isfile(trae_checkin.STATE_FILE):
                    os.remove(trae_checkin.STATE_FILE)
            else:
                with open(trae_checkin.STATE_FILE, "w", encoding="utf-8") as fh:
                    fh.write(backup)
        out = proc.stdout.decode("utf-8", "replace")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("账号数量", out)          # log_title 正常渲染（非乱码/崩溃）
        self.assertNotIn("UnicodeEncodeError", out)

    def test_stderr_emoji_survives_gbk_pipe(self):
        # 无凭据终态：❌ 提示走 stderr（run_all 将其合并入同一管道）
        proc = self._run_under_gbk()
        out = proc.stdout.decode("utf-8", "replace")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("未找到账号配置", out)
        self.assertNotIn("UnicodeEncodeError", out)


# ── D3 回归：check_workbuddy 嵌套凭据结构误报 ──────────────────
class TestCheckWorkbuddyAuth(unittest.TestCase):
    """历史缺陷 D3：真实凭据文件把令牌嵌在 auth.accessToken（顶层无
    token 键），check_workbuddy() 只查顶层导致稳定输出误导性的
    "结构与预期不同"。"""

    def _with_auth_file(self, payload):
        fd, path = tempfile.mkstemp(suffix=".info")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        saved = os.environ.get("WORKBUDDY_AUTH_FILE")
        os.environ["WORKBUDDY_AUTH_FILE"] = path
        try:
            buf = io.StringIO()
            with mock.patch("sys.stdout", new=buf):
                check.check_workbuddy()
            return buf.getvalue()
        finally:
            if saved is None:
                os.environ.pop("WORKBUDDY_AUTH_FILE", None)
            else:
                os.environ["WORKBUDDY_AUTH_FILE"] = saved
            os.remove(path)

    def test_nested_auth_access_token_recognized(self):
        out = self._with_auth_file({
            "account": {"nick": "n"},
            "auth": {"accessToken": "t", "refreshToken": "r", "expiresAt": 1},
            "accounts": [],
        })
        self.assertIn("凭据文件可读", out)
        self.assertNotIn("结构与预期不同", out)

    def test_top_level_still_recognized(self):
        out = self._with_auth_file({"accessToken": "t"})
        self.assertIn("凭据文件可读", out)


# ── D4 回归：成功后 health.json 残留 last_error ───────────────
class TestHealthLastErrorCleanup(unittest.TestCase):
    """历史缺陷 D4：update_health() 成功分支只清零计数不清 last_error，
    恢复后 health.json 仍残留历史错误文本。"""

    def test_success_clears_last_error(self):
        state = {"x": {"outcome": run_all.OUTCOME_RETRY,
                       "consecutive_failures": 2,
                       "last_failure": "2026-09-20 22:00:00",
                       "last_error": "UnicodeEncodeError: 'gbk' codec"}}
        run_all.update_health(state, "x", run_all.OUTCOME_OK)
        rec = state["x"]
        self.assertEqual(rec["consecutive_failures"], 0)
        self.assertNotIn("last_error", rec)

    def test_failure_keeps_last_error(self):
        state = {}
        run_all.update_health(state, "x", run_all.OUTCOME_RETRY,
                               error="boom")
        self.assertEqual(state["x"]["last_error"], "boom")


# ── D2 回归：安装脚本必须是 UTF-8 with BOM ────────────────────
class TestPowerShellScriptBom(unittest.TestCase):
    """历史缺陷 D2：ps1 为 UTF-8 无 BOM 时，Windows PowerShell 5.1 按 ANSI
    （中文系统 = GBK）解析中文注释，解析器直接崩坏（报错行与实际问题无关），
    安装/卸载双路径全坏。BOM 是唯一跨 PS5.1/pwsh7 的可靠标记。"""

    def _read_bom(self, name):
        path = os.path.join(HERE, name)
        with open(path, "rb") as fh:
            head = fh.read(3)
        self.assertEqual(head, b"\xef\xbb\xbf",
                         "%s 缺少 UTF-8 BOM（PS5.1 会按 ANSI 误解析）" % name)
        with open(path, encoding="utf-8-sig") as fh:
            return fh.read()

    def test_install_ps1_has_bom(self):
        self.assertIn("AutoCheckinDaily", self._read_bom("install.ps1"))

    def test_uninstall_ps1_has_bom(self):
        self.assertIn("AutoCheckin", self._read_bom("uninstall.ps1"))


# ── 调度漂移防护：业务时间固定为北京时间，计划任务按 offset/UTC 语义校验 ──
class TestDailyTriggerDrift(unittest.TestCase):
    """本机时区可以不是 UTC+8；installer 与 check 必须围绕北京时间这个单一真相。"""

    XML_TOKYO = (
        "<Triggers>"
        "<CalendarTrigger><StartBoundary>2026-09-21T01:23:00+09:00</StartBoundary></CalendarTrigger>"
        "<CalendarTrigger><StartBoundary>2026-09-21T09:07:00+09:00</StartBoundary></CalendarTrigger>"
        "<CalendarTrigger><StartBoundary>2026-09-21T11:07:00+09:00</StartBoundary></CalendarTrigger>"
        "<CalendarTrigger><StartBoundary>2026-09-21T13:37:00+09:00</StartBoundary></CalendarTrigger>"
        "<CalendarTrigger><StartBoundary>2026-09-21T20:07:00+09:00</StartBoundary></CalendarTrigger>"
        "<CalendarTrigger><StartBoundary>2026-09-21T23:37:00+09:00</StartBoundary></CalendarTrigger>"
        "</Triggers>")
    XML_WRONG_TOKYO = (
        "<Triggers>"
        "<CalendarTrigger><StartBoundary>2026-09-21T10:07:00+09:00</StartBoundary></CalendarTrigger>"
        "</Triggers>")

    def test_install_ps1_beijing_triggers_match_expected(self):
        import re
        with open(os.path.join(HERE, "install.ps1"), encoding="utf-8-sig") as fh:
            text = fh.read()
        m = re.search(r"\$BeijingTriggerTimes\s*=\s*@\(([^)]*)\)", text)
        self.assertIsNotNone(m, "install.ps1 未找到 $BeijingTriggerTimes")
        times = set(re.findall(r'"(\d{2}:\d{2})"', m.group(1)))
        self.assertEqual(times, check.EXPECTED_BEIJING_TRIGGERS)
        self.assertIn("China Standard Time", text)
        self.assertIn("Convert-BeijingClockToLocal", text)

    def test_expected_set_includes_qoder_1007(self):
        self.assertIn("10:07", check.EXPECTED_BEIJING_TRIGGERS)
        self.assertIn("02:07", check.EXPECTED_UTC_TRIGGERS)

    def test_tokyo_local_clock_is_displayed_but_utc_matches_beijing(self):
        self.assertEqual(
            check._parse_trigger_times(self.XML_TOKYO),
            {"01:23", "09:07", "11:07", "13:37", "20:07", "23:37"})
        self.assertEqual(
            check._parse_trigger_utc_times(self.XML_TOKYO),
            check.EXPECTED_UTC_TRIGGERS)

    def test_wrong_tokyo_1007_local_is_not_beijing_1007(self):
        registered = check._parse_trigger_utc_times(self.XML_WRONG_TOKYO)
        self.assertEqual(registered, {"01:07"})
        self.assertNotIn("02:07", registered)

    def test_expected_utc_set_is_fixed(self):
        self.assertEqual(check.EXPECTED_UTC_TRIGGERS,
                         {"16:23", "00:07", "02:07", "04:37", "11:07", "14:37"})

    def test_parse_empty_xml(self):
        self.assertEqual(check._parse_trigger_times("<Task></Task>"), set())
        self.assertEqual(check._parse_trigger_utc_times("<Task></Task>"), set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
