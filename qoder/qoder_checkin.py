#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Qoder CN 每日自动签到（Windows 零依赖版）。

整合自两个开源实现（致谢）：
  - hope0719/qoder-check-in   早期签到流程（sash daily check-in，已退役）
  - luispater/qoder2api-hub   Windows 凭据解密（DPAPI + AES-256-GCM）

工作原理（全程只读官方客户端凭据，不回写、不打印令牌）：
  1. 读 %APPDATA%\\com.qodercn.app.stable\\Local State
     -> os_crypt.encrypted_key -> 剥 "DPAPI" 前缀 -> DPAPI 解出 32 字节 AES key
  2. 读同目录 auth.v1.dat（Electron os_crypt v10 布局）
     -> AES-256-GCM 解出 {token(dt-), refreshToken(drt-), expiresAt, user{...}}
  3. dt- 过期时用 drt- 调 deviceToken/refresh 换新（结果缓存在本目录
     state.json，绝不回写 auth.v1.dat，不影响桌面客户端）
  4. GET  /sash/api/v1/me/campaigns   官方活动领取接口（每日 10:00→次日 10:00 分窗）
     必须带 Cosy-ClientType:10 头，否则服务端返回空 campaigns（实测 2026-09-21）。
     从返回的活动列表里严格筛出"每日 100 Credits"目标活动：
       actionType==CLAIM_BENEFIT && benefit.kind==CREDITS
       && benefit.amount==100 && modelScope.modelSeries.key==ALL_MODELS
     （账号里同时可能存在一次性致歉 500 包等其它 CLAIM_BENEFIT 活动，必须按
       amount==100 过滤，否则会领错；campaignKey 形如 act-YYYYMMDD-NNN 每日变，
       故只能按属性动态匹配，绝不硬编码 campaignId/campaignKey。）
     POST /sash/api/v1/me/campaigns/{campaignId}/claim   仅 claimStatus==CLAIMABLE 时领取
     409 / ALREADY_CLAIMED 归一化为"已领"（幂等，重复运行安全）
     claim 响应缺显式成功证据时，复查 campaigns 确认该 id 变 CLAIMED 才算成功
     未领取（无目标活动/未知状态/请求失败）一律按失败上报，绝不伪装成功。

  注：旧的 sash 每日签到端点（daily check-in 的 status/claim）已退役，服务端只回
      legacy 活动的 DISABLED；当前桌面端 100 Credits 走上面的 campaigns 接口。

用法：
  python qoder_checkin.py            签到（已领自动跳过）
  python qoder_checkin.py status      仅查活动状态（调试）
  python qoder_checkin.py --json      JSON 行输出（供调度器解析）

退出码：0 成功/已领；2 凭据缺失或解密失败；3 token 失效无法续期或活动接口拒绝鉴权；
        4 领取失败、未找到目标活动或响应结构异常（一律 fail-close，
          绝不把"未领取"伪装成成功，疑似 API 改版时让失败暴露）。
"""

import base64
import hmac
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

# ---------------------------------------------------------------------------
# 常量（逆向自 Qoder CN 官方桌面客户端）
# ---------------------------------------------------------------------------
OPENAPI_BASE = os.environ.get("QODER_API_BASE", "https://openapi.qoder.com.cn").rstrip("/")
GATEWAY_BASE = "https://gateway.qoder.com.cn"          # 备用基地址
PATH_CAMPAIGNS = "/sash/api/v1/me/campaigns"
PATH_DEVICE_REFRESH = "/api/v1/deviceToken/refresh"
ORIGIN = "https://qoder.com.cn"
CLIENT_UA = "Go-http-client/2.0"   # deviceToken/refresh 沿用此 UA（已验证可用，勿动鉴权层）
# 活动接口要求桌面端 Cosy 头；缺 Cosy-ClientType 时服务端返回空 campaigns
# （2026-09-21 live 实证：仅本账号验证，非断言服务端永远只校验这一项）。
# Cosy-Version 用本机 live 验证过的值，客户端升级后可经 QODER_COSY_VERSION 覆盖。
COSY_CLIENT_TYPE = "10"
COSY_VERSION = os.environ.get("QODER_COSY_VERSION", "0.3.4")
CAMPAIGN_UA = "Qoder"
CAMPAIGN_REFERER = "https://openapi.qoder.com.cn/growth-page/activity-iframe"
DAILY_BENEFIT_AMOUNT = 100      # 每日活动固定 100 Credits（用于严格区分其它活动）


def claim_path(campaign_id):
    """领取动作端点：POST /sash/api/v1/me/campaigns/{campaignId}/claim。
    campaignId 来自服务端（信任边界），用 quote(safe='') 转义防畸形/越界 URL。"""
    return "/sash/api/v1/me/campaigns/%s/claim" % urllib.parse.quote(
        str(campaign_id), safe="")

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(HERE, "state.json")
LOG_FILE = os.path.join(HERE, "checkin.log")

EXIT_OK, EXIT_AUTH, EXIT_TOKEN, EXIT_FAIL = 0, 2, 3, 4


def app_data_dir():
    """Qoder CN 桌面端 Roaming 数据目录。"""
    override = os.environ.get("QODER_APP_DIR", "").strip()
    if override:
        return override
    base = os.environ.get("APPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Roaming")
    return os.path.join(base, "com.qodercn.app.stable")


# ---------------------------------------------------------------------------
# 纯标准库 AES（S-box 导入期自校验；仅需要 ECB 块加密 + GCM 运算）
# ---------------------------------------------------------------------------
def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _rotl8(x, k):
    return ((x << k) | (x >> (8 - k))) & 0xFF


def _build_sbox():
    sbox = []
    for i in range(256):
        inv = 0
        if i:
            for x in range(1, 256):
                if _gmul(i, x) == 1:
                    inv = x
                    break
        s = inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63
        sbox.append(s)
    return sbox


_SBOX = _build_sbox()
assert _SBOX[0x53] == 0xED and _SBOX[0x00] == 0x63, "AES S-box self-check failed"
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _expand_key(key):
    """AES-256 密钥扩展 -> 15 个 16 字节轮密钥。"""
    assert len(key) == 32
    w = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = t[1:] + t[:1]                      # RotWord
            t = [_SBOX[b] for b in t]              # SubWord
            t[0] ^= _RCON[i // 8 - 1]
        elif i % 8 == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - 8][j] ^ t[j] for j in range(4)])
    rks = []
    for r in range(15):
        rk = []
        for c in range(4):
            rk.extend(w[r * 4 + c])
        rks.append(rk)
    return rks


def _encrypt_block(block, round_keys):
    state = list(block)
    rk0 = round_keys[0]
    state = [state[i] ^ rk0[i] for i in range(16)]

    def sub_shift(s):
        out = [0] * 16
        for c in range(4):
            for r in range(4):
                out[r + 4 * c] = _SBOX[s[r + 4 * ((c + r) % 4)]]
        return out

    def mix_col(s):
        out = [0] * 16
        for c in range(4):
            a = s[4 * c:4 * c + 4]
            out[4 * c + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
            out[4 * c + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
            out[4 * c + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
            out[4 * c + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
        return out

    for rnd in range(1, 14):
        state = sub_shift(state)
        state = mix_col(state)
        rk = round_keys[rnd]
        state = [state[i] ^ rk[i] for i in range(16)]
    state = sub_shift(state)
    rk = round_keys[14]
    state = [state[i] ^ rk[i] for i in range(16)]
    return bytes(state)


def _gf128_mul(x, y):
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ 0xE1000000000000000000000000000000
        else:
            v >>= 1
    return z


def aes_gcm_decrypt(key, nonce, sealed):
    """AES-256-GCM 解密（Chromium os_crypt v10 载荷），tag 严格校验。"""
    if len(nonce) != 12 or len(key) != 32:
        raise ValueError("gcm: key must be 32 bytes and nonce 12 bytes")
    if len(sealed) < 16:
        raise ValueError("gcm payload too short")
    rks = _expand_key(key)
    ct, tag = sealed[:-16], sealed[-16:]
    base = nonce + b"\x00\x00\x00\x01"                # J0 = nonce||1
    high = int.from_bytes(base, "big") & ~0xFFFFFFFF
    low = (int.from_bytes(base[-4:], "big") + 1) & 0xFFFFFFFF
    out = bytearray()
    for off in range(0, len(ct), 16):
        ks = _encrypt_block((high | low).to_bytes(16, "big"), rks)
        chunk = ct[off:off + 16]
        out.extend(a ^ b for a, b in zip(chunk, ks))
        low = (low + 1) & 0xFFFFFFFF
    h = _encrypt_block(b"\x00" * 16, rks)
    y, hh = 0, int.from_bytes(h, "big")
    for off in range(0, len(ct), 16):
        blk = ct[off:off + 16].ljust(16, b"\x00")
        y = _gf128_mul(y ^ int.from_bytes(blk, "big"), hh)
    y = _gf128_mul(y ^ (len(ct) * 8), hh)             # lenA=0
    j0_enc = _encrypt_block(base, rks)
    expect = bytes(a ^ b for a, b in zip(y.to_bytes(16, "big"), j0_enc))
    if not hmac.compare_digest(expect, tag):
        raise ValueError("GCM authentication failed")
    return bytes(out)


def chromium_decrypt_v10(blob, key):
    """Chromium os_crypt v10：v10 + nonce[12] + ciphertext||tag。"""
    if blob[:3] != b"v10":
        raise ValueError("not a v10 payload (got %r)" % blob[:3])
    return aes_gcm_decrypt(key, blob[3:15], blob[15:])


def dpapi_unprotect(data):
    """Windows DPAPI CryptUnprotectData（与当前用户绑定）。"""
    if os.name != "nt":
        raise OSError("DPAPI only available on Windows")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_byte))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    fun = crypt32.CryptUnprotectData
    fun.argtypes = [ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR,
                    ctypes.POINTER(DATA_BLOB), ctypes.c_void_p,
                    wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
    fun.restype = wintypes.BOOL
    in_blob = DATA_BLOB(len(data),
                        (ctypes.c_byte * len(data)).from_buffer_copy(data))
    out_blob = DATA_BLOB()
    if not fun(ctypes.byref(in_blob), None, None, None, None, 0,
               ctypes.byref(out_blob)):
        raise OSError("CryptUnprotectData failed (err=%d)" % ctypes.get_last_error())
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)


# ---------------------------------------------------------------------------
# 凭据加载与续期
# ---------------------------------------------------------------------------
def _parse_expires(value):
    """RFC3339 / epoch -> epoch 秒；解析失败返回 0。"""
    if not value:
        return 0
    if isinstance(value, (int, float)):
        v = float(value)
        return int(v / 1000.0) if v > 1e11 else int(v)
    s = str(value).strip()
    if s.isdigit():
        v = int(s)
        return int(v / 1000.0) if v > 1e11 else v
    import datetime
    # Z 后缀 = UTC，必须按 UTC 解析；裸时间（无偏移）保持本地语义。
    if s.endswith("Z"):
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                dt = datetime.datetime.strptime(
                    s[:26] if "." in s else s[:20], fmt)
                return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp())
            except ValueError:
                continue
        return 0
    try:
        dt = datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
        return int(dt.timestamp())
    except ValueError:
        return 0


def load_app_auth():
    """解出桌面端 auth.v1.dat 明文 dict；失败抛异常。"""
    app_dir = app_data_dir()
    with open(os.path.join(app_dir, "Local State"), encoding="utf-8") as fh:
        state = json.load(fh)
    ek = (state.get("os_crypt") or {}).get("encrypted_key")
    if not ek:
        raise RuntimeError("Local State 缺少 os_crypt.encrypted_key")
    blob = base64.b64decode(ek)
    if blob[:5] != b"DPAPI":
        raise RuntimeError("unexpected encrypted_key header %r" % blob[:5])
    key = dpapi_unprotect(blob[5:])
    with open(os.path.join(app_dir, "auth.v1.dat"), "rb") as fh:
        raw = fh.read()
    data = json.loads(chromium_decrypt_v10(raw, key).decode("utf-8"))
    if not isinstance(data, dict) or not data.get("token"):
        raise RuntimeError("auth.v1.dat 结构异常")
    return data


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_state(token, refresh, expires_at):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"accessToken": token, "refreshToken": refresh,
                   "expiresAt": expires_at, "updatedAt": int(time.time())},
                  fh, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE_FILE)


def pick_credential():
    """选 token：优先 auth.v1.dat（桌面端刷新的最新鲜），过期才回退 state 缓存。"""
    try:
        app = load_app_auth()
    except FileNotFoundError as exc:
        raise RuntimeError("找不到 Qoder CN 凭据（%s）。请先安装并登录 Qoder CN 桌面端。" % exc)
    except Exception as exc:
        raise RuntimeError("解密 auth.v1.dat 失败：%s" % exc)

    app_token = str(app.get("token") or "")
    app_refresh = str(app.get("refreshToken") or "")
    app_exp = _parse_expires(app.get("expiresAt"))
    user = app.get("user") or {}
    uid = str(user.get("id") or "")
    nickname = str(user.get("name") or "")

    state = load_state()
    st_token = str(state.get("accessToken") or "")
    st_refresh = str(state.get("refreshToken") or "")
    st_exp = _parse_expires(state.get("expiresAt"))

    now = time.time()
    if app_token and app_exp > now + 60:
        return app_token, app_refresh or st_refresh, app_exp, uid, nickname, user
    if st_token and st_exp > now + 60:
        # state 是脚本自己续期的 token；refreshToken 优先用 app 的（桌面端可能已轮换）
        return st_token, app_refresh or st_refresh, st_exp, uid, nickname, user
    return app_token, app_refresh or st_refresh, app_exp, uid, nickname, user


def refresh_token_pair(refresh_token):
    """用 drt- 换新 dt-。返回 (token, refresh, expiresAt) 或 None。"""
    if not refresh_token:
        return None
    payload = json.dumps({"refresh_token": refresh_token}).encode("utf-8")
    for base in (OPENAPI_BASE, GATEWAY_BASE):
        req = urllib.request.Request(
            base + PATH_DEVICE_REFRESH, data=payload, method="POST",
            headers={"Content-Type": "application/json",
                     "Accept": "application/json",
                     "User-Agent": CLIENT_UA})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception:
            continue
        token = str(data.get("token") or data.get("device_token") or "")
        refresh = str(data.get("refresh_token") or refresh_token)
        exp = _parse_expires(data.get("expires_at"))
        if not exp and data.get("expires_in"):
            exp = int(time.time() + int(data["expires_in"]) / 1000)
        if not exp:
            exp = int(time.time()) + 30 * 86400
        if token:
            return token, refresh, exp
    return None


def ensure_token():
    """拿到可用 token；必要时自动续期。失败抛异常。"""
    token, refresh, exp, uid, nickname, user = pick_credential()
    if token and exp > time.time() + 60:
        return token, refresh, uid, nickname
    print("[qoder] dt- token 已过期，尝试用 refreshToken 续期 ...")
    got = refresh_token_pair(refresh)
    if not got:
        raise RuntimeError("续期失败（refreshToken 也失效）。请打开一次 Qoder CN 重新登录。")
    token, refresh, exp = got
    save_state(token, refresh, exp)
    print("[qoder] 续期成功，已缓存到 state.json")
    return token, refresh, uid, nickname


# ---------------------------------------------------------------------------
# 活动接口
# ---------------------------------------------------------------------------
def _headers(token, uid):
    """活动接口请求头，对齐桌面端 activity iframe 的真实请求。
    Cosy-ClientType 是 live 实证的关键 gate：缺失时服务端返回空 campaigns
    （2026-09-21 仅本账号验证；不主张服务端永远只校验这一项，故整套 Cosy 头都带上）。
    旧 daily check-in 协议里自派的 X-Machine-ID/X-Session-ID/X-Request-ID 经实测
    对 campaigns 接口无影响，已移除。"""
    return {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "User-Agent": CAMPAIGN_UA,
        "Authorization": "Bearer " + token,
        "Cosy-ClientType": COSY_CLIENT_TYPE,
        "Cosy-Version": COSY_VERSION,
        "Origin": ORIGIN,
        "Referer": CAMPAIGN_REFERER,
    }


def _api(path, method, token, uid, body=None, timeout=20):
    """活动接口请求，返回 (http_status, body_dict_or_text)。

    campaigns 的 GET/POST 都**只走 OPENAPI_BASE，绝不跨 host fallback**：claim 是
    有副作用的 POST，若第一枪服务端已领取成功但客户端超时/连接中断，自动改打第二个
    host 会再 POST 一次并拿回 4xx，从而绕过 do_checkin 的复查恢复——把"其实已领到"
    误判成 CLAIM_FAIL。因此网络异常一律向上抛，交给 do_checkin 复查判定。
    （deviceToken/refresh 有自己的跨 host fallback，见 refresh_token_pair，不受影响。）"""
    req = urllib.request.Request(
        OPENAPI_BASE + path, data=body, method=method,
        headers=_headers(token, uid))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            status = resp.status if hasattr(resp, "status") else 200
        try:
            return status, json.loads(raw)
        except ValueError:
            return status, raw
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", "replace")
        except Exception:
            raw = ""
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = raw
        return exc.code, parsed


# 领取窗口由服务端 campaigns 决定（活动按 10:00→次日10:00 分窗，不是本地自然日）。
# 注意：除 CLAIMED/CLAIMABLE 外的一切 claimStatus（含未知枚举）一律 fail-close，
# 不当作成功——本任务目标是"真的领到 100"，未领取必须暴露而非静默绿。
CLAIMED_STATUSES = {"CLAIMED", "CLAIMED_TODAY"}
CLAIMABLE_STATUSES = {"CLAIMABLE"}


def normalize_body(body):
    """兼容顶层 JSON 与 {data:{...}} 信封两种响应结构。"""
    if not isinstance(body, dict):
        raise ValueError("unexpected non-JSON response: %r" % (body,))
    data = body.get("data")
    return data if isinstance(data, dict) else body


def _benefit_amount(campaign):
    b = campaign.get("benefit") or {}
    try:
        return int(b.get("amount") or 0)
    except (TypeError, ValueError):
        return 0


def _is_daily_100(campaign):
    """严格判定"每日 100 Credits"目标活动，排除一次性致歉 500 包/VIEW_DETAILS 等。"""
    if not isinstance(campaign, dict):
        return False
    b = campaign.get("benefit") or {}
    if not isinstance(b, dict):
        return False
    series = ((b.get("modelScope") or {}).get("modelSeries") or {}).get("key")
    return (campaign.get("actionType") == "CLAIM_BENEFIT"
            and b.get("kind") == "CREDITS"
            and _benefit_amount(campaign) == DAILY_BENEFIT_AMOUNT
            and series == "ALL_MODELS")


def find_target_campaign(campaigns):
    """从活动列表里挑出每日 100 Credits 活动；没有则返回 None。
    多个匹配时取 startAt 最新（当前窗口）的活动，claimable 仅作同窗口内的次级键——
    避免某天残留的旧窗口 CLAIMABLE 盖过当前窗口，导致去 POST 一个已过期活动。"""
    matches = [c for c in (campaigns or []) if _is_daily_100(c)]
    if not matches:
        return None

    def rank(c):
        try:
            start = int(c.get("startAt") or 0)
        except (TypeError, ValueError):
            start = 0
        claimable = str(c.get("claimStatus") or "").upper() in CLAIMABLE_STATUSES
        return (start, 1 if claimable else 0)

    return sorted(matches, key=rank, reverse=True)[0]


def fetch_campaigns(token, uid):
    """GET campaigns。返回 (state, payload)：
      state=OK     payload 为含 campaigns 列表的 dict
      state=AUTH   401/403，token 被拒（payload=None）
      state=HTTP   其它 4xx/5xx 或网络错误（payload 为错误串）
      state=SCHEMA 200 但结构异常/疑似改版（payload 为说明串）
    """
    try:
        status, body = _api(PATH_CAMPAIGNS, "GET", token, uid)
    except Exception as exc:
        return "HTTP", "请求失败：%r" % (exc,)
    if status in (401, 403):
        return "AUTH", None
    if status >= 400:
        return "HTTP", "HTTP %d %s" % (status, str(body)[:160])
    try:
        data = normalize_body(body)
    except ValueError as exc:
        return "SCHEMA", str(exc)[:160]
    if not isinstance(data.get("campaigns"), list):
        return "SCHEMA", "campaigns 字段缺失或非列表（疑似 API 改版）"
    return "OK", data


def _claim_succeeded(body):
    """claim 响应里是否有**明确状态证据**（缺则触发复查）。返回 bool。
    只认 success/CLAIMED*/replayed；绝不把 benefit.amount>0 或 rewardCredits>0
    当成功——否则 {"status":"FAILED","benefit":{"amount":100}} 会被误判为已领取，
    违背"没有明确成功证据就绝不绿"的 fail-close 不变量。"""
    if not isinstance(body, dict):
        return False
    try:
        b = normalize_body(body)
    except ValueError:
        return False
    if b.get("success") is True:
        return True
    cs = str(b.get("claimStatus") or b.get("status") or "").upper()
    if cs in CLAIMED_STATUSES:
        return True
    if b.get("replayed") is True:
        return True
    return False


def _reverify_claimed(token, uid, campaign_id):
    """复查 campaigns，确认指定 campaignId 已变 CLAIMED。
    既用于消灭"假成功"，也用于 POST 超时/5xx 后判断服务端是否其实已记账。"""
    state, payload = fetch_campaigns(token, uid)
    if state != "OK":
        return False
    for c in (payload.get("campaigns") or []):
        if (isinstance(c, dict) and c.get("campaignId") == campaign_id
                and str(c.get("claimStatus") or "").upper() in CLAIMED_STATUSES):
            return True
    return False


def do_checkin(token, uid):
    """签到主流程：campaigns 驱动。返回 (exit_code, result_dict)。

    目标活动 CLAIMED   -> ALREADY（本轮已领，不再 POST）
    目标活动 CLAIMABLE -> POST claim；缺显式成功证据时复查 campaigns 确认 CLAIMED
    无目标活动         -> NO_CAMPAIGN（exit4，未到窗口/传播延迟，归可重试）
    未知 claimStatus / 结构异常 -> SCHEMA_FAIL（exit4，疑似改版，归需人工）
    绝不伪装成功：目标是"真的领到 100"，未领取必须暴露而非静默绿。
    """
    state, payload = fetch_campaigns(token, uid)
    if state == "AUTH":
        return EXIT_TOKEN, {"result": "AUTH_FAIL",
                            "error": "campaigns 接口拒绝鉴权(401/403)，token 可能已失效"}
    if state == "HTTP":
        return EXIT_FAIL, {"result": "CAMPAIGNS_HTTP_FAIL", "error": payload}
    if state == "SCHEMA":
        return EXIT_FAIL, {"result": "SCHEMA_FAIL", "error": payload}

    campaigns = payload.get("campaigns") or []
    target = find_target_campaign(campaigns)
    if target is None:
        # 未找到每日 100 活动：多为未到 10:00 窗口或活动刚开放传播延迟。归 RETRY，
        # 让后续 12:37/19:07/22:37 档兜底；连续多次仍无由 health 计数暴露给人工。
        return EXIT_FAIL, {"result": "NO_CAMPAIGN",
                           "error": "campaigns 中未找到 CLAIM_BENEFIT/CREDITS/100/"
                                    "ALL_MODELS 目标活动（共 %d 个活动）。可能未到 "
                                    "10:00 窗口、活动已结束或响应改版。" % len(campaigns)}

    cid = target.get("campaignId")
    amount = _benefit_amount(target)
    cstatus = str(target.get("claimStatus") or "").upper()

    if not isinstance(cid, str) or not cid.strip():
        # 没有合法 campaignId 就无法构造 claim URL（否则会拼出 /campaigns/None/claim）
        return EXIT_FAIL, {"result": "SCHEMA_FAIL",
                           "error": "目标活动缺少合法 campaignId（%r），疑似响应改版。" % (cid,)}

    if cstatus in CLAIMED_STATUSES:
        return EXIT_OK, {"result": "ALREADY", "msg": "本轮已领取 %d Credits" % amount,
                         "reward_credits": amount, "campaign_id": cid}

    if cstatus not in CLAIMABLE_STATUSES:
        # 未知/异常 claimStatus（EXPIRED/NOT_STARTED/LOCKED/新枚举）-> fail-close
        return EXIT_FAIL, {"result": "SCHEMA_FAIL",
                           "error": "目标活动 claimStatus=%r 非 CLAIMED/CLAIMABLE，"
                                    "按失败上报（疑似活动状态枚举改版）。" % cstatus}

    try:
        status, body = _api(claim_path(cid), "POST", token, uid, body=b"{}")
    except Exception as exc:
        # POST 超时/连接中断：服务端可能已记账但响应丢失。先复查再判失败（recovered），
        # 避免"其实领到了却报失败、下一轮又领一次"或"漏报成功"。
        if _reverify_claimed(token, uid, cid):
            return EXIT_OK, {"result": "OK",
                             "msg": "领取成功（请求异常但复查已 CLAIMED）",
                             "reward_credits": amount, "campaign_id": cid,
                             "verified": True, "recovered": True}
        return EXIT_FAIL, {"result": "CLAIM_FAIL",
                           "error": "claim 请求异常且复查未确认 CLAIMED：%r" % (exc,)}

    text = str(body)
    if status in (401, 403):
        return EXIT_TOKEN, {"result": "AUTH_FAIL",
                            "error": "claim 接口返回 %d，token 可能已失效" % status}
    if status == 409 or "ALREADY_CLAIMED" in text.upper():
        # 409 只是 Conflict，不等价"已领取"；新 campaigns API 的 409 body 尚未 live 捕获。
        # 一律复查：确认该 campaignId 真变 CLAIMED 才认 ALREADY，否则 fail-close。
        if _reverify_claimed(token, uid, cid):
            return EXIT_OK, {"result": "ALREADY",
                             "msg": "本轮已领取（claim 冲突，复查确认 CLAIMED）",
                             "reward_credits": amount, "campaign_id": cid,
                             "verified": True}
        return EXIT_FAIL, {"result": "CLAIM_FAIL",
                           "error": "claim HTTP %d 冲突但复查未确认 CLAIMED %s"
                                    % (status, text[:160])}
    if status >= 400:
        # 5xx 可能是"服务端已记账但网关报错"，先复查再判失败；4xx 是明确客户端错误，直接失败
        if status >= 500 and _reverify_claimed(token, uid, cid):
            return EXIT_OK, {"result": "OK",
                             "msg": "领取成功（HTTP %d 但复查已 CLAIMED）" % status,
                             "reward_credits": amount, "campaign_id": cid,
                             "verified": True, "recovered": True}
        return EXIT_FAIL, {"result": "CLAIM_FAIL",
                           "error": "claim HTTP %d %s" % (status, text[:160])}

    if _claim_succeeded(body):
        return EXIT_OK, {"result": "OK", "msg": "领取成功 +%d Credits" % amount,
                         "reward_credits": amount, "campaign_id": cid, "verified": False}

    # 无明确成功证据：复查 campaigns，确认该 campaignId 变 CLAIMED 才算成功（消灭假成功）
    if _reverify_claimed(token, uid, cid):
        return EXIT_OK, {"result": "OK", "msg": "领取成功（复查确认）",
                         "reward_credits": amount, "campaign_id": cid, "verified": True}
    return EXIT_FAIL, {"result": "CLAIM_FAIL",
                       "error": "claim 无明确成功证据且复查未确认 CLAIMED (resp=%s)"
                                % text[:120]}


def campaigns_summary(token, uid):
    """status 子命令用：返回 (ok, 概览 dict)。"""
    state, payload = fetch_campaigns(token, uid)
    if state != "OK":
        return False, {"state": state, "error": payload}
    camps = [c for c in (payload.get("campaigns") or []) if isinstance(c, dict)]
    target = find_target_campaign(camps)
    return True, {
        "show_campaign": payload.get("showCampaign"),
        "claimable": payload.get("claimable"),
        "n_campaigns": len(camps),
        "campaigns": [{"campaignKey": c.get("campaignKey"),
                       "actionType": c.get("actionType"),
                       "claimStatus": c.get("claimStatus"),
                       "amount": _benefit_amount(c)} for c in camps],
        "target": ({"campaignId": target.get("campaignId"),
                    "campaignKey": target.get("campaignKey"),
                    "claimStatus": target.get("claimStatus"),
                    "amount": _benefit_amount(target)} if target else None),
    }


def log_line(entry):
    line = json.dumps({"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "app": "qoder",
                       **entry}, ensure_ascii=False)
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


def main():
    # Windows 控制台 UTF-8 输出
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    as_json = "--json" in sys.argv
    cmd = "status" if "status" in sys.argv[1:] else "checkin"

    try:
        token, refresh, uid, nickname = ensure_token()
    except Exception as exc:
        log_line({"cmd": cmd, "result": "AUTH_FAIL", "error": str(exc)[:200]})
        sys.exit(EXIT_AUTH)

    if cmd == "status":
        ok, summary = campaigns_summary(token, uid)
        if as_json:
            log_line({"cmd": cmd, "result": "OK" if ok else "FAIL",
                      "status": summary if ok else None,
                      "error": None if ok else summary})
        else:
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        sys.exit(EXIT_OK if ok else EXIT_FAIL)

    code, result = do_checkin(token, uid)
    if as_json:
        log_line({"cmd": cmd, "uid": uid[:8] if uid else "",
                  "nickname": nickname, **result})
    else:
        icon = {"OK": "[+]", "ALREADY": "[=]"}.get(result["result"], "[!]")
        print("%s Qoder CN: %s" % (icon, result.get("msg") or result.get("error")))
    sys.exit(code)


if __name__ == "__main__":
    main()
