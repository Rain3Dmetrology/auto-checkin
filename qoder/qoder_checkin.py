#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Qoder CN 每日自动签到（Windows 零依赖版）。

整合自两个开源实现（致谢）：
  - hope0719/qoder-check-in   签到接口流程（sash daily-check-in）
  - luispater/qoder2api-hub   Windows 凭据解密（DPAPI + AES-256-GCM）

工作原理（全程只读官方客户端凭据，不回写、不打印令牌）：
  1. 读 %APPDATA%\\com.qodercn.app.stable\\Local State
     -> os_crypt.encrypted_key -> 剥 "DPAPI" 前缀 -> DPAPI 解出 32 字节 AES key
  2. 读同目录 auth.v1.dat（Electron os_crypt v10 布局）
     -> AES-256-GCM 解出 {token(dt-), refreshToken(drt-), expiresAt, user{...}}
  3. dt- 过期时用 drt- 调 deviceToken/refresh 换新（结果缓存在本目录
     state.json，绝不回写 auth.v1.dat，不影响桌面客户端）
  4. GET  /sash/api/v1/me/daily-check-in/status   今日已签则跳过
     POST /sash/api/v1/me/daily-check-in/claim    领取签到积分
     409 ALREADY_CLAIMED 归一化为"已签"（幂等，重复运行安全）

用法：
  python qoder_checkin.py            签到（已签自动跳过）
  python qoder_checkin.py status      仅查状态（调试）
  python qoder_checkin.py --json      JSON 行输出（供调度器解析）

退出码：0 成功/已签/活动未开放；2 凭据缺失或解密失败；3 token 失效无法续期；4 签到失败。
"""

import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid

# ---------------------------------------------------------------------------
# 常量（逆向自 Qoder CN 官方桌面客户端）
# ---------------------------------------------------------------------------
OPENAPI_BASE = os.environ.get("QODER_API_BASE", "https://openapi.qoder.com.cn").rstrip("/")
GATEWAY_BASE = "https://gateway.qoder.com.cn"          # 备用基地址
PATH_STATUS = "/sash/api/v1/me/daily-check-in/status"
PATH_CLAIM = "/sash/api/v1/me/daily-check-in/claim"
PATH_DEVICE_REFRESH = "/api/v1/deviceToken/refresh"
CLIENT_UA = "Go-http-client/2.0"
ORIGIN = "https://qoder.com.cn"

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
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S"):
        try:
            return int(datetime.datetime.strptime(s[:26] if "." in s else s[:19],
                                                  fmt).timestamp())
        except ValueError:
            continue
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
# 签到接口
# ---------------------------------------------------------------------------
def _derive_id(uid, salt):
    """由 uid 稳定派生设备/会话标识（与官方客户端多会话行为一致，防风控）。"""
    return hashlib.md5(("%s:%s" % (salt, uid or "anonymous")).encode("utf-8")).hexdigest()[:36]


def _headers(token, uid):
    h = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "User-Agent": CLIENT_UA,
        "Authorization": "Bearer " + token,
        "Origin": ORIGIN,
        "Referer": ORIGIN + "/",
    }
    if uid:
        h["X-Request-ID"] = "%s-%s" % (_derive_id(uid, "req"),
                                       str(time.time_ns() % 1000000).zfill(6))
        h["X-Machine-ID"] = _derive_id(uid, "machine")
        h["X-Session-ID"] = _derive_id(uid, "session")
    return h


def _api(path, method, token, uid, body=None, timeout=20):
    """带备用基地址的请求。返回 (http_status, body_dict_or_text)。"""
    last_err = None
    for base in (OPENAPI_BASE, GATEWAY_BASE):
        req = urllib.request.Request(
            base + path, data=body, method=method,
            headers=_headers(token, uid))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
            try:
                return resp.status if hasattr(resp, "status") else 200, json.loads(raw)
            except ValueError:
                return 200, raw
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
        except Exception as exc:
            last_err = exc
            continue
    raise last_err or RuntimeError("request failed")


def _today():
    return time.strftime("%Y-%m-%d")


def checkin_status(token, uid):
    status, body = _api(PATH_STATUS, "GET", token, uid)
    if status >= 400:
        return False, "HTTP %d %s" % (status, str(body)[:160])
    last = 0
    if body.get("lastClaimedAt"):
        try:
            last = int(body["lastClaimedAt"])
        except Exception:
            last = 0
    st = str(body.get("status") or "")
    return True, {
        "status": st,
        "active": st in ("CLAIMABLE", "CLAIMED"),
        "today_checked_in": st == "CLAIMED"
        and last and time.strftime("%Y-%m-%d", time.localtime(last)) == _today(),
        "streak_days": int(body.get("currentStreakDays") or 0),
        "total_claim_days": int(body.get("totalClaimDays") or 0),
        "reward_credits": int(body.get("rewardCredits") or 0),
        "total_reward_credits": int(body.get("totalRewardCredits") or 0),
    }


def do_checkin(token, uid):
    """签到主流程：已签跳过，CLAIMABLE 才领取。返回 (exit_code, result_dict)。"""
    ok, st = checkin_status(token, uid)
    if not ok:
        return EXIT_FAIL, {"result": "STATUS_FAIL", "error": st}
    if st["today_checked_in"]:
        return EXIT_OK, {"result": "ALREADY", "msg": "今日已签到",
                         "streak_days": st["streak_days"],
                         "reward_credits": st["reward_credits"]}
    if not st["active"]:
        return EXIT_OK, {"result": "DISABLED",
                         "msg": "官方签到活动未开放 (status=%s)" % st["status"]}
    status, body = _api(PATH_CLAIM, "POST", token, uid, body=b"{}")
    text = str(body)
    if status == 409 or "ALREADY_CLAIMED" in text:
        return EXIT_OK, {"result": "ALREADY", "msg": "今日已签到",
                         "streak_days": st["streak_days"]}
    if status >= 400:
        return EXIT_FAIL, {"result": "CLAIM_FAIL",
                           "error": "HTTP %d %s" % (status, text[:160])}
    if isinstance(body, dict) and body.get("success") is False:
        # 复查一次：上游可能已记账
        ok2, st2 = checkin_status(token, uid)
        if ok2 and st2["today_checked_in"]:
            return EXIT_OK, {"result": "ALREADY", "msg": "今日已签到（复查确认）",
                             "streak_days": st2["streak_days"]}
        return EXIT_FAIL, {"result": "CLAIM_FAIL",
                           "error": str(body.get("error") or body)[:160]}
    reward = 0
    if isinstance(body, dict):
        try:
            reward = int(body.get("rewardCredits") or 0)
        except Exception:
            reward = 0
    return EXIT_OK, {"result": "OK", "msg": "签到成功 +%d 积分" % reward,
                     "reward_credits": reward,
                     "streak_days": None}


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
        ok, st = checkin_status(token, uid)
        if as_json:
            log_line({"cmd": cmd, "result": "OK" if ok else "FAIL",
                      "status": st if ok else None, "error": None if ok else st})
        else:
            print(json.dumps(st if ok else {"error": st}, ensure_ascii=False, indent=2))
        sys.exit(EXIT_OK if ok else EXIT_FAIL)

    code, result = do_checkin(token, uid)
    if as_json:
        log_line({"cmd": cmd, "uid": uid[:8] if uid else "",
                  "nickname": nickname, **result})
    else:
        icon = {"OK": "[+]", "ALREADY": "[=]", "DISABLED": "[-]"}.get(result["result"], "[!]")
        print("%s Qoder CN: %s" % (icon, result.get("msg") or result.get("error")))
        if result.get("streak_days") is not None:
            print("    连签 %s 天" % result["streak_days"])
    sys.exit(code)


if __name__ == "__main__":
    main()
