#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""三合一自动签到调度器：WorkBuddy + Trae + Qoder CN。

作为 Windows 计划任务的统一入口，依次静默执行三个签到子任务，
互不影响，汇总日志到 logs/ 目录。

子任务来源（均为成熟开源实现，本包只做整合与调度）：
  workbuddy/  88lin/workbuddy-auto-signin   MIT
  trae/       L0NE-6/Trae-AutoCheckin        （凭据解密改为本文件的零依赖实现）
  qoder/      整合自 hope0719/qoder-check-in 与 qoder2api-hub 的 Windows 移植

用法：
  python run_all.py            完整签到轮（WorkBuddy 全量 + Trae + Qoder）
  python run_all.py --poll     轮询模式（三个都幂等：已签自动跳过）
  python run_all.py --boot     开机模式（等待网络就绪后按 --poll 执行）
  python run_all.py --only trae|workbuddy|qoder    只跑指定软件

退出码：0 全部成功（含已签/跳过）；1 存在失败项。
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(HERE, "logs")
PYTHON = sys.executable or "pythonw.exe"

SUBPROC_TIMEOUT = 10 * 60        # 单个子任务最长 10 分钟
BOOT_NET_WAIT = 150              # 开机模式等网络就绪最长 150 秒


# ---------------------------------------------------------------------------
# 日志（pythonw 下 sys.stdout 为 None，print 静默无效果，统一落文件）
# ---------------------------------------------------------------------------
def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(msg=""):
    line = "[%s] %s" % (_now(), msg) if msg else ""
    os.makedirs(LOG_DIR, exist_ok=True)
    path = os.path.join(LOG_DIR, "run_%s.log" % time.strftime("%Y-%m-%d"))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    if sys.stdout is not None:
        try:
            print(line, flush=True)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Trae 桌面端凭据解密（纯标准库 AES-128-CBC，零 pip 依赖）
# 移植自 L0NE-6/Trae-AutoCheckin 的解密算法 + trae_get_token.py 的纯标准库实现，
# 支持桌面端两种加密形态（tc / tc-private）。
# ---------------------------------------------------------------------------
SALT_A = bytes([82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
                124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
                84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
                8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37])
SALT_B = bytes([31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
               96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
               160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
               23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125])
SALT_C = bytes([191, 192, 216, 250, 122, 246, 220, 97, 31, 254, 98, 27, 8, 72, 71, 176,
                135, 99, 96, 18, 127, 101, 203, 104, 211, 102, 191, 125, 37, 72, 150, 156,
                51, 229, 121, 35, 17, 153, 141, 177, 110, 131, 150, 128, 172, 255, 254, 6,
                18, 140, 55, 62, 236, 249, 135, 64, 135, 12, 117, 4, 89, 149, 168, 209])
SALT_D = bytes([246, 204, 26, 232, 232, 70, 129, 109, 223, 146, 169, 242, 23, 241, 105, 145,
                50, 196, 165, 42, 254, 120, 3, 54, 244, 207, 209, 85, 53, 6, 138, 106,
                175, 148, 31, 204, 186, 186, 165, 182, 87, 142, 49, 10, 39, 110, 26, 154,
                86, 56, 173, 125, 18, 64, 198, 225, 99, 99, 83, 82, 191, 134, 76, 170])
SALT_AES = bytes(a ^ b for a, b in zip(SALT_A, SALT_B))
SALT_AES_PRIVATE = bytes(a ^ b for a, b in zip(SALT_C, SALT_D))
TRAE_STORAGE_KEY = "iCubeAuthInfo://icube.cloudide"


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


def _build_sbox():
    inv = [0] * 256
    for i in range(1, 256):
        for j in range(1, 256):
            if _gmul(i, j) == 1:
                inv[i] = j
                break
    sb = [0] * 256
    for i in range(256):
        x = inv[i] if i else 0
        s = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        sb[i] = s ^ 0x63
    return sb


SBOX = _build_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
AES_RC = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _expand_key(key):
    w = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= AES_RC[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return w


def _round_key(w, r):
    ws = w[r * 4:r * 4 + 4]
    return [ws[c][k] for c in range(4) for k in range(4)]


def _addrk(s, k):
    return [s[i] ^ k[i] for i in range(16)]


def _isub(s):
    return [INV_SBOX[b] for b in s]


def _ishift(s):
    return [s[0], s[13], s[10], s[7], s[4], s[1], s[14], s[11],
            s[8], s[5], s[2], s[15], s[12], s[9], s[6], s[3]]


def _imix(s):
    o = []
    for c in range(4):
        a = s[c * 4:c * 4 + 4]
        o += [_gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9),
              _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13),
              _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11),
              _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)]
    return o


def aes128_cbc_decrypt(key, iv, data):
    w = _expand_key(key)
    out = b""
    prev = list(iv)
    for off in range(0, len(data), 16):
        blk = list(data[off:off + 16])
        s = _addrk(blk, _round_key(w, 10))
        for r in range(9, 0, -1):
            s = _ishift(s)
            s = _isub(s)
            s = _addrk(s, _round_key(w, r))
            s = _imix(s)
        s = _ishift(s)
        s = _isub(s)
        s = _addrk(s, _round_key(w, 0))
        out += bytes(a ^ b for a, b in zip(s, prev))
        prev = blk
    return out


def _trae_enc_type(header):
    if header[0:6] == bytes([0x74, 0x63, 0x05, 0x10, 0x00, 0x00]):
        return "AES"
    if header[0:6] == bytes([18, 57, 32, 32, 2, 3]):
        return "AES_PRIVATE"
    return "UNKNOWN"


def trae_decrypt_storage_value(b64):
    """解密 Trae storage.json 的 icubeAuth 值 -> 明文 JSON 字符串。"""
    buf = base64.b64decode(b64)
    enc_type = _trae_enc_type(buf[0:6])
    if enc_type == "UNKNOWN":
        raise ValueError("未知的加密类型 (前6字节=%s)" % buf[0:6].hex())
    salt = SALT_AES_PRIVATE if enc_type == "AES_PRIVATE" else SALT_AES
    rb = buf[6:38]
    fh = hashlib.sha512(hashlib.sha512(rb).digest() + salt).digest()
    dec = aes128_cbc_decrypt(fh[:16], fh[16:32], buf[38:])
    stored_hash, plaintext = dec[0:64], dec[64:]
    pad = plaintext[-1] if plaintext else 0
    if 1 <= pad <= 16:
        plaintext = plaintext[:-pad]
    else:
        plaintext = plaintext.rstrip(b"\x00").rstrip()
    if stored_hash != hashlib.sha512(plaintext).digest():
        raise ValueError("SHA-512 校验失败，解密可能不正确")
    return plaintext.decode("utf-8")


def find_trae_storage():
    """自动探测 Trae 桌面端 storage.json（与 trae_checkin.py 同路径集）。"""
    home = os.path.expanduser("~")
    names = ("Trae CN", "TRAE SOLO CN", "TRAE SOLO", "Trae")
    sub = ("User", "globalStorage", "storage.json")
    appdata = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
    candidates = [os.path.join(appdata, n, *sub) for n in names]
    lib = os.path.join(home, "Library", "Application Support")
    candidates += [os.path.join(lib, n, *sub) for n in names]
    for base in (home, os.path.join(home, ".config")):
        for n in (".trae-cn", ".trae", "Trae CN", "TRAE SOLO CN"):
            candidates.append(os.path.join(base, n, *sub))
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


def load_trae_credential():
    """解出 Trae 登录凭据。返回 dict（含 refreshToken / 设备号 / uid）。"""
    import re
    path = find_trae_storage()
    if not path:
        return {"error": "未找到 Trae 桌面端 storage.json（请先登录 Trae / TRAE SOLO）"}
    with open(path, encoding="utf-8") as fh:
        storage = json.load(fh)
    enc = (storage.get(TRAE_STORAGE_KEY) or "").strip()
    if not enc:
        return {"error": "storage.json 中无登录凭据（请先在 Trae 登录）"}
    txt = enc if enc.startswith("{") else trae_decrypt_storage_value(enc)
    rt = re.search(r'"refreshToken"\s*:\s*"([^"]+)"', txt)
    if not rt:
        return {"error": "凭据中无 refreshToken"}
    uid = re.search(r'"userId"\s*:\s*"(\d+)"', txt)
    nick = re.search(r'"username"\s*:\s*"([^"]*)"', txt)
    # 客户端真实设备号（icube-dc 键），比生成号更不易触发风控
    device = ""
    for k in storage:
        if k.startswith("iCubeAuthInfo://icube-dc:"):
            d = k.split(":")[-1]
            if d.isdigit():
                device = d
                break
    return {"refreshToken": rt.group(1), "uid": uid.group(1) if uid else "",
            "nickname": nick.group(1) if nick else "", "device": device, "path": path}


# ---------------------------------------------------------------------------
# 子任务执行
# ---------------------------------------------------------------------------
def net_ready():
    """探测三个签到服务任一可达。"""
    for url in ("https://api.trae.cn", "https://copilot.tencent.com",
                "https://openapi.qoder.com.cn"):
        try:
            urllib.request.urlopen(url, timeout=8)
            return True
        except Exception:
            continue
    return False


def wait_for_network(seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if net_ready():
            return True
        time.sleep(5)
    return False


def run_child(name, script, args, env_extra=None, cwd=None):
    """执行子脚本，输出汇入统一日志。返回 (exit_code, tail_lines)。"""
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    cmd = [PYTHON, script] + args
    log("%s 开始: %s" % (name, " ".join(
        [os.path.basename(script)] + [a for a in args if "TOKEN" not in a.upper()])))
    try:
        proc = subprocess.run(
            cmd, env=env, cwd=cwd or os.path.dirname(script),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=SUBPROC_TIMEOUT)
        out = (proc.stdout or b"").decode("utf-8", "replace")
        code = proc.returncode
    except subprocess.TimeoutExpired:
        log("%s 超时（>%d 分钟），已终止" % (name, SUBPROC_TIMEOUT // 60))
        return 1, []
    except Exception as exc:
        log("%s 启动失败: %s" % (name, exc))
        return 1, []
    tail = [l for l in out.splitlines() if l.strip()][-6:]
    for line in tail:
        log("  %s | %s" % (name, line))
    log("%s 结束 (exit=%d)" % (name, code))
    return code, tail


def task_workbuddy(poll=False):
    script = os.path.join(HERE, "workbuddy", "signin.py")
    if not os.path.isfile(script):
        log("workbuddy 跳过：signin.py 不存在")
        return 0, None
    mode = "silent-poll" if poll else "silent"
    code, tail = run_child("workbuddy", script, [mode])
    # signin.py 退出码：0 成功；1 会话失效（需重新登录桌面端）；2 环境类
    # （NO_AUTH / 未安装 / 凭据损坏）。未部署该软件不应拖垮整体退出码。
    if code in (0, 2):
        if code == 2:
            log("workbuddy 无可用凭据（未安装或未登录），本轮跳过")
        return 0, None
    return 1, None


def task_trae(poll=None):
    script = os.path.join(HERE, "trae", "trae_checkin.py")
    if not os.path.isfile(script):
        log("trae 跳过：trae_checkin.py 不存在")
        return 0, None
    cred = load_trae_credential()
    if cred.get("error"):
        log("trae 跳过：%s" % cred["error"])
        return 0, None     # 未装/未登录不算失败，避免拖累整体退出码
    env = {"TRAE_REFRESH_TOKEN": cred["refreshToken"]}
    if cred.get("device"):
        env["TRAE_DEVICE_ID"] = cred["device"]
    if cred.get("uid"):
        env["TRAE_UID"] = cred["uid"]
    if cred.get("nickname"):
        env["TRAE_NAME"] = cred["nickname"]
    log("trae 凭据已解出（账号 %s，来源 %s）"
        % (cred.get("nickname") or cred.get("uid") or "?",
           os.path.basename(os.path.dirname(os.path.dirname(cred["path"])))))
    code, tail = run_child("trae", script, [], env_extra=env)
    # trae_checkin.py：0=全部成功；非0表示有失败/异常
    return (0 if code == 0 else 1), None


def task_qoder(poll=None):
    script = os.path.join(HERE, "qoder", "qoder_checkin.py")
    if not os.path.isfile(script):
        log("qoder 跳过：qoder_checkin.py 不存在")
        return 0, None
    code, tail = run_child("qoder", script, ["--json"])
    # 退出码：0 成功/已签；2 未登录；3 token失效；4 签到失败
    if code in (0,):
        return 0, None
    if code == 2:
        log("qoder 未登录或凭据解密失败（详见 qoder/checkin.log）")
        return 0, None     # 未装/未登录不算失败
    return 1, None


TASKS = {"workbuddy": task_workbuddy, "trae": task_trae, "qoder": task_qoder}


def main():
    argv = sys.argv[1:]
    poll = "--poll" in argv or "--boot" in argv
    only = None
    for i, a in enumerate(argv):
        if a == "--only" and i + 1 < len(argv):
            only = argv[i + 1].lower()
    if "--boot" in argv:
        log("开机模式：等待网络就绪 ...")
        ok = wait_for_network(BOOT_NET_WAIT)
        log("网络%s" % ("已就绪" if ok else "等待超时，仍继续尝试签到"))

    log("=" * 60)
    log("自动签到调度开始（模式: %s%s）"
        % ("poll" if poll else "full", "，only=" + only if only else ""))

    names = [only] if only in TASKS else ["workbuddy", "trae", "qoder"]
    failed = []
    for n in names:
        rc, _ = TASKS[n](poll)
        if rc:
            failed.append(n)

    if failed:
        log("本轮结果：失败 %s" % "、".join(failed))
        log("=" * 60)
        sys.exit(1)
    log("本轮结果：全部成功（已签/跳过视为成功）")
    log("=" * 60)
    sys.exit(0)


if __name__ == "__main__":
    main()
