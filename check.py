#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""部署前一键体检：验证三件套的本地凭据、网络与计划任务状态。

用法：
  python check.py       全部诊断（不发签到请求、不打印任何令牌）
"""

import json
import os
import subprocess
import sys
import time
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_all  # noqa: E402  复用其解密与探测逻辑


def ok(msg):
    print("  [OK] %s" % msg)


def bad(msg):
    print("  [!!] %s" % msg)


def info(msg):
    print("  [--] %s" % msg)


def section(title):
    print("\n== %s ==" % title)


def check_python():
    section("Python 运行环境")
    v = sys.version_info
    if v >= (3, 8):
        ok("Python %d.%d.%d (%s)" % (v.major, v.minor, v.micro, sys.executable))
    else:
        bad("Python %d.%d 过旧，需要 3.8+" % (v.major, v.minor))


def check_workbuddy():
    section("WorkBuddy 凭据")
    home = os.path.expanduser("~")
    local = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
    candidates = [
        os.environ.get("WORKBUDDY_AUTH_FILE") or "",
        os.path.join(local, "CodeBuddyExtension", "Data", "Public", "auth",
                     "workbuddy-desktop.info"),
        os.path.join(home, ".workbuddy", "auth", "workbuddy-desktop.info"),
    ]
    found = None
    for c in candidates:
        if c and os.path.isfile(c):
            found = c
            break
    if not found:
        bad("未找到 workbuddy-desktop.info。请安装并登录 WorkBuddy 桌面端。")
        info("已探测: %s" % "; ".join(c for c in candidates if c))
        return
    try:
        with open(found, encoding="utf-8") as fh:
            d = json.load(fh)
        if isinstance(d, dict) and ("accessToken" in d or "token" in d
                                    or "session" in d):
            ok("凭据文件可读: %s" % found)
        else:
            info("凭据文件存在但结构与预期不同（signin.py 会自行解析）: %s" % found)
    except Exception as exc:
        bad("凭据文件存在但解析失败: %s" % exc)


def check_trae():
    section("Trae / TRAE SOLO 凭据")
    path = run_all.find_trae_storage()
    if not path:
        bad("未找到 storage.json。请先安装并登录 Trae / TRAE SOLO 客户端。")
        return
    info("storage.json: %s" % path)
    cred = run_all.load_trae_credential()
    if cred.get("error"):
        bad(cred["error"])
        return
    ok("凭据解密成功（账号 %s，设备号 %s）"
       % (cred.get("nickname") or cred.get("uid") or "?",
          "客户端真实值" if cred.get("device") else "将自动生成"))


def check_qoder():
    section("Qoder CN 凭据")
    if os.name != "nt":
        bad("当前不是 Windows，DPAPI 解密不可用（本方案仅支持 Windows）。")
        return
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "qoder_checkin", os.path.join(HERE, "qoder", "qoder_checkin.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    app_dir = mod.app_data_dir()
    info("数据目录: %s" % app_dir)
    try:
        app = mod.load_app_auth()
    except FileNotFoundError as exc:
        bad("未找到 Qoder 凭据文件（%s）。请安装并登录 Qoder CN 桌面端。" % exc)
        return
    except Exception as exc:
        bad("解密失败: %s" % exc)
        return
    user = app.get("user") or {}
    exp = mod._parse_expires(app.get("expiresAt"))
    left = int((exp - time.time()) / 86400) if exp else None
    ok("auth.v1.dat 解密成功（账号 %s，token 剩余约 %s 天）"
       % (user.get("name") or user.get("id") or "?", left if left is not None else "?"))
    if exp and exp < time.time():
        info("token 已过期：签到时会自动用 refreshToken 续期（drt- 一年有效）")


def check_network():
    section("签到服务网络连通")
    for name, url in (("Trae", "https://api.trae.cn"),
                      ("WorkBuddy", "https://copilot.tencent.com"),
                      ("Qoder", "https://openapi.qoder.com.cn")):
        try:
            urllib.request.urlopen(url, timeout=10)
            ok("%s (%s) 可达" % (name, url))
        except urllib.error.HTTPError:
            ok("%s (%s) 可达（HTTP 错误码属正常）" % (name, url))
        except Exception as exc:
            bad("%s (%s) 不可达: %s" % (name, url, exc))


def check_tasks():
    section("计划任务")
    if os.name != "nt":
        info("非 Windows 环境，跳过。")
        return
    for name in ("AutoCheckinBoot", "AutoCheckinDaily"):
        try:
            r = subprocess.run(["schtasks", "/query", "/tn", name],
                               capture_output=True, timeout=15)
            if r.returncode == 0:
                ok("%s 已安装" % name)
            else:
                info("%s 未安装（运行 install.ps1 安装）" % name)
        except Exception:
            info("%s 查询失败" % name)


def check_health():
    section("运行健康（连续失败计数，logs\\health.json）")
    health = run_all.load_health()
    if not health:
        info("尚无运行记录：安装后会随每轮签到自动累积")
        return
    for name in ("workbuddy", "trae", "qoder"):
        rec = health.get(name)
        if not rec:
            info("%s: 暂无记录" % name)
            continue
        fails = int(rec.get("consecutive_failures") or 0)
        last_ok = rec.get("last_success") or "从未成功"
        if fails == 0:
            ok("%s: 正常（最近成功 %s）" % (name, last_ok))
            continue
        msg = "%s: 已连续失败 %d 次（最近成功 %s）" % (name, fails, last_ok)
        # NEEDS_HUMAN（凭据/会话失效）重试无意义；连续 >=5 次也该人工看一眼
        if rec.get("outcome") == run_all.OUTCOME_HUMAN or fails >= 5:
            bad(msg)
            bad("  最近错误: %s" % (rec.get("last_error") or "?"))
            info("  排查: python run_all.py --only %s 看完整输出；"
                 "凭据类失败需重新登录对应客户端" % name)
        else:
            info("%s —— 多为瞬时网络/限流，下一个触发点自动补签" % msg)


def main():
    print("三合一自动签到 · 部署体检  (%s)" % time.strftime("%Y-%m-%d %H:%M:%S"))
    check_python()
    check_workbuddy()
    check_trae()
    check_qoder()
    check_network()
    check_tasks()
    check_health()
    print("\n体检完成。手动试跑一轮签到（控制台可见输出）：")
    print("  python \"%s\"" % os.path.join(HERE, "run_all.py"))
    print("查看日志: %s" % os.path.join(HERE, "logs"))


if __name__ == "__main__":
    main()
