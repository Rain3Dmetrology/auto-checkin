#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Credential-only JSON storage.

Windows: current-user DPAPI + restrictive directory/file ACL + atomic replace.
POSIX: mode-0700 directory and mode-0600 file (no encryption without an OS
secret-store provider). Never silently downgrade Windows storage to plaintext.
"""

import csv
import ctypes
import io
import json
import os
import subprocess
import tempfile


MAGIC_DPAPI = b"AUTOCHECKIN-DPAPI-V1\n"
MAGIC_LOCAL = b"AUTOCHECKIN-LOCAL-V1\n"


class CredentialStoreError(RuntimeError):
    """The protected credential store is unavailable or corrupt."""


def credential_dir(env=None):
    env = os.environ if env is None else env
    if os.name == "nt":
        base = env.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
    else:
        base = env.get("XDG_DATA_HOME") or os.path.join(
            os.path.expanduser("~"), ".local", "share"
        )
    return os.path.join(base, "AutoCheckin", "credentials")


def _current_user_sid():
    try:
        raw = subprocess.check_output(
            ["whoami.exe", "/user", "/fo", "csv", "/nh"],
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
            timeout=5,
        )
        rows = [row for row in csv.reader(io.StringIO(raw)) if row]
        sid = rows[-1][-1].strip() if rows else ""
        if not sid.startswith("S-1-"):
            raise ValueError("SID format is invalid")
        return sid
    except Exception:
        raise CredentialStoreError(
            "无法确定当前 Windows 用户 SID，拒绝创建凭据存储 ACL"
        ) from None


def _set_windows_acl(path, is_dir):
    if os.name != "nt":
        return
    sid = _current_user_sid()
    icacls = os.path.join(
        os.environ.get("WINDIR", r"C:\Windows"), "System32", "icacls.exe"
    )
    rights = "(OI)(CI)F" if is_dir else "F"
    command = [
        icacls,
        path,
        "/inheritance:r",
        "/grant:r",
        "*%s:%s" % (sid, rights),
        "*S-1-5-18:%s" % rights,
        "*S-1-5-32-544:%s" % rights,
    ]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except Exception:
        raise CredentialStoreError("无法设置凭据文件 ACL") from None
    if result.returncode != 0:
        raise CredentialStoreError("凭据文件 ACL 设置失败")


def ensure_private_dir(path):
    if not path:
        raise CredentialStoreError("凭据目录路径为空")
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        if os.name == "nt":
            _set_windows_acl(path, True)
        else:
            os.chmod(path, 0o700)
    except CredentialStoreError:
        raise
    except Exception:
        raise CredentialStoreError("无法创建或保护凭据目录") from None


def _dpapi_crypt(data, protect):
    if os.name != "nt":
        raise CredentialStoreError("DPAPI 仅能在 Windows 当前用户上下文中解密")

    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    source = ctypes.create_string_buffer(data, len(data))
    in_blob = DATA_BLOB(
        len(data), ctypes.cast(source, ctypes.POINTER(ctypes.c_byte))
    )
    out_blob = DATA_BLOB()
    description = ctypes.c_wchar_p("AutoCheckin credential cache v1")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN

    if protect:
        fn = crypt32.CryptProtectData
        fn.argtypes = [
            ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR,
            ctypes.POINTER(DATA_BLOB), ctypes.c_void_p,
            ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)
        ]
        fn.restype = wintypes.BOOL
        ok = fn(
            ctypes.byref(in_blob), description, None, None, None,
            flags, ctypes.byref(out_blob)
        )
    else:
        fn = crypt32.CryptUnprotectData
        description_out = ctypes.c_wchar_p()
        fn.argtypes = [
            ctypes.POINTER(DATA_BLOB), ctypes.POINTER(ctypes.c_wchar_p),
            ctypes.POINTER(DATA_BLOB), ctypes.c_void_p,
            ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)
        ]
        fn.restype = wintypes.BOOL
        ok = fn(
            ctypes.byref(in_blob), ctypes.byref(description_out), None,
            None, None, flags, ctypes.byref(out_blob)
        )

    if not ok:
        code = ctypes.get_last_error()
        raise CredentialStoreError("DPAPI 操作失败（Windows 错误 %d）" % code)
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        if out_blob.pbData:
            kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))
        if not protect and description_out:
            kernel32.LocalFree(ctypes.cast(description_out, ctypes.c_void_p))


def _encode(value):
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if os.name == "nt":
        import base64
        return MAGIC_DPAPI + base64.b64encode(_dpapi_crypt(raw, True)) + b"\n"
    return MAGIC_LOCAL + raw


def _decode(raw):
    if raw.startswith(MAGIC_DPAPI):
        if os.name != "nt":
            raise CredentialStoreError("此凭据文件由 Windows DPAPI 保护，当前平台不能解密")
        import base64
        encoded = raw[len(MAGIC_DPAPI):].strip()
        try:
            cipher = base64.b64decode(encoded, validate=True)
            plain = _dpapi_crypt(cipher, False)
        except CredentialStoreError:
            raise
        except Exception:
            raise CredentialStoreError("DPAPI 凭据文件格式损坏") from None
    elif raw.startswith(MAGIC_LOCAL):
        if os.name == "nt":
            raise CredentialStoreError("Windows 凭据文件缺少 DPAPI 保护，拒绝读取")
        plain = raw[len(MAGIC_LOCAL):]
    else:
        # Unmarked JSON is accepted only as a one-time migration source.
        plain = raw

    try:
        value = json.loads(plain.decode("utf-8"))
    except Exception:
        raise CredentialStoreError("凭据缓存无法解析，拒绝回退到明文/过期凭据") from None
    if not isinstance(value, dict):
        raise CredentialStoreError("凭据缓存顶层必须为 JSON 对象")
    return value


def write_secure_json(path, value):
    if not isinstance(value, dict):
        raise CredentialStoreError("凭据缓存顶层必须为 JSON 对象")
    parent = os.path.dirname(os.path.abspath(path))
    ensure_private_dir(parent)
    payload = _encode(value)
    fd = None
    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(
            prefix=os.path.basename(path) + ".tmp-",
            dir=parent,
        )
        if os.name != "nt":
            os.chmod(temp_path, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        temp_path = None
        if os.name == "nt":
            _set_windows_acl(path, False)
        else:
            os.chmod(path, 0o600)
    except CredentialStoreError:
        raise
    except Exception:
        raise CredentialStoreError("无法原子写入加密凭据缓存") from None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def read_json_with_migration(path, legacy_paths=()):
    """Load a protected object, migrating plaintext legacy files only after
    the protected target has been written and read back successfully.
    """
    target = os.path.abspath(path)
    parent = os.path.dirname(target)
    ensure_private_dir(parent)

    if os.path.exists(target):
        try:
            with open(target, "rb") as stream:
                raw = stream.read()
        except Exception:
            raise CredentialStoreError("无法读取凭据缓存文件") from None

        value = _decode(raw)
        if not raw.startswith((MAGIC_DPAPI, MAGIC_LOCAL)):
            write_secure_json(target, value)
            verified = read_json_with_migration(target)
            if verified != value:
                raise CredentialStoreError("凭据缓存迁移读回校验失败")
        return value

    seen = set()
    for legacy in legacy_paths:
        if not legacy:
            continue
        source = os.path.abspath(legacy)
        if source in seen or source == target:
            continue
        seen.add(source)
        if not os.path.isfile(source):
            continue
        try:
            with open(source, "rb") as stream:
                raw = stream.read()
            value = _decode(raw)
            write_secure_json(target, value)
            with open(target, "rb") as stream:
                verify_raw = stream.read()
            verified = _decode(verify_raw)
            if verified != value:
                raise CredentialStoreError("旧凭据迁移读回校验失败")
            os.remove(source)
            return value
        except CredentialStoreError:
            raise
        except Exception:
            raise CredentialStoreError(
                "旧凭据缓存迁移失败；原文件已保留，停止使用该缓存"
            ) from None

    return {}
