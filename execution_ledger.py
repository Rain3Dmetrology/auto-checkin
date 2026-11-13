"""Append-only, idempotent reward claim ledger.

The ledger stores hashed account references only; never persist raw UIDs,
tokens, HTTP bodies, response dumps, or credentials.
"""
import datetime as dt
try:
    import fcntl
except ImportError:  # Windows
    fcntl = None
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from secure_store import credential_dir, ensure_private_dir, read_json_with_migration, write_secure_json
from reward_rules import get_rule, RewardRulesError

try:
    from secure_store import _set_windows_acl
except ImportError:
    _set_windows_acl = None


class LedgerError(RuntimeError):
    pass


def ledger_path():
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(
            os.path.expanduser("~"), ".local", "share"
        )
    return os.path.join(base, "AutoCheckin", "ledger", "claims.jsonl")


def _hash_account(provider_id, account_id, key=None):
    key = _identity_key() if key is None else key
    value = (str(provider_id) + "\0" + str(account_id)).encode("utf-8")
    return hmac.new(key, value, hashlib.sha256).hexdigest()


def _event_id(provider_id, account_ref, rule_id, window_key, key=None):
    key = _identity_key() if key is None else key
    value = "\0".join((provider_id, account_ref, rule_id, window_key)).encode("utf-8")
    return hmac.new(key, value, hashlib.sha256).hexdigest()


def _legacy_event_id(provider_id, account_id, rule_id, window_key):
    legacy_ref = hashlib.sha256(
        (str(provider_id) + "\0" + str(account_id)).encode("utf-8")
    ).hexdigest()
    value = "\0".join((provider_id, legacy_ref, rule_id, window_key))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _lock(stream):
    stream.seek(0, os.SEEK_END)
    if stream.tell() == 0:
        stream.write("\n")
        stream.flush()
    stream.seek(0)
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
    else:
        if fcntl is None:
            raise LedgerError("当前平台缺少文件锁实现")
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)


def _unlock(stream):
    try:
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            if fcntl is not None:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass


def _identity_key():
    """Load or create the local HMAC key inside the OS-protected credential store."""
    target = os.path.join(credential_dir(), "ledger-account-hash.dpapi")
    lock_path = target + ".lock"
    ensure_private_dir(os.path.dirname(target))
    with open(lock_path, "a+", encoding="utf-8", newline="") as stream:
        _lock(stream)
        try:
            value = read_json_with_migration(target)
            if value:
                key_text = value.get("key")
                if value.get("schema") != 1 or not isinstance(key_text, str):
                    raise LedgerError("ledger identity key has an unsupported format")
                try:
                    key = bytes.fromhex(key_text)
                except ValueError:
                    raise LedgerError("ledger identity key is corrupt") from None
                if len(key) != 32:
                    raise LedgerError("ledger identity key has an invalid length")
                return key
            key = secrets.token_bytes(32)
            write_secure_json(target, {"schema": 1, "key": key.hex()})
            return key
        finally:
            _unlock(stream)


def _read_ids(stream):
    stream.seek(0)
    ids = set()
    for line_no, line in enumerate(stream, 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except Exception:
            raise LedgerError("奖励账本第 %d 行损坏，拒绝追加以避免重复计数" % line_no)
        event_id = item.get("event_id") if isinstance(item, dict) else None
        if not isinstance(event_id, str) or len(event_id) != 64:
            raise LedgerError("奖励账本第 %d 行缺少 event_id" % line_no)
        ids.add(event_id)
    return ids


def append_claim(provider_id, account_id, rule_id, window_key, amount=None, evidence="explicit_success", path=None, outcome="claimed"):
    """Append a confirmed claim or already-claimed verification, idempotently.

    Evidence records how the result was confirmed; outcome distinguishes a new
    claim from a provider-reported claim that already existed.
    """
    if not account_id:
        raise LedgerError("account_id is required")
    if not isinstance(provider_id, str) or not provider_id.strip():
        raise LedgerError("provider_id is required")
    if not isinstance(window_key, str) or not window_key or len(window_key) > 128:
        raise LedgerError("window_key 无效")
    if evidence not in {"explicit_success", "state_reverified", "local_state"}:
        raise LedgerError("evidence type is invalid")
    if outcome not in {"claimed", "already"}:
        raise LedgerError("outcome is invalid")
    if outcome == "already" and evidence not in {"state_reverified", "local_state"}:
        raise LedgerError("already outcome requires verified or cached-state evidence")
    if outcome == "claimed" and evidence == "local_state":
        raise LedgerError("local-state evidence cannot represent a new claim")
    try:
        rule = get_rule(rule_id, provider_id=provider_id)
    except RewardRulesError as exc:
        raise LedgerError(str(exc)) from None
    if amount is not None and (
        isinstance(amount, bool) or not isinstance(amount, (int, float)) or amount < 0
        or (isinstance(amount, float) and not math.isfinite(amount))
    ):
        raise LedgerError("奖励金额必须是非负数字或 unknown")
    currency = rule["reward"].get("currency")
    if not isinstance(currency, str) or not currency:
        raise LedgerError("奖励规则缺少 currency")

    identity_key = _identity_key()
    subject = _hash_account(provider_id, account_id, identity_key)
    event_id = _event_id(provider_id, subject, rule_id, window_key, identity_key)
    legacy_event_id = _legacy_event_id(provider_id, account_id, rule_id, window_key)
    recorded_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    event = {
        "event_id": event_id,
        "recorded_at": recorded_at,
        "provider_id": provider_id,
        "account_ref": subject[:16],
        "rule_id": rule_id,
        "window_key": window_key,
        "outcome": outcome,
        "evidence": evidence,
        "currency": currency,
    }
    if amount is not None:
        event["amount"] = amount
    expiry = rule.get("expiry") or {}
    if expiry.get("duration") and expiry.get("unit") == "days" and expiry.get("anchor") == "claim_time":
        expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=int(expiry["duration"]))
        event["expected_expiry_at"] = expires.isoformat(timespec="seconds")
    target = os.path.abspath(path or ledger_path())
    parent = os.path.dirname(target)
    ensure_private_dir(parent)
    try:
        with open(target, "a+", encoding="utf-8", newline="") as stream:
            _lock(stream)
            try:
                existing_ids = _read_ids(stream)
                if event_id in existing_ids or legacy_event_id in existing_ids:
                    return False
                stream.seek(0, os.SEEK_END)
                stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            finally:
                _unlock(stream)
        if os.name == "nt" and _set_windows_acl:
            _set_windows_acl(target, False)
    except LedgerError:
        raise
    except Exception:
        raise LedgerError("奖励账本写入失败") from None
    return True


def read_events(path=None):
    target = path or ledger_path()
    if not os.path.exists(target):
        return []
    events = []
    with open(target, "r", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except Exception:
                raise LedgerError("奖励账本第 %d 行无法解析" % line_no)
    return events
