"""Persisted manual-review freezes for provider accounts.

Only a one-way hash of the provider account identifier is persisted. The file
lives beside the DPAPI credential cache and is protected by the same store.
"""
import hashlib
import os
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from secure_store import credential_dir, read_json_with_migration, write_secure_json

CONTROL_FILE = os.path.join(credential_dir(), "account-controls.dpapi")
SCHEMA_VERSION = 1


def _key(provider, account_id):
    provider = str(provider or "").strip().lower()
    identity = str(account_id or "").strip()
    if provider not in {"workbuddy", "trae", "qoder"} or not identity:
        raise ValueError("provider/account_id is invalid")
    return hashlib.sha256((provider + "\0" + identity).encode("utf-8")).hexdigest()


def _load():
    data = read_json_with_migration(CONTROL_FILE)
    if data and data.get("schema") != SCHEMA_VERSION:
        raise RuntimeError("account-control schema is unsupported")
    frozen = data.get("frozen", {}) if data else {}
    if not isinstance(frozen, dict):
        raise RuntimeError("account-control data is corrupt")
    return {"schema": SCHEMA_VERSION, "frozen": frozen}


def _save(data):
    write_secure_json(CONTROL_FILE, data)


def is_frozen(provider, account_id):
    if not account_id:
        return False
    key = _key(provider, account_id)
    return key in _load()["frozen"]


def freeze_account(provider, account_id, reason):
    key = _key(provider, account_id)
    safe_reason = str(reason or "AUTH_REJECTED")[:64]
    data = _load()
    data["frozen"][key] = {
        "provider": str(provider).lower(),
        "reason": safe_reason,
        "frozen_at": int(time.time()),
    }
    _save(data)
    return key[:12]


def unfreeze_accounts(provider=None, account_id=None):
    data = _load()
    selected_provider = str(provider or "").strip().lower()
    if selected_provider and selected_provider not in {"workbuddy", "trae", "qoder", "all"}:
        raise ValueError("provider must be workbuddy, trae, qoder or all")
    selected_key = _key(selected_provider, account_id) if account_id else None
    removed = []
    for key, record in list(data["frozen"].items()):
        if selected_key:
            match = key == selected_key
        elif selected_provider in ("", "all"):
            match = True
        else:
            match = record.get("provider") == selected_provider
        if match:
            removed.append(key[:12])
            del data["frozen"][key]
    if removed:
        _save(data)
    return removed


def list_frozen():
    data = _load()
    return [
        {
            "id": key[:12],
            "provider": record.get("provider", "unknown"),
            "reason": record.get("reason", "unknown"),
            "frozen_at": record.get("frozen_at"),
        }
        for key, record in sorted(data["frozen"].items())
    ]
