"""Read-only loader and validator for descriptive reward rules."""
import json
import os


ROOT = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(ROOT, "data", "reward-rules.json")
VALID_STATUSES = {
    "official_verified",
    "secondary_verified_needs_official_confirmation",
    "review_required",
}


class RewardRulesError(RuntimeError):
    pass


def load_rules(path=None):
    source = path or RULES_FILE
    try:
        with open(source, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        raise RewardRulesError("奖励规则文件无法读取或解析") from None
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise RewardRulesError("奖励规则 schema_version 不支持")
    rules = data.get("rules")
    if not isinstance(rules, list):
        raise RewardRulesError("奖励规则 rules 必须为列表")
    seen = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise RewardRulesError("奖励规则记录必须为对象")
        rule_id = rule.get("rule_id")
        if not isinstance(rule_id, str) or not rule_id.strip() or rule_id in seen:
            raise RewardRulesError("奖励规则 ID 缺失或重复")
        seen.add(rule_id)
        if rule.get("status") not in VALID_STATUSES:
            raise RewardRulesError("奖励规则状态无效：" + rule_id)
        if not isinstance(rule.get("provider_id"), str) or not rule["provider_id"]:
            raise RewardRulesError("奖励规则 provider_id 缺失：" + rule_id)
        reward = rule.get("reward")
        if not isinstance(reward, dict):
            raise RewardRulesError("奖励规则 reward 缺失：" + rule_id)
        amount = reward.get("amount")
        if amount is not None and (isinstance(amount, bool) or not isinstance(amount, (int, float)) or amount < 0):
            raise RewardRulesError("奖励金额无效：" + rule_id)
        if not isinstance(rule.get("sources"), list) or not rule["sources"]:
            raise RewardRulesError("奖励规则缺少来源：" + rule_id)
        for item in rule["sources"]:
            if not isinstance(item, dict) or not str(item.get("url", "")).startswith(("https://", "http://")):
                raise RewardRulesError("奖励规则来源 URL 无效：" + rule_id)
    return data


def get_rule(rule_id, provider_id=None, path=None):
    for rule in load_rules(path)["rules"]:
        if rule["rule_id"] == rule_id:
            if provider_id and rule["provider_id"] != provider_id:
                raise RewardRulesError("奖励规则与 provider 不匹配")
            return rule
    raise RewardRulesError("找不到奖励规则：" + str(rule_id))
