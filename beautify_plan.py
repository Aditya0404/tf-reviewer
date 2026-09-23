#!/usr/bin/env python3
"""Beautify Terraform JSON plan output for terminal review."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
import urllib.error
import urllib.request
from typing import Any


# ANSI colors
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "llama3.1"
LLM_SUMMARY_MAX_LEN = 64
LLM_VERDICT_MAX_LEN = 140
VALUE_MAX_LEN = 28

DEFAULT_GUARDRAILS_PATH = "guardrails.yaml"
VERDICT_LEVELS = ("allow", "require")
DEFAULT_VERDICT_LABELS = {"require": "APPROVAL REQUIRED", "allow": "NO APPROVAL"}
DEFAULT_ACTION_VERDICTS = {
    "create": "allow",
    "update": "require",
    "delete": "require",
    "replace": "require",
    "no-op": "allow",
}
ALLOWED_TOP_KEYS = {
    "version",
    "org_context",
    "verdict_labels",
    "rules",
    "protected_addresses",
    "defaults",
    "summary_hints",
}
ALLOWED_RULE_KEYS = {"id", "description", "match", "verdict", "reason", "severity"}
ALLOWED_MATCH_KEYS = {
    "resource_type",
    "address_regex",
    "module_regex",
    "action",
    "attribute",
    "only_attributes",
    "after_equals",
    "after_contains_any",
    "direction",
}
EXIT_APPROVAL_REQUIRED = 2
COMPLEX_ATTR_HINTS = (
    "policy",
    "assume_role_policy",
    "inline_policy",
    "document",
    "template",
    "user_data",
    "container_definitions",
)


def colorize(text: str, *codes: str, use_color: bool) -> str:
    if not use_color or not codes:
        return text
    return f"{''.join(codes)}{text}{RESET}"


def classify_action(actions: list[str]) -> str:
    normalized = tuple(actions)
    if normalized in {("delete", "create"), ("create", "delete")}:
        return "replace"
    if normalized == ("create",):
        return "create"
    if normalized == ("delete",):
        return "delete"
    if normalized == ("update",):
        return "update"
    if normalized == ("no-op",) or normalized == ("read",):
        return "no-op"
    return "+".join(actions) if actions else "unknown"


def action_style(action: str) -> tuple[str, ...]:
    styles = {
        "delete": (BOLD, RED),
        "replace": (BOLD, MAGENTA),
        "create": (BOLD, GREEN),
        "update": (BOLD, YELLOW),
        "no-op": (DIM,),
    }
    return styles.get(action, (CYAN,))


def truncate(value: str, max_len: int = VALUE_MAX_LEN) -> str:
    if len(value) <= max_len:
        return value
    return value[: max_len - 1] + "…"


def format_value(value: Any, max_len: int = VALUE_MAX_LEN) -> str:
    if value is None:
        return "null"
    if value == "<missing>":
        return "—"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                return format_value(json.loads(stripped), max_len=max_len)
            except json.JSONDecodeError:
                pass
        return truncate(stripped.replace("\n", " "), max_len)
    if isinstance(value, list):
        if not value:
            return "[]"
        if all(not isinstance(item, (dict, list)) for item in value):
            return truncate(
                ",".join(format_value(item, max_len=16) for item in value),
                max_len,
            )
        return truncate(json.dumps(value, separators=(",", ":")), max_len)
    if isinstance(value, dict):
        return truncate(json.dumps(value, separators=(",", ":")), max_len)
    return truncate(str(value), max_len)


def shorten_attr(key: str) -> str:
    aliases = {
        "engine_version": "engine",
        "instance_types": "instance",
        "instance_class": "class",
        "force_destroy": "force_destroy",
        "message_retention_seconds": "retention",
        "desired_capacity": "desired",
        "min_size": "min",
        "max_size": "max",
        "cidr_blocks": "cidr",
        "from_port": "from",
        "to_port": "to",
        "memory_size": "memory",
    }
    if key in aliases:
        return aliases[key]
    if key.startswith("tags."):
        return f"tag:{key.split('.', 1)[1]}"
    if key.startswith("scaling_config"):
        return key.replace("scaling_config[0].", "scale.")
    return key


def summarize_policy_delta(before: Any, after: Any) -> str | None:
    """Compact IAM/policy diffs instead of dumping JSON."""
    try:
        old = json.loads(before) if isinstance(before, str) else before
        new = json.loads(after) if isinstance(after, str) else after
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(old, dict) or not isinstance(new, dict):
        return None

    old_actions: set[str] = set()
    new_actions: set[str] = set()
    for statement in old.get("Statement", []) if isinstance(old.get("Statement"), list) else []:
        action = statement.get("Action", [])
        old_actions.update(action if isinstance(action, list) else [action])
    for statement in new.get("Statement", []) if isinstance(new.get("Statement"), list) else []:
        action = statement.get("Action", [])
        new_actions.update(action if isinstance(action, list) else [action])

    added = sorted(new_actions - old_actions)
    removed = sorted(old_actions - new_actions)
    if not added and not removed:
        return "policy updated"
    parts: list[str] = []
    if added:
        parts.append("+" + ",".join(added[:3]))
    if removed:
        parts.append("-" + ",".join(removed[:2]))
    return "policy " + " ".join(parts)


def format_change_line(key: str, old: Any, new: Any) -> str:
    key_l = key.lower()
    if "policy" in key_l:
        policy = summarize_policy_delta(old, new)
        if policy:
            return policy
    attr = shorten_attr(key)
    if old in (None, "<missing>"):
        return f"add {attr}={format_value(new, 20)}"
    if new in (None, "<missing>"):
        return f"remove {attr}={format_value(old, 20)}"
    return f"{attr} {format_value(old, 18)}→{format_value(new, 18)}"


def flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts/lists into dotted paths for short diffs."""
    flat: dict[str, Any] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else key
            flat.update(flatten(value, path))
        return flat
    if isinstance(obj, list):
        if not obj:
            flat[prefix or "[]"] = []
            return flat
        if all(not isinstance(item, (dict, list)) for item in obj):
            flat[prefix] = obj
            return flat
        for index, item in enumerate(obj):
            path = f"{prefix}[{index}]"
            flat.update(flatten(item, path))
        return flat
    flat[prefix or "."] = obj
    return flat


def changed_attributes(before: Any, after: Any) -> dict[str, dict[str, Any]]:
    """Return only attributes that differ between before and after."""
    if before is None and after is not None:
        return {key: {"before": None, "after": value} for key, value in flatten(after).items()}
    if after is None and before is not None:
        return {key: {"before": value, "after": None} for key, value in flatten(before).items()}
    if before is None and after is None:
        return {}

    before_flat = flatten(before)
    after_flat = flatten(after)
    changes: dict[str, dict[str, Any]] = {}
    for key in sorted(set(before_flat) | set(after_flat)):
        old = before_flat.get(key, "<missing>")
        new = after_flat.get(key, "<missing>")
        if old == new:
            continue
        changes[key] = {"before": old, "after": new}
    return changes


def is_complex_summary(summary: str, changes: dict[str, dict[str, Any]]) -> bool:
    """Decide whether an LLM should rewrite the mechanical summary."""
    if "…" in summary:
        return True
    if len(summary) > LLM_SUMMARY_MAX_LEN:
        return True
    for key, values in changes.items():
        key_l = key.lower()
        if any(hint in key_l for hint in COMPLEX_ATTR_HINTS):
            return True
        for side in ("before", "after"):
            raw = values.get(side)
            if isinstance(raw, str) and len(raw) > 80:
                return True
            if isinstance(raw, (dict, list)) and len(json.dumps(raw)) > 80:
                return True
    return False


def diff_summary(before: Any, after: Any, replace_paths: list[list[str]] | None = None) -> str:
    """Build a short, precise before→after summary."""
    if before is None and after is not None:
        changes = changed_attributes(None, after)
        identity_keys = ("name", "bucket", "id", "function_name", "identifier")
        for key in identity_keys:
            if key in changes:
                return f"create {format_value(changes[key]['after'], 24)}"
        lines = [format_change_line(key, vals["before"], vals["after"]) for key, vals in list(changes.items())[:2]]
        return truncate("; ".join(lines) if lines else "create resource", LLM_SUMMARY_MAX_LEN)

    if after is None and before is not None:
        changes = changed_attributes(before, None)
        if "type" in changes and ("from_port" in changes or "to_port" in changes):
            proto = format_value(changes.get("type", {}).get("before"), 12)
            port = format_value(
                changes.get("from_port", changes.get("to_port", {})).get("before"),
                8,
            )
            cidr = format_value(changes.get("cidr_blocks", {}).get("before"), 18)
            return truncate(f"delete {proto} {port} ({cidr})", LLM_SUMMARY_MAX_LEN)
        lines = [format_change_line(key, vals["before"], vals["after"]) for key, vals in list(changes.items())[:2]]
        return truncate("; ".join(lines) if lines else "delete resource", LLM_SUMMARY_MAX_LEN)

    if before is None and after is None:
        return "—"

    changes = changed_attributes(before, after)
    if not changes and replace_paths:
        paths = [".".join(path) for path in replace_paths]
        return truncate(f"replace via {','.join(paths)}", LLM_SUMMARY_MAX_LEN)
    if not changes:
        return "no changes"

    ordered_keys = list(changes.keys())
    if replace_paths:
        forced = {".".join(path) for path in replace_paths}
        ordered_keys.sort(key=lambda key: (0 if key in forced else 1, key))

    lines = [format_change_line(key, changes[key]["before"], changes[key]["after"]) for key in ordered_keys[:2]]
    if len(ordered_keys) > 2:
        lines.append(f"+{len(ordered_keys) - 2}")
    return truncate("; ".join(lines), LLM_SUMMARY_MAX_LEN)


def strip_llm_noise(content: str) -> str:
    content = (content or "").strip()
    if "</think>" in content:
        content = content.split("</think>", 1)[1].strip()
    if content.startswith("```"):
        lines = content.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        content = "\n".join(lines).strip()
    return content


def parse_json_payload(content: str) -> Any:
    cleaned = strip_llm_noise(content)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(cleaned[start : end + 1])
        start = cleaned.find("[")
        end = cleaned.rfind("]")
        if start != -1 and end != -1 and end > start:
            return json.loads(cleaned[start : end + 1])
        raise


def ollama_chat(
    *,
    messages: list[dict[str, str]],
    model: str,
    base_url: str,
    timeout: float,
) -> str:
    payload = {
        "model": model,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1, "num_predict": 900},
        "messages": messages,
    }
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))
    content = (body.get("message", {}) or {}).get("content") or ""
    if not content.strip():
        raise ValueError("empty LLM response")
    return content


# --------------------------------------------------------------------------- guardrails


class GuardrailsError(ValueError):
    """Raised when the guardrails file is missing, unparsable, or invalid."""


def default_guardrails() -> dict[str, Any]:
    """Minimal built-in policy used when no guardrails file is present."""
    return {
        "version": 1,
        "org_context": "",
        "verdict_labels": dict(DEFAULT_VERDICT_LABELS),
        "rules": [],
        "protected_addresses": [],
        "defaults": dict(DEFAULT_ACTION_VERDICTS),
        "summary_hints": [],
        "_source": "built-in defaults",
    }


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def validate_guardrails(data: Any, source: str) -> dict[str, Any]:
    """Validate the raw guardrails mapping. Unknown keys are errors (typos are dangerous)."""
    if not isinstance(data, dict):
        raise GuardrailsError(f"{source}: top level must be a mapping")

    unknown = set(data) - ALLOWED_TOP_KEYS
    if unknown:
        raise GuardrailsError(f"{source}: unknown top-level key(s): {', '.join(sorted(unknown))}")
    if data.get("version") != 1:
        raise GuardrailsError(f"{source}: unsupported or missing version (expected 1)")

    labels = dict(DEFAULT_VERDICT_LABELS)
    labels.update(data.get("verdict_labels") or {})
    if set(labels) != set(VERDICT_LEVELS):
        raise GuardrailsError(f"{source}: verdict_labels must define exactly {VERDICT_LEVELS}")

    defaults = dict(DEFAULT_ACTION_VERDICTS)
    for action, level in (data.get("defaults") or {}).items():
        if action not in DEFAULT_ACTION_VERDICTS:
            raise GuardrailsError(f"{source}: defaults has unknown action '{action}'")
        if level not in VERDICT_LEVELS:
            raise GuardrailsError(f"{source}: defaults.{action} must be one of {VERDICT_LEVELS}")
        defaults[action] = level

    rules: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw_rule in enumerate(as_list(data.get("rules"))):
        where = f"{source}: rules[{index}]"
        if not isinstance(raw_rule, dict):
            raise GuardrailsError(f"{where}: must be a mapping")
        unknown = set(raw_rule) - ALLOWED_RULE_KEYS
        if unknown:
            raise GuardrailsError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")
        rule_id = raw_rule.get("id")
        if not rule_id or not isinstance(rule_id, str):
            raise GuardrailsError(f"{where}: 'id' is required")
        if rule_id in seen_ids:
            raise GuardrailsError(f"{where}: duplicate rule id '{rule_id}'")
        seen_ids.add(rule_id)
        if raw_rule.get("verdict") not in VERDICT_LEVELS:
            raise GuardrailsError(f"{where} ({rule_id}): verdict must be one of {VERDICT_LEVELS}")
        match = raw_rule.get("match")
        if not isinstance(match, dict) or not match:
            raise GuardrailsError(f"{where} ({rule_id}): 'match' must be a non-empty mapping")
        unknown = set(match) - ALLOWED_MATCH_KEYS
        if unknown:
            raise GuardrailsError(f"{where} ({rule_id}): unknown match key(s): {', '.join(sorted(unknown))}")
        if "direction" in match and match["direction"] not in ("increase", "decrease"):
            raise GuardrailsError(f"{where} ({rule_id}): direction must be 'increase' or 'decrease'")
        for regex_key in ("address_regex", "module_regex"):
            if regex_key in match:
                try:
                    re.compile(match[regex_key])
                except re.error as exc:
                    raise GuardrailsError(f"{where} ({rule_id}): invalid {regex_key}: {exc}") from exc
        for action in as_list(match.get("action")):
            if action not in DEFAULT_ACTION_VERDICTS:
                raise GuardrailsError(f"{where} ({rule_id}): unknown action '{action}'")
        rules.append(
            {
                "id": rule_id,
                "description": raw_rule.get("description") or "",
                "match": match,
                "verdict": raw_rule["verdict"],
                "reason": raw_rule.get("reason") or raw_rule.get("description") or rule_id,
                "severity": raw_rule.get("severity") or "medium",
            }
        )

    protected: list[str] = []
    for pattern in as_list(data.get("protected_addresses")):
        try:
            re.compile(pattern)
        except (re.error, TypeError) as exc:
            raise GuardrailsError(f"{source}: invalid protected_addresses pattern '{pattern}': {exc}") from exc
        protected.append(pattern)

    return {
        "version": 1,
        "org_context": (data.get("org_context") or "").strip(),
        "verdict_labels": labels,
        "rules": rules,
        "protected_addresses": protected,
        "defaults": defaults,
        "summary_hints": [str(hint) for hint in as_list(data.get("summary_hints"))],
        "_source": source,
    }


def load_guardrails(path: str) -> dict[str, Any]:
    """Load YAML (PyYAML) or JSON guardrails. Raises FileNotFoundError / GuardrailsError."""
    with open(path, encoding="utf-8") as handle:
        text = handle.read()

    if path.lower().endswith(".json"):
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise GuardrailsError(f"{path}: invalid JSON: {exc}") from exc
        return validate_guardrails(raw, path)

    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:
        raise GuardrailsError(
            f"{path}: PyYAML is required to read YAML guardrails "
            "(pip install pyyaml), or provide a .json guardrails file"
        ) from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise GuardrailsError(f"{path}: invalid YAML: {exc}") from exc
    return validate_guardrails(raw, path)


def value_as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"))


def numeric(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def rule_matches(rule: dict[str, Any], row: dict[str, Any]) -> bool:
    match = rule["match"]
    changes: dict[str, dict[str, Any]] = row.get("changes") or {}

    resource_types = as_list(match.get("resource_type"))
    if resource_types and row.get("type") not in resource_types:
        return False

    actions = as_list(match.get("action"))
    if actions and row["action"] not in actions:
        return False

    if "address_regex" in match and not re.search(match["address_regex"], row["resource"]):
        return False
    if "module_regex" in match and not re.search(match["module_regex"], row.get("module_address") or ""):
        return False

    only_globs = as_list(match.get("only_attributes"))
    if only_globs:
        if not changes:
            return False
        if not all(any(fnmatch.fnmatch(key, glob) for glob in only_globs) for key in changes):
            return False

    attr_globs = as_list(match.get("attribute"))
    if attr_globs:
        matched_attrs = [key for key in changes if any(fnmatch.fnmatch(key, glob) for glob in attr_globs)]
        if not matched_attrs:
            return False
    else:
        matched_attrs = list(changes)

    if "after_equals" in match:
        expected = match["after_equals"]
        if not any(changes[key]["after"] == expected for key in matched_attrs):
            return False

    needles = as_list(match.get("after_contains_any"))
    if needles:
        haystacks = [value_as_text(changes[key]["after"]) for key in matched_attrs]
        if not any(str(needle) in text for needle in needles for text in haystacks):
            return False

    direction = match.get("direction")
    if direction:
        found = False
        for key in matched_attrs:
            old = numeric(changes[key]["before"])
            new = numeric(changes[key]["after"])
            if old is None or new is None:
                continue
            if direction == "decrease" and new < old:
                found = True
                break
            if direction == "increase" and new > old:
                found = True
                break
        if not found:
            return False

    return True


def evaluate_guardrails(row: dict[str, Any], guardrails: dict[str, Any]) -> dict[str, Any]:
    """Deterministic verdict: rules -> protected addresses -> per-action default."""
    for rule in guardrails["rules"]:
        if rule_matches(rule, row):
            return {
                "level": rule["verdict"],
                "reason": rule["reason"],
                "locked": True,
                "rule_id": rule["id"],
                "source": "rule",
            }

    for pattern in guardrails["protected_addresses"]:
        if re.search(pattern, row["resource"]):
            return {
                "level": "require",
                "reason": "protected resource; any change needs second approval",
                "locked": True,
                "rule_id": "protected",
                "source": "protected",
            }

    level = guardrails["defaults"].get(row["action"], "require")
    reasons = {
        "create": "additive create; no impact on existing resources",
        "update": "unclassified update; confirm blast radius",
        "delete": "resource deletion can break dependent workloads",
        "replace": "replace recreates the resource and may cause downtime",
        "no-op": "no operational change",
    }
    return {
        "level": level,
        "reason": reasons.get(row["action"], "unclassified change"),
        "locked": False,
        "rule_id": f"default:{row['action']}",
        "source": "default",
    }


def format_verdict(decision: dict[str, Any], guardrails: dict[str, Any], show_rule_ids: bool) -> str:
    label = guardrails["verdict_labels"][decision["level"]]
    text = f"{label} — {decision['reason']}"
    if show_rule_ids:
        text += f" [{decision['rule_id']}]"
    return truncate(text, LLM_VERDICT_MAX_LEN + 40)


def parse_verdict_label(text: str, guardrails: dict[str, Any]) -> tuple[str | None, str]:
    """Split an LLM verdict like 'APPROVAL REQUIRED — reason' into (level, reason)."""
    cleaned = " ".join((text or "").split())
    upper = cleaned.upper()
    for level in ("require", "allow"):  # check longer label first to avoid prefix clashes
        label = guardrails["verdict_labels"][level].upper()
        if upper.startswith(label):
            reason = cleaned[len(label) :].strip(" —–-:;")
            return level, reason
    return None, cleaned


def verdict_style(verdict: str) -> tuple[str, ...]:
    upper = verdict.upper()
    if upper.startswith(DEFAULT_VERDICT_LABELS["require"]):
        return (BOLD, RED)
    if upper.startswith(DEFAULT_VERDICT_LABELS["allow"]):
        return (GREEN,)
    return (YELLOW,)


def render_rules_for_prompt(guardrails: dict[str, Any]) -> str:
    lines: list[str] = []
    for rule in guardrails["rules"]:
        label = guardrails["verdict_labels"][rule["verdict"]]
        desc = rule["description"] or rule["reason"]
        lines.append(f"- {rule['id']} -> {label}: {desc}")
    for pattern in guardrails["protected_addresses"]:
        lines.append(f"- protected {pattern} -> {guardrails['verdict_labels']['require']}")
    for action, level in guardrails["defaults"].items():
        lines.append(f"- default {action} -> {guardrails['verdict_labels'][level]}")
    return "\n".join(lines)


def ollama_review_plan(
    rows: list[dict[str, Any]],
    *,
    guardrails: dict[str, Any],
    model: str,
    base_url: str,
    timeout: float,
) -> dict[str, dict[str, str]]:
    """One batched Ollama call: short summary + one-line verdict per change."""
    labels = guardrails["verdict_labels"]
    payload_rows = []
    for row in rows:
        decision = row["decision"]
        payload_rows.append(
            {
                "resource": row["resource"],
                "type": row.get("type"),
                "action": row["action"],
                "mechanical_summary": row["summary"],
                "changed_attributes": row.get("changes") or {},
                "precomputed_verdict": labels[decision["level"]],
                "precomputed_reason": decision["reason"],
                "rule_id": decision["rule_id"],
                "locked": decision["locked"],
            }
        )

    org_context = guardrails["org_context"] or "(none provided)"
    hints = "\n".join(f"- {hint}" for hint in guardrails["summary_hints"]) or "- (none)"
    system = (
        "You are a Terraform change reviewer for production infrastructure.\n"
        "Return ONLY valid JSON with this shape: "
        '{"reviews":[{"resource":"string","summary":"string","verdict":"string"}]}.\n\n'
        f"ORG CONTEXT:\n{org_context}\n\n"
        "POLICY RULES (already applied to every change; do not contradict them):\n"
        f"{render_rules_for_prompt(guardrails)}\n\n"
        "VERDICT RULES:\n"
        f"1) verdict MUST be one line, max 22 words, starting with '{labels['require']} —' "
        f"or '{labels['allow']} —'.\n"
        "2) Each change carries precomputed_verdict. If locked is true you MUST keep that label "
        "and may only sharpen the reason text.\n"
        f"3) If locked is false you may escalate '{labels['allow']}' to '{labels['require']}' "
        f"when you see a concrete risk. You may NEVER downgrade '{labels['require']}' "
        f"to '{labels['allow']}'.\n"
        "4) The reason must state the main operational/security risk concretely "
        "(e.g. SG ingress delete may stop attached resources receiving that traffic; "
        "IAM wildcard increases privilege; DB replace risks downtime).\n\n"
        "SUMMARY RULES:\n"
        "1) summary MUST be very short and precise (max 10 words). Prefer compact diffs like "
        "'engine 15.4→16.2', 'delete ingress 443 (0.0.0.0/0)', 'policy +ecs:* +iam:PassRole', "
        "'force_destroy false→true', 'min 6→2'. Never paste raw JSON.\n"
        f"2) Org hints:\n{hints}\n\n"
        "No markdown."
    )
    # /no_think reduces latency on Qwen3 thinking builds.
    user = "/no_think\nReview these Terraform changes:\n" + json.dumps(
        {"changes": payload_rows},
        indent=2,
    )

    raw = ollama_chat(
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        model=model,
        base_url=base_url,
        timeout=timeout,
    )
    parsed = parse_json_payload(raw)
    reviews = parsed.get("reviews") if isinstance(parsed, dict) else parsed
    if not isinstance(reviews, list):
        raise ValueError("LLM JSON missing reviews list")

    by_resource: dict[str, dict[str, str]] = {}
    for item in reviews:
        if not isinstance(item, dict):
            continue
        resource = item.get("resource")
        if not resource:
            continue
        entry: dict[str, str] = {}
        verdict = item.get("verdict")
        summary = item.get("summary")
        if isinstance(verdict, str) and verdict.strip():
            entry["verdict"] = truncate(" ".join(verdict.split()), LLM_VERDICT_MAX_LEN)
        if isinstance(summary, str) and summary.strip() and summary.strip().lower() != "null":
            entry["summary"] = truncate(" ".join(summary.split()), LLM_SUMMARY_MAX_LEN)
        by_resource[resource] = entry
    return by_resource


def apply_llm_review(row: dict[str, Any], review: dict[str, str], guardrails: dict[str, Any]) -> str | None:
    """Merge an LLM review into the row's decision. Returns a warning string if the LLM was overridden."""
    if review.get("summary"):
        row["summary"] = review["summary"]

    llm_level, llm_reason = parse_verdict_label(review.get("verdict", ""), guardrails)
    if llm_level is None:
        return None if not review.get("verdict") else f"unparseable verdict kept as policy: {review['verdict']!r}"

    decision = row["decision"]
    if llm_level == decision["level"]:
        if llm_reason:
            decision["reason"] = truncate(llm_reason, LLM_VERDICT_MAX_LEN)
        return None

    if decision["locked"]:
        return f"LLM tried {llm_level!r} but rule {decision['rule_id']} locks {decision['level']!r}"

    if llm_level == "require":  # escalation of an unlocked default is allowed
        decision["level"] = "require"
        decision["reason"] = truncate(llm_reason or "LLM flagged a concrete risk", LLM_VERDICT_MAX_LEN)
        decision["rule_id"] = f"llm-escalated:{decision['rule_id']}"
        decision["source"] = "llm"
        return None

    return f"LLM tried to downgrade {decision['level']!r} to {llm_level!r}; policy kept"


def enrich_rows_with_llm(
    rows: list[dict[str, Any]],
    *,
    guardrails: dict[str, Any],
    model: str,
    base_url: str,
    timeout: float,
    use_color: bool,
) -> None:
    if not rows:
        return

    print(
        colorize(
            f"Generating LLM verdicts for {len(rows)} change(s) via {model}…",
            DIM,
            use_color=use_color,
        ),
        file=sys.stderr,
    )

    try:
        reviews = ollama_review_plan(
            rows,
            guardrails=guardrails,
            model=model,
            base_url=base_url,
            timeout=timeout,
        )
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError, KeyError) as exc:
        print(
            colorize(f"  LLM review failed, using guardrail verdicts: {exc}", YELLOW, use_color=use_color),
            file=sys.stderr,
        )
        return

    for row in rows:
        review = reviews.get(row["resource"])
        if not review:
            continue
        warning = apply_llm_review(row, review, guardrails)
        if warning:
            print(
                colorize(f"  {row['resource']}: {warning}", YELLOW, use_color=use_color),
                file=sys.stderr,
            )


def load_plan(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def build_rows(plan: dict[str, Any], include_noop: bool, guardrails: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for resource in plan.get("resource_changes", []):
        change = resource.get("change", {})
        actions = change.get("actions", [])
        action = classify_action(actions)
        if action == "no-op" and not include_noop:
            continue

        before = change.get("before")
        after = change.get("after")
        replace_paths = change.get("replace_paths")
        summary = diff_summary(before, after, replace_paths)
        changes = changed_attributes(before, after)

        row = {
            "resource": resource.get("address", "<unknown>"),
            "type": resource.get("type", ""),
            "module_address": resource.get("module_address", ""),
            "action": action,
            "summary": summary,
            "changes": changes,
            "needs_llm": is_complex_summary(summary, changes),
        }
        row["decision"] = evaluate_guardrails(row, guardrails)
        rows.append(row)
    return rows


def finalize_rows(rows: list[dict[str, Any]], guardrails: dict[str, Any], show_rule_ids: bool) -> None:
    for row in rows:
        row["verdict"] = format_verdict(row["decision"], guardrails, show_rule_ids)
        row.pop("changes", None)
        row.pop("needs_llm", None)


def print_guardrails_explanation(rows: list[dict[str, Any]], guardrails: dict[str, Any]) -> None:
    print(f"Guardrails source: {guardrails['_source']}")
    print(f"Rules loaded: {len(guardrails['rules'])}, protected patterns: {len(guardrails['protected_addresses'])}")
    print()
    for row in rows:
        decision = row["decision"]
        label = guardrails["verdict_labels"][decision["level"]]
        lock = "locked" if decision["locked"] else "unlocked"
        print(f"{row['resource']}  [{row['action']}]")
        print(f"  matched : {decision['rule_id']} ({decision['source']}, {lock})")
        print(f"  verdict : {label} — {decision['reason']}")
        changed = ", ".join(row.get("changes") or {}) or "(none)"
        print(f"  changed : {changed}")
        print()


def section_order(action: str) -> int:
    order = {"delete": 0, "replace": 1, "create": 2, "update": 3, "no-op": 4}
    return order.get(action, 5)


def visible_width(text: str) -> int:
    """Strip ANSI codes for width calculation."""
    result: list[str] = []
    index = 0
    while index < len(text):
        if text[index] == "\033":
            end = text.find("m", index)
            index = len(text) if end == -1 else end + 1
            continue
        result.append(text[index])
        index += 1
    return len("".join(result))


def pad(text: str, width: int) -> str:
    return text + (" " * max(0, width - visible_width(text)))


def print_table(rows: list[dict[str, Any]], use_color: bool) -> None:
    headers = ("Resource", "Action", "Before → After", "Verdict")
    display_rows: list[tuple[str, str, str, str]] = []

    for row in rows:
        action = row["action"]
        styled_action = colorize(action.upper(), *action_style(action), use_color=use_color)
        resource = row["resource"]
        if action in {"delete", "replace"}:
            resource = colorize(resource, *action_style(action), use_color=use_color)
        verdict = row.get("verdict") or f"{DEFAULT_VERDICT_LABELS['require']} — unclassified change"
        styled_verdict = colorize(verdict, *verdict_style(verdict), use_color=use_color)
        display_rows.append((resource, styled_action, row["summary"], styled_verdict))

    col_widths = [
        max(len(headers[i]), max((visible_width(r[i]) for r in display_rows), default=0))
        for i in range(4)
    ]

    top = (
        f"┌{'─' * (col_widths[0] + 2)}┬{'─' * (col_widths[1] + 2)}"
        f"┬{'─' * (col_widths[2] + 2)}┬{'─' * (col_widths[3] + 2)}┐"
    )
    mid = (
        f"├{'─' * (col_widths[0] + 2)}┼{'─' * (col_widths[1] + 2)}"
        f"┼{'─' * (col_widths[2] + 2)}┼{'─' * (col_widths[3] + 2)}┤"
    )
    bot = (
        f"└{'─' * (col_widths[0] + 2)}┴{'─' * (col_widths[1] + 2)}"
        f"┴{'─' * (col_widths[2] + 2)}┴{'─' * (col_widths[3] + 2)}┘"
    )

    def line(c1: str, c2: str, c3: str, c4: str) -> str:
        return (
            f"│ {pad(c1, col_widths[0])} │ {pad(c2, col_widths[1])} │ "
            f"{pad(c3, col_widths[2])} │ {pad(c4, col_widths[3])} │"
        )

    print(top)
    print(colorize(line(*headers), BOLD, use_color=use_color) if use_color else line(*headers))
    print(mid)
    for cells in display_rows:
        print(line(*cells))
    print(bot)


def print_summary(rows: list[dict[str, Any]], noop_count: int, use_color: bool) -> None:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["action"]] = counts.get(row["action"], 0) + 1
    if noop_count and "no-op" not in counts:
        counts["no-op"] = noop_count

    parts: list[str] = []
    for action in ("delete", "replace", "create", "update", "no-op"):
        if action not in counts:
            continue
        label = f"{counts[action]} {action}"
        parts.append(colorize(label, *action_style(action), use_color=use_color))

    print(colorize("Plan summary", BOLD, use_color=use_color) + ": " + ", ".join(parts))
    print()


def print_delete_callout(rows: list[dict[str, Any]], use_color: bool) -> None:
    deletes = [row for row in rows if row["action"] == "delete"]
    replaces = [row for row in rows if row["action"] == "replace"]
    if not deletes and not replaces:
        return

    print(colorize("⚠ Destructive changes", BOLD, RED, use_color=use_color))
    for row in deletes:
        print(
            colorize("  DELETE ", BOLD, RED, use_color=use_color)
            + colorize(row["resource"], RED, use_color=use_color)
        )
    for row in replaces:
        print(
            colorize("  REPLACE ", BOLD, MAGENTA, use_color=use_color)
            + colorize(row["resource"], MAGENTA, use_color=use_color)
            + colorize(f"  ({row['summary']})", DIM, use_color=use_color)
        )
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Beautify Terraform JSON plan output as a terminal table.",
    )
    parser.add_argument(
        "plan_file",
        nargs="?",
        default="plan-output.json",
        help="Path to terraform show -json output (default: plan-output.json)",
    )
    parser.add_argument(
        "--include-noop",
        action="store_true",
        help="Include no-op resources in the table",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors",
    )
    llm_group = parser.add_mutually_exclusive_group()
    llm_group.add_argument(
        "--llm",
        dest="use_llm",
        action="store_true",
        help="Use local Ollama to refine summaries/reasons (default)",
    )
    llm_group.add_argument(
        "--nollm",
        "--no-llm",
        dest="use_llm",
        action="store_false",
        help="Skip Ollama; verdicts come only from guardrails.yaml",
    )
    parser.set_defaults(use_llm=True)
    parser.add_argument(
        "--ollama-url",
        default=DEFAULT_OLLAMA_URL,
        help=f"Ollama base URL (default: {DEFAULT_OLLAMA_URL})",
    )
    parser.add_argument(
        "--ollama-model",
        default=DEFAULT_OLLAMA_MODEL,
        help=f"Ollama model name (default: {DEFAULT_OLLAMA_MODEL})",
    )
    parser.add_argument(
        "--ollama-timeout",
        type=float,
        default=180.0,
        help="Timeout in seconds for the batched Ollama request (default: 180)",
    )
    parser.add_argument(
        "--guardrails",
        default=DEFAULT_GUARDRAILS_PATH,
        help=f"Path to org guardrails YAML/JSON (default: {DEFAULT_GUARDRAILS_PATH})",
    )
    parser.add_argument(
        "--strict-guardrails",
        action="store_true",
        help="Fail if the guardrails file is missing or invalid (recommended in CI)",
    )
    parser.add_argument(
        "--show-rule-ids",
        action="store_true",
        help="Append the matched guardrail rule id to each verdict",
    )
    parser.add_argument(
        "--explain-guardrails",
        action="store_true",
        help="Print which guardrail matched each change and exit (no LLM call)",
    )
    args = parser.parse_args()

    use_color = not args.no_color and sys.stdout.isatty()

    try:
        plan = load_plan(args.plan_file)
    except FileNotFoundError:
        print(f"Error: file not found: {args.plan_file}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in {args.plan_file}: {exc}", file=sys.stderr)
        return 1

    try:
        guardrails = load_guardrails(args.guardrails)
    except FileNotFoundError:
        if args.strict_guardrails:
            print(f"Error: guardrails file not found: {args.guardrails}", file=sys.stderr)
            return 1
        guardrails = default_guardrails()
        print(
            colorize(
                f"No guardrails file at {args.guardrails}; using built-in defaults",
                DIM,
                use_color=use_color,
            ),
            file=sys.stderr,
        )
    except GuardrailsError as exc:
        print(f"Error: invalid guardrails: {exc}", file=sys.stderr)
        return 1

    all_changes = plan.get("resource_changes", [])
    noop_count = sum(
        1
        for resource in all_changes
        if classify_action(resource.get("change", {}).get("actions", [])) == "no-op"
    )

    rows = build_rows(plan, include_noop=args.include_noop, guardrails=guardrails)
    rows.sort(key=lambda row: (section_order(row["action"]), row["resource"]))

    if args.explain_guardrails:
        print_guardrails_explanation(rows, guardrails)
        return 0

    if args.use_llm:
        enrich_rows_with_llm(
            rows,
            guardrails=guardrails,
            model=args.ollama_model,
            base_url=args.ollama_url,
            timeout=args.ollama_timeout,
            use_color=use_color,
        )

    finalize_rows(rows, guardrails, show_rule_ids=args.show_rule_ids)

    tf_version = plan.get("terraform_version", "?")
    format_version = plan.get("format_version", "?")
    mode = "llm" if args.use_llm else "nollm"
    print(
        colorize("Terraform Plan", BOLD, use_color=use_color)
        + f"  ·  terraform {tf_version}  ·  format {format_version}"
        + f"  ·  guardrails {guardrails['_source']}"
        + f"  ·  mode {mode}"
    )
    print()
    print_summary(rows, noop_count=noop_count, use_color=use_color)
    print_delete_callout(rows, use_color=use_color)

    if not rows:
        print("No resource changes to display.")
        return 0

    print_table(rows, use_color=use_color)

    requires = sum(1 for row in rows if row["decision"]["level"] == "require")
    print()
    if requires:
        print(colorize(f"{requires} change(s) need second approval.", BOLD, RED, use_color=use_color))
        return EXIT_APPROVAL_REQUIRED
    print(colorize("No changes need second approval.", GREEN, use_color=use_color))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
