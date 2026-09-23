# Guardrails for `beautify_plan.py` — Implementation Plan

## 1. Problem

Verdicts today come from two places, and neither knows anything about **our** org:

| Source | Where | Limitation |
|---|---|---|
| `heuristic_verdict()` | hard-coded in `beautify_plan.py` | Generic rules; editing requires a code change |
| Ollama (`--llm`) | system prompt in `ollama_review_plan()` | Generic "be conservative" guidance; no org policy |

Concrete failure: `aws_route53_record.api` (`ttl 300→60`, `records 10.0.12.4→10.0.14.9`) was judged
`NO APPROVAL — DNS TTL/record tweak; monitor briefly after apply`.
For us **any DNS change is APPROVAL REQUIRED** — the LLM cannot know that unless we tell it.

## 2. Goal

A single, human-editable **guardrails file** that:

1. Injects org-specific context into the LLM prompt (so verdicts reflect our risk appetite).
2. Provides **deterministic rules** that are enforced *regardless* of what the LLM says
   (the LLM must never be able to downgrade a hard rule).
3. Feeds the non-LLM fallback (`heuristic_verdict`) so `--llm` and non-`--llm` runs agree on policy.
4. Is reviewable in git like any other policy-as-code artifact.

## 3. File format

**Choice: YAML** — `guardrails.yaml` in `tf-reviewer/`.

- Comments allowed (unlike JSON) → reviewers can explain *why* a rule exists.
- Readable by non-Python folks (SRE/security).
- Requires `pyyaml`. Fallback: also accept `guardrails.json` with identical schema so the tool
  stays stdlib-only when PyYAML is absent.

### 3.1 Schema (v1)

```yaml
version: 1

# Free-text context prepended to the LLM system prompt. Keep it terse; it is sent on every run.
org_context: |
  We are a payments company (PCI-DSS scope). Production changes are reviewed by two people.
  Treat anything that can affect customer traffic, money movement, or auth as high risk.

# Verdict vocabulary the LLM must use. First one is the "strict" outcome.
verdict_labels:
  require: "APPROVAL REQUIRED"
  allow:   "NO APPROVAL"

# Rules are evaluated top-to-bottom; the FIRST match wins for deterministic verdicts.
# Each rule can match on any combination of: resource_type, address_regex, action,
# attribute (changed attribute path, glob), module_regex.
rules:
  - id: dns-any-change
    description: Any Route53 / DNS change needs second approval (traffic steering, cert validation, failover).
    match:
      resource_type: [aws_route53_record, aws_route53_zone, aws_route53_health_check]
      action: [create, update, delete, replace]
    verdict: require
    reason: "DNS change can redirect or blackhole customer traffic; requires second approval"
    severity: high

  - id: sg-ingress-delete
    description: Deleting an SG rule can silently cut traffic to attached resources.
    match:
      resource_type: [aws_security_group_rule, aws_security_group]
      action: [delete, replace]
    verdict: require
    reason: "Attached resources may stop receiving matching traffic"
    severity: high

  - id: iam-wildcard
    description: Wildcard actions / PassRole widen privilege.
    match:
      attribute: ["policy", "assume_role_policy", "inline_policy*"]
      after_contains_any: ['"*"', ':*"', "iam:PassRole"]
    verdict: require
    reason: "IAM policy widened with wildcard or PassRole"
    severity: critical

  - id: datastore-replace
    match:
      resource_type: [aws_db_instance, aws_rds_cluster, aws_elasticache_cluster, aws_dynamodb_table]
      action: [replace, delete]
    verdict: require
    reason: "Data-store replace/delete risks downtime and data loss"
    severity: critical

  - id: s3-force-destroy
    match:
      resource_type: [aws_s3_bucket]
      attribute: ["force_destroy"]
      after_equals: true
    verdict: require
    reason: "force_destroy=true allows bucket contents to be wiped on destroy"
    severity: high

  - id: capacity-reduction
    match:
      resource_type: [aws_autoscaling_group, aws_eks_node_group]
      attribute: ["min_size", "desired_capacity", "scaling_config*"]
      direction: decrease
    verdict: require
    reason: "Capacity reduction may under-provision under load"
    severity: medium

  - id: tags-only
    description: Pure tag changes are safe.
    match:
      only_attributes: ["tags.*"]
    verdict: allow
    reason: "Tag-only change; no runtime impact"
    severity: low

# Attributes to ignore entirely when deciding whether a change is "tags-only"/"cosmetic".
cosmetic_attributes:
  - "tags.*"
  - "tags_all.*"
  - "description"

# Resources/modules that are always high-blast-radius; forces `require` even if no rule matched.
protected_addresses:
  - "^aws_db_instance\\.payments_.*"
  - "^module\\.eks\\..*"

# Fallback when no rule / protected address matched. Binary only (`require`|`allow`).
# Unclassified updates still get a second pair of eyes.
defaults:
  create: allow
  update: require
  delete: require
  replace: require
  no-op: allow

# Extra hints the LLM may use for *summary* wording (not verdicts).
summary_hints:
  - "Say 'ingress'/'egress' explicitly for SG rules."
  - "For IAM, list added actions with '+' and removed with '-'."
```

### 3.2 Matching semantics

| Key | Meaning |
|---|---|
| `resource_type` | exact match on `type` from the plan |
| `address_regex` / `module_regex` | Python `re.search` on `address` / `module_address` |
| `action` | one of `create/update/delete/replace/no-op` (post-`classify_action`) |
| `attribute` | fnmatch glob against *changed* attribute paths from `changed_attributes()` |
| `only_attributes` | **all** changed attributes must match one of these globs |
| `after_equals` / `after_contains_any` | inspect the `after` value of matched attributes |
| `direction: decrease\|increase` | numeric compare of `before` vs `after` |

All keys inside `match` are AND-ed. Rules list is OR-ed with first-match-wins.

## 4. How verdicts are composed

```
plan row
   │
   ▼
[1] deterministic rules  ──match──►  verdict + reason  (locked; LLM cannot override)
   │ no match
   ▼
[2] protected_addresses  ──match──►  require
   │ no match
   ▼
[3] defaults[action] ─► allow / require
   │
   ▼
[4] LLM (--llm only)
      • receives org_context + a compact rendering of rules
      • receives the pre-computed verdict for each row
      • may ONLY:  (a) rewrite the reason text,
                   (b) escalate unlocked allow→require if it spots a risk
      • may NEVER downgrade require→allow
   │
   ▼
[5] post-validate LLM output against [1]–[3]; on violation, keep deterministic verdict and
    tag the row with "(LLM overridden)" in stderr log
```

Key principle: **the LLM adds explanation and catches what rules miss; it does not decide policy.**

## 5. Code changes (in `beautify_plan.py`)

Keep it in one file for now; split into a package only if it grows past ~1k lines.

### 5.1 New module-level pieces

- `DEFAULT_GUARDRAILS_PATH = "guardrails.yaml"`
- `load_guardrails(path) -> Guardrails` — tries YAML (if `yaml` importable) then JSON; validates
  `version == 1`; returns a typed `dataclass` (`Guardrails`, `Rule`, `Match`). Fails loudly on
  unknown keys (typos in policy files are dangerous).
- `evaluate_rules(row, guardrails) -> RuleResult | None` — implements §3.2.
- `deterministic_verdict(row, guardrails) -> tuple[label, reason, locked: bool]` — steps [1]–[3].

### 5.2 Modify existing

- `build_rows()` — carry `type` and `module_address` into each row (needed for matching).
- `heuristic_verdict()` — becomes a thin wrapper: call `deterministic_verdict()`; keep the current
  hard-coded rules only as a **built-in fallback** when no guardrails file is found.
- `ollama_review_plan()`:
  - system prompt gets `org_context` + a rendered rule list (id + description + verdict).
  - user payload includes `precomputed_verdict` and `locked` per row.
  - instruct: "If `locked` is true, keep the verdict label; only refine the reason."
- `enrich_rows_with_llm()` — add post-validation step [5]. Log overrides to stderr.
- `print_table()` — optionally append rule id in dim text, e.g. `APPROVAL REQUIRED — … [dns-any-change]`,
  behind `--show-rule-ids`.
- `main()` — new flags:
  - `--guardrails PATH` (default `guardrails.yaml`, silently skipped if absent unless
    `--strict-guardrails`)
  - `--strict-guardrails` (error if file missing/invalid — for CI)
  - `--show-rule-ids`
  - `--explain-guardrails` (dump which rule matched each row and exit; for debugging policy)

### 5.3 Exit code

- `0` — no `APPROVAL REQUIRED` rows
- `2` — at least one `APPROVAL REQUIRED` row (lets CI gate on it)
- `1` — tool error (bad JSON, bad guardrails, etc.)

## 6. Prompt contract (LLM)

```
SYSTEM:
  <existing formatting rules>
  ORG CONTEXT:
  <org_context>
  POLICY RULES (already applied, do not contradict):
  - dns-any-change: Any Route53/DNS change → APPROVAL REQUIRED
  - sg-ingress-delete: SG rule delete/replace → APPROVAL REQUIRED
  ...
  You may escalate a verdict to APPROVAL REQUIRED. You may NEVER downgrade one.
USER:
  {"changes":[{"resource":..., "action":..., "changed_attributes":...,
               "precomputed_verdict":"APPROVAL REQUIRED", "locked":true, "rule_id":"dns-any-change"}, ...]}
```

## 7. Testing

Keep tests outside the repo until a `tests/` dir is agreed; then:

- Unit: each match key in §3.2 with positive + negative cases.
- Golden: run against `plan-output.json` with the sample `guardrails.yaml`; assert
  `aws_route53_record.api` → `APPROVAL REQUIRED [dns-any-change]`.
- Override test: fake LLM response that downgrades a locked row → assert deterministic verdict kept.
- Schema test: unknown key in guardrails → non-zero exit with clear message.
- `--llm` off and on must produce identical **labels** for every row (only reason text may differ).

## 8. Rollout

1. Ship `guardrails.yaml` with the 7 rules above; run in non-`--llm` mode to validate labels.
2. Turn on `--llm`; compare reasons; tune `org_context`.
3. Add `--strict-guardrails` + exit code `2` to the CI job.
4. Ownership: `guardrails.yaml` reviewed by platform + security via CODEOWNERS.

# Open questions (resolved / deferred)
#
# - Verdict vocabulary is BINARY: `require` | `allow` only. No `review` / yellow
#   undecided state — every change gets a definite answer.
# - Per-environment guardrails (`guardrails.prod.yaml` vs staging): deferred to v2.
# - Pinning the Ollama model inside the guardrails file: deferred; use `--ollama-model`.
