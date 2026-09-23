#!/usr/bin/env python3
"""Beautify Terraform plan JSON into readable terminal tables."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

SECTION_ORDER = ("delete", "replace", "create", "update", "no-op")
SECTION_META = {
    "delete": {"title": "Deletes", "border": "red", "action_style": "bold red"},
    "replace": {"title": "Replaces (destroy + create)", "border": "yellow", "action_style": "bold yellow"},
    "create": {"title": "Creates", "border": "green", "action_style": "bold green"},
    "update": {"title": "Updates", "border": "cyan", "action_style": "bold cyan"},
    "no-op": {"title": "No-op", "border": "dim", "action_style": "dim"},
}


def load_plan(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        console.print(f"[red]File not found:[/red] {path}")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid JSON in {path}:[/red] {exc}")
        sys.exit(1)


def classify_action(actions: list[str]) -> str:
    action_set = set(actions)
    if action_set == {"no-op"}:
        return "no-op"
    if action_set == {"create"}:
        return "create"
    if action_set == {"delete"}:
        return "delete"
    if action_set == {"update"}:
        return "update"
    if action_set == {"create", "delete"}:
        return "replace"
    return "update"


def format_value(value: Any, max_len: int = 48) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        text = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    else:
        text = str(value)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def changed_attributes(before: dict[str, Any] | None, after: dict[str, Any] | None) -> list[tuple[str, Any, Any]]:
    before = before or {}
    after = after or {}
    keys = sorted(set(before) | set(after))
    return [(key, before.get(key), after.get(key)) for key in keys if before.get(key) != after.get(key)]


def summarize_change(change: dict[str, Any], max_items: int = 3) -> str:
    actions = change.get("actions") or []
    before = change.get("before")
    after = change.get("after")
    replace_paths = change.get("replace_paths") or []

    if set(actions) == {"create"}:
        if not isinstance(after, dict) or not after:
            return "new resource"
        preview = ", ".join(f"{k}={format_value(v, 24)}" for k, v in list(after.items())[:max_items])
        extra = len(after) - max_items
        suffix = f" (+{extra} more)" if extra > 0 else ""
        return f"new → {preview}{suffix}"

    if set(actions) == {"delete"}:
        if not isinstance(before, dict) or not before:
            return "resource removed"
        preview = ", ".join(f"{k}={format_value(v, 24)}" for k, v in list(before.items())[:max_items])
        extra = len(before) - max_items
        suffix = f" (+{extra} more)" if extra > 0 else ""
        return f"{preview} → removed{suffix}"

    diffs = changed_attributes(before if isinstance(before, dict) else None, after if isinstance(after, dict) else None)
    if not diffs:
        return "no attribute changes"

    replace_attrs = {".".join(str(part) for part in path) for path in replace_paths if path}
    diffs.sort(key=lambda item: (item[0] not in replace_attrs, item[0]))

    parts = [f"{key}: {format_value(old)} → {format_value(new)}" for key, old, new in diffs[:max_items]]
    extra = len(diffs) - max_items
    if extra > 0:
        parts.append(f"(+{extra} more)")
    return "; ".join(parts)


def build_rows(plan: dict[str, Any], *, include_noop: bool) -> dict[str, list[tuple[str, str, str]]]:
    grouped: dict[str, list[tuple[str, str, str]]] = {key: [] for key in SECTION_ORDER}
    for resource in plan.get("resource_changes") or []:
        change = resource.get("change") or {}
        actions = change.get("actions") or ["no-op"]
        kind = classify_action(actions)
        if kind == "no-op" and not include_noop:
            continue
        address = resource.get("address") or "(unknown)"
        action_label = "replace" if kind == "replace" else actions[0] if len(actions) == 1 else "+".join(actions)
        summary = summarize_change(change)
        grouped[kind].append((address, action_label, summary))
    return grouped


def make_table(rows: list[tuple[str, str, str]], action_style: str) -> Table:
    table = Table(show_header=True, header_style="bold", expand=True, pad_edge=False)
    table.add_column("Resource", style="bold white", no_wrap=False, ratio=2)
    table.add_column("Action", style=action_style, no_wrap=True, ratio=1)
    table.add_column("Before → After", style="white", no_wrap=False, ratio=3)
    for resource, action, summary in rows:
        table.add_row(resource, action, summary)
    return table


def render_plan(plan: dict[str, Any], *, include_noop: bool) -> None:
    tf_version = plan.get("terraform_version", "unknown")
    format_version = plan.get("format_version", "unknown")
    grouped = build_rows(plan, include_noop=include_noop)

    counts = {kind: len(rows) for kind, rows in grouped.items()}
    total = sum(counts.values())

    header = Text.assemble(
        ("Terraform Plan", "bold"),
        (f"  ·  terraform {tf_version}", "dim"),
        (f"  ·  format {format_version}", "dim"),
        (f"  ·  {total} change(s)", "bold"),
    )
    console.print(header)

    summary_bits = []
    for kind in SECTION_ORDER:
        if counts[kind] == 0:
            continue
        color = SECTION_META[kind]["border"]
        summary_bits.append(f"[{color}]{counts[kind]} {kind}[/{color}]")
    if summary_bits:
        console.print("  " + "  ·  ".join(summary_bits))
    console.print()

    rendered_any = False
    for kind in SECTION_ORDER:
        rows = grouped[kind]
        if not rows:
            continue
        rendered_any = True
        meta = SECTION_META[kind]
        panel = Panel(
            make_table(rows, meta["action_style"]),
            title=f"[bold]{meta['title']}[/bold] ({len(rows)})",
            border_style=meta["border"],
            padding=(0, 1),
        )
        console.print(panel)
        console.print()

    if not rendered_any:
        console.print("[dim]No resource changes to display.[/dim]")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Beautify Terraform plan JSON into readable terminal tables.",
    )
    parser.add_argument(
        "plan_file",
        type=Path,
        help="Path to terraform show -json plan output",
    )
    parser.add_argument(
        "--include-noop",
        action="store_true",
        help="Include no-op resources in the output",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    plan = load_plan(args.plan_file)
    if "resource_changes" not in plan:
        console.print("[red]Not a Terraform plan JSON:[/red] missing 'resource_changes'")
        sys.exit(1)
    render_plan(plan, include_noop=args.include_noop)


if __name__ == "__main__":
    main()
