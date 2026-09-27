from __future__ import annotations

import ast
import importlib.util
import json
import re
from pathlib import Path

import pytest

PUBLIC_SCHEMA_AND_RUNTIME_TOKENS = {
    "agent",
    "admin",
    "administration",
    "administrative",
    "after",
    "arguments",
    "assistant",
    "attack",
    "calendar.create",
    "command",
    "credential",
    "data",
    "db.query",
    "deployment",
    "devops",
    "drop",
    "email",
    "email.send",
    "events",
    "fs.write",
    "http.get",
    "http.post",
    "identity",
    "invalid",
    "marker",
    "metadata",
    "network",
    "post",
    "query",
    "revoked",
    "role",
    "search",
    "secret",
    "secrets",
    "send",
    "shell.exec",
    "split",
    "stale",
    "test",
    "traces",
    "transfer",
    "trust",
    "update",
    "values",
    "allow",
    "allowed",
    "appraisal",
    "artifact",
    "attestation",
    "benchmark",
    "benign",
    "chunk",
    "clean",
    "configuration",
    "content",
    "context",
    "control",
    "database.query",
    "delete",
    "degraded",
    "digest",
    "egress",
    "event",
    "file.read",
    "fresh",
    "grant",
    "local",
    "malicious",
    "measurement",
    "mutation",
    "nonce",
    "ordinary",
    "policy",
    "private",
    "quote",
    "read",
    "register",
    "request",
    "requires",
    "runtime",
    "secret:",
    "sensitive",
    "status",
    "synthetic",
    "tainted",
    "token",
    "tool",
    "trusted",
    "untrusted",
    "user",
    "write",
}


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _string_value(node.left)
        right = _string_value(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _docstring_node_ids(tree: ast.AST) -> set[int]:
    docstring_nodes: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(
                node,
                ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
            )
            and node.body
            and isinstance(node.body[0], ast.Expr)
        ):
            first = node.body[0].value
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                docstring_nodes.add(id(first))
    return docstring_nodes


def _string_literals(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    docstring_nodes = _docstring_node_ids(tree)
    values: list[str] = []
    for node in ast.walk(tree):
        if id(node) in docstring_nodes:
            continue
        value = _string_value(node)
        if value is not None:
            values.append(value)
    return values


def _regex_name(node: ast.Call, parents: dict[ast.AST, ast.AST]) -> str:
    parent = parents.get(node)
    if isinstance(parent, ast.Assign) and len(parent.targets) == 1:
        target = parent.targets[0]
        if isinstance(target, ast.Name):
            return target.id
    return ""


def _regex_alternation_count(pattern: str) -> int:
    in_class = False
    escaped = False
    count = 0
    for ch in pattern:
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "|" and not in_class:
            count += 1
    return count + 1 if count else 0


def _compiled_regexes(path: Path) -> list[tuple[str, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    patterns: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "compile"
            and isinstance(func.value, ast.Name)
            and func.value.id == "re"
            and node.args
        ):
            pattern = _string_value(node.args[0])
            if pattern is not None:
                patterns.append((_regex_name(node, parents), pattern))
    return patterns


@pytest.mark.skipif(
    importlib.util.find_spec("zero_trust_agent_benchmark") is None,
    reason="benchmark package is optional outside integration jobs",
)
def test_src_string_literals_do_not_copy_benchmark_generator_tokens() -> None:
    from zero_trust_agent_benchmark.generator import literal_tokens

    src = Path(__file__).resolve().parents[1] / "src"
    source_tokens: set[str] = set()
    for path in src.rglob("*.py"):
        for literal in _string_literals(path):
            source_tokens.update(re.findall(r"[a-z][a-z0-9_.:-]{3,}", literal.lower()))

    forbidden = literal_tokens() - PUBLIC_SCHEMA_AND_RUNTIME_TOKENS
    assert sorted(source_tokens & forbidden) == []


def test_src_has_no_large_content_keyword_regexes() -> None:
    src = Path(__file__).resolve().parents[1] / "src"
    offenders: list[str] = []
    for path in src.rglob("*.py"):
        for name, pattern in _compiled_regexes(path):
            if _regex_alternation_count(pattern) > 10:
                offenders.append(f"{path.relative_to(src)}:{name}")
    assert offenders == []


def test_source_does_not_match_benchmark_domain_shortcut() -> None:
    src = Path(__file__).resolve().parents[1] / "src"
    offenders = [
        path.relative_to(src)
        for path in src.rglob("*.py")
        if (".".join(("acme", "test"))) in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def _sibling_result(name: str) -> Path | None:
    candidate = (
        Path(__file__).resolve().parents[2] / "zero-trust-agent-benchmark" / "results" / name
    )
    return candidate if candidate.exists() else None


def test_benchmark_shortcut_audit_has_no_reported_shortcuts_when_available() -> None:
    path = _sibling_result("shortcut_audit.json")
    if path is None:
        pytest.skip("benchmark shortcut audit is not present")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["shortcut_count"] == 0


def test_benchmark_overfit_check_has_small_generalization_gap_when_available() -> None:
    path = _sibling_result("overfit_check.json")
    if path is None:
        pytest.skip("benchmark overfit check is not present")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert abs(float(data["test_accuracy"]) - float(data["dev_accuracy"])) <= 0.05
