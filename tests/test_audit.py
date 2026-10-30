#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["requests", "pyyaml"]
# ///
"""
Checks the report["audit"] block (status / blast radius / needs) and the
fail-soft ClawHub registry lookup stage.

Run:  uv run tests/test_audit.py

No network: requests.get is replaced for the ClawHub cases. The strings
written to temp files are inert haystacks for the static stage, never run.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from test_static_rules import load_scanner  # tests/ is sys.path[0] when run as a script

scanner = load_scanner()
requests = scanner.requests
RULES = scanner.load_static_rules(scanner.STATIC_RULES_FILE)


def report(*, findings=(), error=None, kind="skill", **stage_overrides) -> dict:
    """A minimal finished report: every stage passed unless overridden."""
    stages = {name: {"status": "passed", "reasons": [], "data": {}} for name in scanner.ALL_STAGES}
    stages["static"]["data"] = {"findings": list(findings)}
    stages.update(stage_overrides)
    return {"kind": kind, "kind_details": {}, "error": error, "stages": stages}


def hit(rule: str, file: str, in_docs: bool) -> dict:
    return {"type": "high_confidence", "rule": rule, "file": file, "in_docs": in_docs, "match": "x"}


def url(file: str, host: str) -> dict:
    return {"type": "external_api_dependency", "rule": "external-url", "file": file,
            "match": f"https://{host}/", "hosts": [host]}


def check_audit_status(failures: list[str]) -> None:
    """Part 1: status classes, blast radius and needs from stage data."""
    cases = [
        ("clean", report(), "clean", "low"),
        ("README link", report(findings=[url("README.md", "example.org")]), "links-only", "low"),
        ("subprocess in code", report(findings=[hit("python-subprocess", "run.py", False)]), "runs-commands", "medium"),
        ("curl|sh only in docs", report(findings=[hit("curl-pipe-shell", "README.md", True)]), "runs-commands", "low"),
        ("curl|sh in code", report(findings=[hit("curl-pipe-shell", "install.sh", False)]), "review", "medium"),
        ("download failed", report(error="Download failed: 403"), "not-scanned", "low"),
        ("SCA install error", report(snyk_sca={"status": "failed", "reasons": ["x"], "data": {"exit_code": 2}}), "links-only", "low"),
        ("Cisco errored", report(cisco={"status": "failed", "reasons": ["timeout"], "data": {"runs": []}}), "review", "low"),
        ("core skipped, rejected", {**report(cisco={"status": "skipped", "reasons": ["x"], "data": {}}), "status": "rejected"}, "review", "low"),
    ]
    for name, rep, want_status, want_risk in cases:
        audit = scanner.build_audit(rep, RULES)
        if (audit["status"], audit["risk_level"]) != (want_status, want_risk):
            failures.append(f"{name}: got {audit['status']}/{audit['risk_level']}, want {want_status}/{want_risk} ({audit['drivers']})")

    # The real static stage feeds env names, hooks and declared requires.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "SKILL.md").write_text(
            '---\nname: t\nmetadata: {"clawdbot":{"requires":{"bins":["gh"],"env":["GH_HOST"]}}}\n---\n# t\n',
            encoding="utf-8",
        )
        (root / "scripts").mkdir()
        (root / "scripts" / "call.py").write_text(
            'import os, requests\nkey = os.environ["OPENAI_API_KEY"]\n'
            'requests.post("https://api.openai.com/v1/x", headers={"Authorization": key})\n',
            encoding="utf-8",
        )
        (root / "hooks").mkdir()
        (root / "hooks" / "hooks.json").write_text('{"hooks": {}}', encoding="utf-8")
        static = scanner.run_static_scan(root, RULES).to_dict()

        # Hostile frontmatter: a self-referencing alias must not crash or hang.
        (root / "evil").mkdir()
        (root / "evil" / "SKILL.md").write_text("---\nmetadata: &a [*a, *a]\n---\n", encoding="utf-8")
        if scanner.declared_requires((root / "evil" / "SKILL.md").read_text(encoding="utf-8")) != {}:
            failures.append("self-referencing frontmatter returned requires")
        audit = scanner.build_audit(report(static=static), RULES)
        br, needs = audit["blast_radius"], audit["needs"]
        if audit["status"] != "review" or "secret-near-net" not in audit["drivers"]:
            failures.append(f"key near requests: status {audit['status']}, drivers {audit['drivers']}")
        if br["network_hosts"] != ["api.openai.com"] or br["hooks"] != ["hooks/hooks.json"]:
            failures.append(f"blast radius hosts/hooks: {br['network_hosts']} / {br['hooks']}")
        if "OPENAI_API_KEY" not in br["credentials_env"] or audit["risk_level"] != "high":
            failures.append(f"credentials/risk: {br['credentials_env']} / {audit['risk_level']} ({audit['risk_score']})")
        if needs != {"binaries": ["gh"], "keys": ["GH_HOST", "OPENAI_API_KEY"], "accounts": ["openai"]}:
            failures.append(f"needs: {needs}")


class FakeResponse:
    def __init__(self, body, status=200, url=""):
        self._body, self.status_code, self.url = body, status, url

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} Client Error")

    def json(self):
        return self._body


def check_clawhub_stage(failures: list[str]) -> None:
    """Part 2: ClawHub lookup - owner-qualified call, registry block, fail-soft."""
    calls: list[tuple[str, dict]] = []
    replies: list = []

    def fake_get(u, **kwargs):
        calls.append((u, kwargs.get("params") or {}))
        reply = replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

    real_get = requests.get
    requests.get = fake_get
    try:
        target = scanner.make_target("https://clawhub.ai/steipete/skills/github", "cli")
        replies.append(FakeResponse({
            "version": {"version": "1.0.0"},
            "moderation": None,
            "security": {"status": "suspicious", "hasWarnings": True,
                         "scanners": {"skillspector": {"status": "suspicious", "normalizedStatus": "suspicious"}}},
        }, url="https://clawhub.ai/api/v1/skills/github/scan?owner=steipete"))
        stage = scanner.run_clawhub_audit(target)
        if calls != [("https://clawhub.ai/api/v1/skills/github/scan", {"owner": "steipete"})]:
            failures.append(f"ClawHub call: {calls}")
        audit = scanner.build_audit(report(clawhub_audit=stage.to_dict()), RULES)
        reg = audit["registry"] or {}
        if stage.status != "passed" or reg.get("status") != "suspicious" or reg.get("scanners") != {"skillspector": "suspicious"}:
            failures.append(f"registry block: stage {stage.status}, registry {reg}")
        if audit["status"] != "review" or reg.get("disagreement") is not True:
            failures.append(f"registry flag: status {audit['status']}, disagreement {reg.get('disagreement')}")

        replies.append(FakeResponse({"security": "oops"}))
        if scanner.run_clawhub_audit(target).status != "skipped":
            failures.append("malformed ClawHub body did not fail soft")

        replies.append(requests.ConnectionError("down"))
        stage = scanner.run_clawhub_audit(target)
        stages = {"clawhub_audit": stage}
        verdict, _ = scanner.compute_verdict("mcp_server", {}, stages)
        if stage.status != "skipped" or verdict != "approved":
            failures.append(f"API down: stage {stage.status} {stage.reasons}, verdict {verdict}")

        github = scanner.run_clawhub_audit(scanner.make_target("https://github.com/a/b", "cli"))
        if github.status != "skipped" or len(calls) != 3:
            failures.append(f"non-ClawHub target: {github.status}, calls {len(calls)}")
    finally:
        requests.get = real_get


def main() -> int:
    failures: list[str] = []
    checks = (check_audit_status, check_clawhub_stage)
    for check in checks:
        try:
            check(failures)
        except Exception as exc:  # noqa: BLE001 - keep going so every part reports
            failures.append(f"{check.__name__} crashed: {type(exc).__name__}: {exc}")
    print(f"checks: {len(checks)}")
    for failure in failures:
        print(f"  FAIL {failure}")
    print("RESULT:", "ALL PASS" if not failures else f"{len(failures)} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
