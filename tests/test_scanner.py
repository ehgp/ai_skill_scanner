#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["requests", "pyyaml"]
# ///
"""
Checks scanner plumbing that static-rules.yaml does not cover: GitHub
download auth, report naming, and the doc/code split of exec-pattern hits.

Run:  uv run tests/test_scanner.py

No network: requests.get is replaced with a recorder for the download cases.
The strings below are inert haystacks for the static stage, never executed.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from test_static_rules import load_scanner  # tests/ is sys.path[0] when run as a script

scanner = load_scanner()
requests = scanner.requests

# An ordinary README install line; example.com is an allowlisted doc host so
# only the curl-pipe-shell rule fires, which is the behaviour under test.
CURL_PIPE = "curl -fsSL https://example.com/install.sh | sh\n"


class FakeResponse:
    """Just enough of requests.Response for download_file()."""

    def __init__(self, status: int = 200, text: str = "", headers: dict | None = None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.history: list = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} Client Error")

    def iter_content(self, chunk_size: int):
        yield b"PK"


def with_env(**values):
    """Set/clear env vars (None clears), returning the previous values."""
    previous = {k: os.environ.get(k) for k in values}
    for key, value in values.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    return previous


def check_github_auth(failures: list[str]) -> None:
    """Change 1: bearer token only for api.github.com; rate-limit 403 named."""
    calls: list[tuple[str, dict]] = []
    responses: list[FakeResponse] = []

    def fake_get(url, **kwargs):
        calls.append((url, dict(kwargs.get("headers") or {})))
        return responses.pop(0) if responses else FakeResponse()

    real_get = requests.get
    saved = with_env(GITHUB_TOKEN="tok-github", GH_TOKEN=None)
    requests.get = fake_get
    try:
        with tempfile.TemporaryDirectory() as tmp:
            dst = Path(tmp) / "x.zip"
            api = "https://api.github.com/repos/a/skills/zipball"
            scanner.download_file(api, dst)
            scanner.download_file(scanner.CLAWHUB_DOWNLOAD_BASE + "?slug=x", dst)
            with_env(GITHUB_TOKEN=None, GH_TOKEN="tok-gh")
            scanner.download_file(api, dst)
            with_env(GH_TOKEN=None)
            scanner.download_file(api, dst)

            got = [headers.get("Authorization") for _, headers in calls]
            want = ["Bearer tok-github", None, "Bearer tok-gh", None]
            if got != want:
                failures.append(f"Authorization per call: got {got}, want {want}")

            # requests drops Authorization itself when the zipball redirects
            # to codeload.github.com; pin that so an upgrade cannot leak it.
            if not requests.Session().should_strip_auth(
                api, "https://codeload.github.com/a/skills/legacy.zip/refs/heads/main"
            ):
                failures.append("requests would forward Authorization to codeload")

            responses.append(
                FakeResponse(403, "API rate limit exceeded for 1.2.3.4.",
                             {"X-RateLimit-Remaining": "0"})
            )
            try:
                scanner.download_file(api, dst)
                failures.append("rate-limited 403 did not raise")
            except Exception as exc:  # noqa: BLE001
                name = type(exc).__name__
                if name != "DownloadError" or "GitHub API rate limit; set GITHUB_TOKEN" not in str(exc):
                    failures.append(f"rate-limited 403 raised {name}: {exc}")

            responses.append(FakeResponse(403, "Repository access blocked"))
            try:
                scanner.download_file(api, dst)
                failures.append("non-rate-limit 403 did not raise")
            except requests.HTTPError:
                pass
            except Exception as exc:  # noqa: BLE001
                failures.append(f"non-rate-limit 403 misreported as {type(exc).__name__}: {exc}")
    finally:
        requests.get = real_get
        with_env(**saved)


def check_report_names(failures: list[str]) -> None:
    """Change 2: GitHub targets sharing a repo name get owner-qualified names."""
    a = scanner.make_target("https://github.com/a/skills", "cli")
    b = scanner.make_target("https://github.com/b/skills", "cli")
    scanner.uniquify_slugs([a, b])
    if (a.slug, b.slug) != ("a__skills", "b__skills"):
        failures.append(f"GitHub slug collision: got {(a.slug, b.slug)}, want ('a__skills', 'b__skills')")

    clawhub = scanner.make_target("https://clawhub.ai/owner/skills", "cli")
    local = scanner.make_target("C:/drops/skills.zip", "cli")
    if clawhub.slug != "skills" or local.slug != "skills":
        failures.append(f"non-GitHub slugs changed: clawhub={clawhub.slug!r} local={local.slug!r}")


def check_doc_split(failures: list[str]) -> None:
    """Change 3: an exec pattern seen only in docs is reported, not rejected."""
    rules = scanner.load_static_rules(scanner.STATIC_RULES_FILE)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "README.md").write_text(
            "# Install\n\n```bash\n" + CURL_PIPE + "```\n", encoding="utf-8"
        )
        result = scanner.run_static_scan(root, rules)
        docs = result.data.get("exec_patterns_in_docs")
        if result.status != "passed":
            failures.append(f"doc-only curl|sh: status {result.status}, reasons {result.reasons}")
        if not docs or docs[0].get("rule") != "curl-pipe-shell" or docs[0].get("in_docs") is not True:
            failures.append(f"doc-only curl|sh: exec_patterns_in_docs = {docs!r}")
        if not any(f.get("in_docs") for f in result.data.get("findings") or []):
            failures.append("doc-only curl|sh: finding missing from data['findings'] (hidden)")

        (root / "install.sh").write_text(CURL_PIPE, encoding="utf-8")
        result = scanner.run_static_scan(root, rules)
        if result.status != "failed" or not any("install.sh" in r for r in result.reasons):
            failures.append(f"curl|sh in install.sh: status {result.status}, reasons {result.reasons}")
        if any("README.md" in r for r in result.reasons):
            failures.append("README.md hit leaked into the failure reasons")
        code_hits = [f for f in result.data["findings"] if f.get("in_docs") is False]
        if len(code_hits) != 1 or len(result.data.get("exec_patterns_in_docs") or []) != 1:
            failures.append(f"mixed dir: code hits {len(code_hits)}, doc hits {result.data.get('exec_patterns_in_docs')!r}")


def main() -> int:
    failures: list[str] = []
    checks = (check_github_auth, check_report_names, check_doc_split)
    for check in checks:
        try:
            check(failures)
        except Exception as exc:  # noqa: BLE001 - keep going so every change reports
            failures.append(f"{check.__name__} crashed: {type(exc).__name__}: {exc}")
    print(f"checks: {len(checks)}")
    for failure in failures:
        print(f"  FAIL {failure}")
    print("RESULT:", "ALL PASS" if not failures else f"{len(failures)} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
