#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["requests", "pyyaml"]
# ///
"""
Security scanner for AI agent artifacts: skills, plugins, and MCP servers/configs.

Version 12 policy:
1.  Intake is dynamic. The scan queue is built from three merged sources:
    a. Everything dropped into candidates/ (ZIPs, bare directories, MCP JSON files).
    b. targets.yaml (URLs and local paths; replaces the old hardcoded SKILLS list).
    c. Command-line targets (when given, ONLY those are scanned).
2.  Targets are classified as: skill, skill_collection, plugin, mcp_config,
    mcp_server, or unknown. Unknown packaging is rejected with a contract hint.
3.  Scanner stages (each recorded as passed / failed / skipped with reasons):
    - gendigital       ClawHub URLs only (reputation lookup).
    - static           In-house red flags: exec payloads, env/secret access near
                       network/shell context, required third-party APIs, URLs,
                       and credential requests. Runs on every target.
    - cisco            cisco-ai-skill-scanner (offline static+YARA+bytecode+
                       pipeline+behavioral analyzers), per contained skill.
    - skillspector     NVIDIA SkillSpector (offline pattern/AST/taint/YARA
                       analysis, risk score 0-100), per contained skill.
    - snyk_agent_scan  snyk-agent-scan (prompt injection / toxic flow analysis
                       for skills and MCP configs). Requires SNYK_TOKEN; the
                       tool exits 1 SILENTLY without it, so it is pre-gated.
    - snyk_sca         Snyk CLI `snyk test --all-projects` (dependency CVEs).
    - snyk_code        Snyk CLI `snyk code test` (SAST, SARIF output).
4.  Exit-code contracts honored per scanner:
    - cisco: exit 0 even with findings -> gate on JSON findings.
    - skillspector: exit 1 just means risk>50 -> gate on JSON issues.
    - snyk test / code test: 0 clean, 1 findings, 2 error, 3 nothing scannable
      (3 is treated as a pass: skill dirs usually have no manifests).
    - snyk-agent-scan: gate on JSON issues; errors with is_failure reject.
5.  Findings at or above --fail-on severity (default: medium) reject a target.
    Scan errors in an enabled stage reject. Unconfigured cloud stages are
    skipped with a recorded reason -- EXCEPT for MCP artifacts, where
    snyk_agent_scan is a core verifier: no SNYK_TOKEN means rejection as
    unverifiable.
6.  Core offline stages (static + cisco + skillspector for skill content) must
    pass for approval. ZIP candidates are copied to approved/ or rejected/;
    directory targets are reported only.

ZIP packaging contract (for LLMs packaging candidates from a skill repository):
    Drop a ZIP into candidates/. The ZIP must contain ONE top-level directory
    named after the artifact, holding at its root:
      - SKILL.md                          -> a single skill (bundled files ok)
      - several subdirs each with SKILL.md-> a skill collection
      - .claude-plugin/plugin.json or plugin.json
                                          -> a plugin (commands/, agents/,
                                             skills/, hooks/, .mcp.json ok)
      - mcp.json / .mcp.json / mcp_config.json / claude_desktop_config.json,
        or any *.json with an "mcpServers" key
                                          -> an MCP server config
      - MCP server source (package.json depending on @modelcontextprotocol/sdk,
        or Python code depending on the mcp package)
                                          -> an MCP server
    SKILL.md at the ZIP root (no wrapper directory) is also accepted.
    A bare *.json MCP config file may be dropped into candidates/ directly.

targets.yaml (optional, next to this script; --config to override):
    settings:
      fail_on: medium          # critical|high|medium|low|info
      llm: true                # LLM analyzers (needs env keys; see .env.example)
      scanners:                # turn whole engines on/off
        gendigital: true
        static: true
        cisco: true
        skillspector: true
        snyk_agent_scan: true
        snyk_sca: true
        snyk_code: true
      cisco:                   # Cisco's optional analyzers
        behavioral: true
        llm: true
        osv: false
        virustotal: true       # activates only when its key is set
        aidefense: true        # activates only when its key is set
        trigger: false
        meta: false
        adjudicate: false
      skillspector:
        llm: true
    targets:
      - https://clawhub.ai/owner/some-skill
      - https://github.com/owner/skills-repo
      - ./candidates/some-skill.zip
      - C:/path/to/local/skill-dir
      - url: https://clawhub.ai/owner/other-skill
        slug: custom-slug

Environment:
- Python 3.10+, requests, pyyaml (only if targets.yaml is used), uv (uvx) on
  PATH (uv provisions each scanner engine's own interpreter automatically).
- Secrets live in .env next to this script (see .env.example for every
  variable); it is auto-loaded at startup and a variable already set in the
  real environment always wins.
- Optional: SNYK_TOKEN (snyk_agent_scan), authenticated `snyk` CLI on PATH
  (snyk_sca / snyk_code), CISCO_SKILL_SCANNER_LLM_API_KEY + --llm (Cisco LLM
  analyzer), SKILLSPECTOR_PROVIDER + provider key + --llm (SkillSpector LLM).
- Pins (env-overridable): CISCO_SKILL_SCANNER_VERSION, SKILLSPECTOR_GIT_REF,
  SNYK_AGENT_SCAN_VERSION.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import requests

GENDIGITAL_API = "https://ai.gendigital.com/api/scan/lookup"
CLAWHUB_DOWNLOAD_BASE = "https://wry-manatee-359.convex.site/api/v1/download"
# GET /api/v1/skills/{slug}/scan, verified in clawhub.ai/api/v1/openapi.json
# (2026-10-19). `owner` is not in the spec but is honoured, and is required
# when several publishers share a slug (bare slug -> 409 AMBIGUOUS_SKILL_SLUG).
CLAWHUB_SCAN_API = "https://clawhub.ai/api/v1/skills/{slug}/scan"

BASE_DIR = Path(__file__).resolve().parent
CANDIDATES_DIR = BASE_DIR / "candidates"
EXTRACTED_DIR = CANDIDATES_DIR / "_extracted"
DOWNLOADS_DIR = CANDIDATES_DIR / "_downloads"
APPROVED_DIR = BASE_DIR / "approved"
REJECTED_DIR = BASE_DIR / "rejected"
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_CONFIG_PATH = BASE_DIR / "targets.yaml"

TIMEOUT = 90
SCANNER_TIMEOUT = 600
USER_AGENT = "skill-scanner/12.0"
DELETE_EXTRACTED_AFTER_SCAN = False


def load_env_file(path: Path) -> None:
    """
    Load KEY=VALUE lines from a .env file into os.environ.

    A variable already set in the real environment always wins. Values may be
    single- or double-quoted; comment and blank lines are skipped.
    """
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and value:
            os.environ.setdefault(key, value)


# Loaded before the pins below so .env can override scanner versions too.
load_env_file(BASE_DIR / ".env")

def materialize_local_ca_bundle() -> None:
    """
    Make the local LLM endpoint's CA trusted by every scanner subprocess.

    requestOptionscaBundlePathdata holds the endpoint's CA certificate as a
    base64 data URI (or a PEM file path). Python LLM clients (httpx /
    requests / the OpenAI SDK) do not read that variable, so build a combined
    bundle - certifi's defaults PLUS the local CA, keeping public TLS intact -
    and export it via SSL_CERT_FILE / REQUESTS_CA_BUNDLE, which those clients
    honor and subprocesses inherit.
    """
    raw = os.environ.get("requestOptionscaBundlePathdata", "").strip()
    if not raw:
        return
    try:
        import base64

        import certifi

        if ";base64," in raw:
            pem = base64.b64decode(raw.split(";base64,", 1)[1]).decode("ascii")
        elif Path(raw).is_file():
            pem = Path(raw).read_text(encoding="utf-8")
        else:
            return
        bundle = Path(tempfile.gettempdir()) / "skill-scanner-ca-bundle.pem"
        bundle.write_text(
            Path(certifi.where()).read_text(encoding="utf-8") + "\n" + pem,
            encoding="utf-8",
        )
        os.environ.setdefault("SSL_CERT_FILE", str(bundle))
        os.environ.setdefault("REQUESTS_CA_BUNDLE", str(bundle))
    except Exception as exc:  # noqa: BLE001 - CA setup must never block scans
        print(f"Warning: could not materialize local CA bundle: {exc}")


materialize_local_ca_bundle()

# Our env namespace prefixes Cisco's vars with CISCO_ for clarity; the tool
# itself reads the native names on the right, so map them through for the
# subprocess (an explicitly set native name still wins).
for _ours, _native in (
    ("CISCO_SKILL_SCANNER_LLM_API_KEY", "SKILL_SCANNER_LLM_API_KEY"),
    ("CISCO_SKILL_SCANNER_LLM_MODEL", "SKILL_SCANNER_LLM_MODEL"),
    ("CISCO_SKILL_SCANNER_LLM_BASE_URL", "SKILL_SCANNER_LLM_BASE_URL"),
    ("CISCO_SKILL_SCANNER_LLM_PROVIDER", "SKILL_SCANNER_LLM_PROVIDER"),
    ("CISCO_VIRUSTOTAL_API_KEY", "VIRUSTOTAL_API_KEY"),
    ("CISCO_AI_DEFENSE_API_KEY", "AI_DEFENSE_API_KEY"),
):
    if os.environ.get(_ours):
        os.environ.setdefault(_native, os.environ[_ours])

# With no dedicated Cisco LLM config, fall back to the local OpenAI-compatible
# endpoint already configured for SkillSpector (OPENAI_BASE_URL + key).
if (
    not os.environ.get("SKILL_SCANNER_LLM_API_KEY")
    and os.environ.get("OPENAI_API_KEY")
    and os.environ.get("OPENAI_BASE_URL")
):
    os.environ.setdefault("SKILL_SCANNER_LLM_API_KEY", os.environ["OPENAI_API_KEY"])
    os.environ.setdefault("SKILL_SCANNER_LLM_BASE_URL", os.environ["OPENAI_BASE_URL"])
    os.environ.setdefault("SKILL_SCANNER_LLM_PROVIDER", "openai-compatible")
    if os.environ.get("SKILLSPECTOR_MODEL"):
        os.environ.setdefault(
            "SKILL_SCANNER_LLM_MODEL", os.environ["SKILLSPECTOR_MODEL"]
        )

PINS_FILE = BASE_DIR / "scanner-pins.json"

# Fallback pins - verified latest releases as of 2026-08-08. Normally
# superseded by scanner-pins.json, which update-scanners.py refreshes as the
# first step of every run (skip with --no-update).
FALLBACK_PINS = {
    "cisco_ai_skill_scanner": "2.0.13",
    "skillspector_git_ref": "v2.8.2",
    "snyk_agent_scan": "0.5.16",
}


def resolve_pins() -> None:
    """Set scanner version globals: env var > scanner-pins.json > fallback."""
    global CISCO_SKILL_SCANNER_VERSION, SKILLSPECTOR_GIT_REF, SNYK_AGENT_SCAN_VERSION
    pins = dict(FALLBACK_PINS)
    if PINS_FILE.is_file():
        try:
            data = json.loads(PINS_FILE.read_text(encoding="utf-8"))
            for key in FALLBACK_PINS:
                if data.get(key):
                    pins[key] = str(data[key])
        except json.JSONDecodeError:
            pass
    CISCO_SKILL_SCANNER_VERSION = os.environ.get(
        "CISCO_SKILL_SCANNER_VERSION", pins["cisco_ai_skill_scanner"]
    )
    SKILLSPECTOR_GIT_REF = os.environ.get(
        "SKILLSPECTOR_GIT_REF", pins["skillspector_git_ref"]
    )
    SNYK_AGENT_SCAN_VERSION = os.environ.get(
        "SNYK_AGENT_SCAN_VERSION", pins["snyk_agent_scan"]
    )


resolve_pins()

SKILLSPECTOR_GIT_URL = "git+https://github.com/NVIDIA/skillspector.git"

CLAWHUB_HOSTS = {
    "clawhub.ai",
    "clawhub.com",
    "www.clawhub.ai",
    "www.clawhub.com",
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_FAIL_ON = "medium"

# Every scanner stage, in report order. Each can be toggled from targets.yaml
# (settings.scanners) or the CLI (--skip / --only).
ALL_STAGES = [
    "gendigital",
    "static",
    "cisco",
    "skillspector",
    "snyk_agent_scan",
    "snyk_sca",
    "snyk_code",
    "clawhub_audit",
]
DEFAULT_SCANNERS = {name: True for name in ALL_STAGES}

# Cisco analyzer toggles -> the CLI flag each one adds. The offline core
# (static + YARA + bytecode + pipeline) always runs and has no flag.
CISCO_ANALYZER_FLAGS = {
    "behavioral": "--use-behavioral",
    "llm": "--use-llm",
    "osv": "--use-osv",
    "virustotal": "--use-virustotal",
    "aidefense": "--use-aidefense",
    "trigger": "--use-trigger",
    "meta": "--enable-meta",
    "adjudicate": "--adjudicate",
}
# virustotal/aidefense default on but still require their key to activate;
# llm additionally requires --llm / settings.llm.
DEFAULT_CISCO_ANALYZERS = {
    "behavioral": True,
    "llm": True,
    "osv": False,
    "virustotal": True,
    "aidefense": True,
    "trigger": False,
    "meta": False,
    "adjudicate": False,
}

# Bounds on untrusted archives and scan fan-out (fail-closed when exceeded).
MAX_ZIP_ENTRIES = 10_000
MAX_ZIP_UNCOMPRESSED = 1024 * 1024 * 1024  # 1 GiB
MAX_ZIP_RATIO = 200
MAX_SKILL_DIRS = 50

MCP_CONFIG_NAMES = {
    "mcp.json",
    ".mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
}

STATIC_RULES_FILE = BASE_DIR / "static-rules.yaml"

# Rule groups in static-rules.yaml that hold {id, enabled, pattern} entries.
RULE_GROUPS = (
    "high_confidence",
    "env_access",
    "secret_names",
    "suspicious_context",
    "external_api",
)
AUDIT_KEYS = (
    "command_rules",
    "outside_repo_rules",
    "rule_binaries",
    "risk_weights",
    "risk_levels",
)

# Env var names a code file reads through an env API (any name), plus shell
# `$NAME` / `${NAME}` references that look like credentials. Feeds
# audit.blast_radius.credentials_env and audit.needs.keys.
ENV_READ_RE = re.compile(
    r"""(?:os\.environ(?:\.get)?\s*[\[(]\s*|getenv\s*\(\s*|process\.env\.|"""
    r"""process\.env\[\s*|Deno\.env\.get\(\s*|\$env:|ENV\[\s*)['"]?([A-Z][A-Z0-9_]{2,})"""
)
# A real DNS name or IPv4 - drops template-literal noise like ${host}.
HOSTNAME_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]+$|^\d{1,3}(?:\.\d{1,3}){3}$")
SHELL_VAR_RE = re.compile(r"\$\{?([A-Z][A-Z0-9_]{2,})")
SECRET_NAME_RE = re.compile(
    r"(?:^|_)(?:API_?KEY|KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|AUTH|PAT)(?:_|$)"
)


@dataclass
class StaticRule:
    """One toggleable pattern from static-rules.yaml."""

    id: str
    description: str
    pattern: str
    regex: re.Pattern[str]


@dataclass
class StaticRules:
    """Everything the static stage matches against."""

    high_confidence: list[StaticRule] = field(default_factory=list)
    env_access: list[StaticRule] = field(default_factory=list)
    secret_names: list[StaticRule] = field(default_factory=list)
    suspicious_context: list[StaticRule] = field(default_factory=list)
    external_api: list[StaticRule] = field(default_factory=list)
    dependency_markers: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    text_extensions: set[str] = field(default_factory=set)
    markdown_extensions: set[str] = field(default_factory=set)
    doc_extensions: set[str] = field(default_factory=set)
    max_file_bytes: int = 2_000_000
    disabled_ids: list[str] = field(default_factory=list)
    audit: dict[str, Any] = field(default_factory=dict)

    @property
    def enabled_count(self) -> int:
        return sum(len(getattr(self, group)) for group in RULE_GROUPS)


def load_static_rules(path: Path = STATIC_RULES_FILE) -> StaticRules:
    """
    Load the static scanner's rules from YAML.

    Fails loudly rather than falling back to an empty rule set: a static stage
    with no rules would pass every artifact, which is the worst possible
    failure mode for a security gate.
    """
    if not path.is_file():
        raise RuntimeError(
            f"Static rule file not found: {path}\n"
            "It ships with this scanner and defines everything the static "
            "stage looks for. Restore it (git checkout static-rules.yaml) or "
            "disable the stage explicitly with --skip static."
        )

    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(
            "PyYAML is required to read static-rules.yaml. Install it "
            "(pip install pyyaml) or run via: uv run skill-scanner.py"
        ) from exc

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise RuntimeError(f"{path} must contain a mapping at top level.")

    rules = StaticRules()

    for group in RULE_GROUPS:
        entries = data.get(group) or []
        if not isinstance(entries, list):
            raise RuntimeError(f"{path}: '{group}' must be a list of rules.")
        for entry in entries:
            if not isinstance(entry, dict) or "id" not in entry:
                raise RuntimeError(f"{path}: every {group} rule needs an id.")
            rule_id = str(entry["id"])
            if not entry.get("enabled", True):
                rules.disabled_ids.append(rule_id)
                continue
            pattern = str(entry.get("pattern", "")).strip()
            if not pattern:
                raise RuntimeError(f"{path}: rule '{rule_id}' has no pattern.")
            try:
                regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as exc:
                raise RuntimeError(
                    f"{path}: rule '{rule_id}' has an invalid regex: {exc}"
                ) from None
            getattr(rules, group).append(
                StaticRule(
                    id=rule_id,
                    description=str(entry.get("description", "")),
                    pattern=pattern,
                    regex=regex,
                )
            )

    rules.dependency_markers = [
        str(m).lower() for m in (data.get("dependency_markers") or [])
    ]
    rules.allowed_domains = [
        str(d).lower().strip() for d in (data.get("allowed_domains") or [])
    ]

    scope = data.get("scan_scope") or {}
    rules.text_extensions = {
        str(e).lower() for e in (scope.get("text_extensions") or [])
    }
    rules.markdown_extensions = {
        str(e).lower() for e in (scope.get("markdown_extensions") or [])
    }
    rules.doc_extensions = {
        str(e).lower() for e in (scope.get("doc_extensions") or [])
    }
    rules.max_file_bytes = int(scope.get("max_file_bytes", 2_000_000))

    audit = data.get("audit")
    if not isinstance(audit, dict) or any(k not in audit for k in AUDIT_KEYS):
        raise RuntimeError(f"{path}: 'audit' must define {', '.join(AUDIT_KEYS)}.")
    rules.audit = audit

    if not rules.enabled_count:
        raise RuntimeError(
            f"{path}: every rule is disabled, so the static stage would pass "
            "everything. Enable at least one rule, or --skip static to make "
            "the omission explicit in the report."
        )
    return rules


GENDIGITAL_PASS_SEVERITIES = {"SAFE", "LOW"}
GENDIGITAL_FAIL_SEVERITIES = {"MEDIUM", "HIGH", "CRITICAL"}

IGNORABLE_AGENT_SCAN_ISSUE_CODES = {"W004"}
IGNORABLE_AGENT_SCAN_MESSAGE_PATTERNS = [
    r"mcp server is not in our registry",
]

# Specific phrases only: a bare word like "authentication" would downgrade
# genuine scan failures that merely mention it into skipped-auth (fail-open).
SNYK_AUTH_ERROR_MARKERS = [
    "use `snyk auth` to authenticate",
    "run `snyk auth`",
    "not authorised",
    "not authorized",
    "missing api token",
    "must be authenticated",
    "invalid auth token",
]


@dataclass
class Target:
    """One artifact to scan."""

    slug: str
    source: str  # "candidates" | "yaml" | "cli"
    url: str | None = None
    path: Path | None = None  # local zip, dir, or json file
    zip_name: str | None = None


@dataclass
class Settings:
    """Effective scan settings (yaml merged with CLI)."""

    fail_on: str = DEFAULT_FAIL_ON
    llm: bool = False
    osv: bool = False
    scanners: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_SCANNERS))
    cisco_analyzers: dict[str, bool] = field(
        default_factory=lambda: dict(DEFAULT_CISCO_ANALYZERS)
    )
    skillspector_llm: bool = True
    keep_extracted: bool = not DELETE_EXTRACTED_AFTER_SCAN
    config_path: Path = DEFAULT_CONFIG_PATH

    def stage_enabled(self, name: str) -> bool:
        """Return True if a scanner stage is turned on for this run."""
        return bool(self.scanners.get(name, True))

    def cisco_analyzer_enabled(self, name: str) -> bool:
        """
        Return True if a Cisco optional analyzer will actually run.

        Three gates compose: the analyzer's own toggle, the master `llm`
        switch for LLM-backed analyzers, and the presence of any credential
        the analyzer requires. Reporting the composed answer keeps the
        startup banner honest about what really ran.
        """
        if not self.cisco_analyzers.get(name, DEFAULT_CISCO_ANALYZERS.get(name)):
            return False
        if name in ("llm", "meta", "adjudicate"):
            return bool(self.llm and os.environ.get("SKILL_SCANNER_LLM_API_KEY"))
        if name == "virustotal":
            return bool(os.environ.get("CISCO_VIRUSTOTAL_API_KEY"))
        if name == "aidefense":
            return bool(os.environ.get("CISCO_AI_DEFENSE_API_KEY"))
        return True


@dataclass
class StageResult:
    """Outcome of a single scanner stage."""

    # "passed" | "failed" | "skipped" (could not run) | "disabled" (turned off
    # by the operator). The distinction matters for the verdict: a stage that
    # could not run is fail-closed, one deliberately disabled is a recorded
    # coverage gap.
    status: str
    reasons: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "reasons": self.reasons, "data": self.data}


def run_timed(fn: Any, *args: Any, **kwargs: Any) -> StageResult:
    """Run a stage function, stamping its wall-clock duration into the result."""
    started = time.monotonic()
    result: StageResult = fn(*args, **kwargs)
    result.data["duration_seconds"] = round(time.monotonic() - started, 1)
    return result


def stage_skipped(reason: str, **data: Any) -> StageResult:
    return StageResult("skipped", [reason], dict(data))


def stage_disabled(name: str) -> StageResult:
    return StageResult("disabled", [f"{name} is disabled in settings.scanners."])


def stage_failed(reasons: list[str], **data: Any) -> StageResult:
    return StageResult("failed", reasons, dict(data))


def stage_passed(**data: Any) -> StageResult:
    return StageResult("passed", [], dict(data))


def severity_rank(value: str) -> int:
    """Rank a severity string; unknown severities rank as critical (fail-safe)."""
    return SEVERITY_ORDER.get(str(value).lower().strip(), SEVERITY_ORDER["critical"])


def meets_threshold(severity: str, fail_on: str) -> bool:
    return severity_rank(severity) >= SEVERITY_ORDER[fail_on]


def ensure_dirs() -> None:
    """Create required working directories."""
    for path in (
        CANDIDATES_DIR,
        EXTRACTED_DIR,
        DOWNLOADS_DIR,
        APPROVED_DIR,
        REJECTED_DIR,
        REPORTS_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)


def is_clawhub(url: str) -> bool:
    """Return True if the URL is a supported ClawHub host."""
    return urlparse(url).netloc.lower() in CLAWHUB_HOSTS


def slugify(value: str) -> str:
    """Convert an arbitrary string to a filesystem-safe slug."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("_") or "target"


# Interpreter-selection variables that must not reach a spawned scanner.
# Each engine runs through `uvx`, which resolves its own interpreter; if the
# parent's environment advertises a different one (running under `uv run`,
# inside an activated venv, conda, or pyenv), the child can end up pairing one
# interpreter's binary with another's stdlib and dies with errors like
# "AssertionError: SRE module mismatch". User-facing UV_* settings (index URL,
# cache dir, proxy timeouts) are deliberately preserved.
SUBPROCESS_ENV_STRIP = {
    "VIRTUAL_ENV",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONEXECUTABLE",
    "PYVENV_LAUNCHER",
    "__PYVENV_LAUNCHER__",
    "CONDA_PREFIX",
    "CONDA_DEFAULT_ENV",
    "PYENV_VERSION",
    "UV_RUN_RECURSION_DEPTH",
    "UV_PROJECT_ENVIRONMENT",
}


def scanner_env() -> dict[str, str]:
    """Build a clean environment for scanner subprocesses."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in SUBPROCESS_ENV_STRIP and not key.startswith("UV_INTERNAL")
    }
    # Scanner output is decoded as UTF-8; ask the children to emit it.
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


def run_cmd(
    cmd: list[str],
    cwd: Path | None = None,
    timeout: int = SCANNER_TIMEOUT,
) -> tuple[int, str, str]:
    """
    Run a subprocess command.

    Returns
    -------
    tuple[int, str, str]
        Return code, stdout, stderr. Exit 127 = launcher missing,
        124 = timeout.
    """
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=scanner_env(),
        )
    except FileNotFoundError as exc:
        return 127, "", str(exc)

    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        # Popen.kill() terminates only the direct child (uvx / cmd.exe);
        # grandchildren (skillspector, node) inherit the pipe write handles
        # and would keep communicate() blocked forever. Kill the whole tree.
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                check=False,
            )
        else:
            proc.kill()
        try:
            proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            pass
        return 124, "", f"Timed out after {timeout}s: {' '.join(cmd[:4])}..."


def command_exists(cmd: list[str]) -> bool:
    """Return True if the command launcher exists."""
    rc, _, _ = run_cmd(cmd, timeout=60)
    return rc != 127


def detect_uv_launcher() -> list[str] | None:
    """Detect a working uvx-style launcher command prefix."""
    candidates = [
        ["uvx", "--help"],
        ["uv", "tool", "run", "--help"],
        ["python", "-m", "uv", "tool", "run", "--help"],
    ]
    for candidate in candidates:
        if command_exists(candidate):
            if candidate[0] == "uvx":
                return ["uvx"]
            if candidate[:3] == ["uv", "tool", "run"]:
                return ["uv", "tool", "run"]
            return ["python", "-m", "uv", "tool", "run"]
    return None


def detect_snyk_cli() -> str | None:
    """Return the resolved path of the snyk CLI, or None."""
    return shutil.which("snyk")


# ---------------------------------------------------------------------------
# Intake
# ---------------------------------------------------------------------------


def load_yaml_config(config_path: Path) -> tuple[list[Target], dict[str, Any]]:
    """
    Load targets and settings from targets.yaml.

    Returns
    -------
    tuple[list[Target], dict[str, Any]]
        Targets and the raw settings mapping.
    """
    if not config_path.exists():
        return [], {}

    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(
            f"{config_path} exists but PyYAML is not installed. "
            "Install it (pip install pyyaml) or run via: uv run skill-scanner.py"
        ) from exc

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{config_path} must contain a mapping at top level.")

    settings = raw.get("settings") or {}
    targets: list[Target] = []

    for entry in raw.get("targets") or []:
        if isinstance(entry, str):
            targets.append(make_target(entry, source="yaml"))
        elif isinstance(entry, dict):
            url = entry.get("url")
            path = entry.get("path")
            spec = url or path
            if not spec:
                raise ValueError(f"targets.yaml entry needs url or path: {entry!r}")
            target = make_target(str(spec), source="yaml")
            if entry.get("slug"):
                target.slug = slugify(str(entry["slug"]))
            if entry.get("zip_name"):
                target.zip_name = str(entry["zip_name"])
            targets.append(target)
        else:
            raise ValueError(f"Unsupported targets.yaml entry: {entry!r}")

    return targets, settings


def clawhub_owner_and_slug(url: str) -> tuple[str | None, str]:
    """
    Parse a ClawHub listing URL (/owner/slug) into its download API params.

    The API's bare-slug lookup returns 409 Conflict when several publishers
    share a skill name, so the owner must be sent when the URL carries one.
    """
    parts = [p for p in urlparse(url).path.split("/") if p]
    # Current listing URLs are /owner/skills/slug; older ones /owner/slug.
    if len(parts) >= 3 and parts[-2] == "skills":
        return parts[-3], parts[-1]
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return None, parts[-1] if parts else "skill"


def is_github(url: str) -> bool:
    """Return True if the URL is a GitHub repository."""
    return urlparse(url).netloc.lower() in {"github.com", "www.github.com"}


def make_target(spec: str, source: str) -> Target:
    """
    Build a Target from a URL or local path string.

    Relative CLI paths resolve against the invoking cwd; relative yaml paths
    resolve against the config's home (the script directory).
    """
    if re.match(r"^https?://", spec, flags=re.IGNORECASE):
        path = urlparse(spec).path.strip("/")
        slug = slugify(path.rsplit("/", 1)[-1] or "skill")
        if is_github(spec) and "/" in path:
            # github.com/a/skills and github.com/b/skills must not share a
            # report or an approved/rejected zip: GitHub slugs carry the owner.
            slug = slugify(path.split("/", 1)[0]) + "__" + slug
        return Target(slug=slug, source=source, url=spec)

    path = Path(spec)
    if not path.is_absolute():
        base = Path.cwd() if source == "cli" else BASE_DIR
        path = (base / path).resolve()
    return Target(slug=slugify(path.stem), source=source, path=path)


def discover_candidates() -> list[Target]:
    """Build targets from everything dropped into candidates/."""
    targets: list[Target] = []
    if not CANDIDATES_DIR.exists():
        return targets

    for entry in sorted(CANDIDATES_DIR.iterdir()):
        # "_"-prefixed dirs are scanner workspace (_extracted, _downloads).
        # Dot-prefixed entries are allowed only for JSON MCP configs
        # (.mcp.json is a documented drop) - other dotfiles are noise.
        if entry.name.startswith("_"):
            continue
        if entry.name.startswith(".") and entry.suffix.lower() != ".json":
            continue
        if entry.is_file() and entry.suffix.lower() == ".zip":
            targets.append(
                Target(
                    slug=slugify(entry.stem),
                    source="candidates",
                    path=entry,
                    zip_name=entry.name,
                )
            )
        elif entry.is_file() and entry.suffix.lower() == ".json":
            targets.append(
                Target(slug=slugify(entry.stem), source="candidates", path=entry)
            )
        elif entry.is_dir():
            targets.append(
                Target(slug=slugify(entry.name), source="candidates", path=entry)
            )

    return targets


def dedupe_targets(targets: list[Target]) -> list[Target]:
    """Drop duplicate targets (same URL or same resolved path)."""
    seen: set[str] = set()
    unique: list[Target] = []
    for target in targets:
        key = (target.url or "").lower() or str(target.path).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(target)
    return unique


def uniquify_slugs(targets: list[Target]) -> None:
    """Ensure report ids do not collide ("summary" is reserved for summary.json)."""
    used: set[str] = {"summary"}
    for target in targets:
        base = target.slug
        counter = 2
        while target.slug in used:
            target.slug = f"{base}-{counter}"
            counter += 1
        used.add(target.slug)


# ---------------------------------------------------------------------------
# Download / extraction / classification
# ---------------------------------------------------------------------------


class DownloadError(RuntimeError):
    """A download failed for a reason the report should state verbatim."""


_rate_limit_printed = False


def download_file(url: str, dst: Path) -> Path:
    """Download a file to disk."""
    global _rate_limit_printed
    headers = {"User-Agent": USER_AGENT}
    # Only the API host sees the token (never ClawHub, GenDigital, or
    # codeload: requests drops Authorization itself on the cross-host redirect
    # a zipball answers with - Session.rebuild_auth, pinned in tests/).
    if urlparse(url).netloc.lower() == "api.github.com":
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    with requests.get(url, stream=True, timeout=TIMEOUT, headers=headers) as response:
        for hop in (*response.history, response):
            remaining = hop.headers.get("X-RateLimit-Remaining")
            if remaining is not None and not _rate_limit_printed:
                _rate_limit_printed = True
                print(f"GitHub API rate limit: {remaining} request(s) remaining this hour")
                break
        if response.status_code in (403, 429) and (
            "rate limit" in response.text.lower()
            or response.headers.get("X-RateLimit-Remaining") == "0"
        ):
            raise DownloadError("GitHub API rate limit; set GITHUB_TOKEN")
        response.raise_for_status()
        with dst.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=1024 * 128):
                if chunk:
                    handle.write(chunk)
    return dst


def download_clawhub_zip(target: Target) -> Path:
    """
    Download a ClawHub skill ZIP into candidates/_downloads/.

    The API owner+slug come from the URL (target.slug may have been uniquified
    for reporting). Downloads live outside candidates/ discovery so they never
    clobber, or get re-scanned as, user drops.
    """
    zip_name = target.zip_name or f"{target.slug}.zip"
    zip_path = DOWNLOADS_DIR / zip_name
    owner, slug = clawhub_owner_and_slug(target.url or "")
    download_url = f"{CLAWHUB_DOWNLOAD_BASE}?slug={slug}"
    if owner:
        download_url += f"&owner={owner}"
    download_file(download_url, zip_path)
    return zip_path


def download_github_zip(target: Target) -> Path:
    """
    Download a GitHub repository's default-branch ZIP into
    candidates/_downloads/ via the zipball API (redirects to codeload).
    """
    parts = [p for p in urlparse(target.url or "").path.split("/") if p]
    if len(parts) < 2:
        raise ValueError(f"GitHub URL needs /owner/repo: {target.url}")
    owner, repo = parts[0], parts[1].removesuffix(".git")
    zip_name = target.zip_name or f"{target.slug}.zip"
    zip_path = DOWNLOADS_DIR / zip_name
    download_file(
        f"https://api.github.com/repos/{owner}/{repo}/zipball", zip_path
    )
    return zip_path


def clear_extracted_root(root: Path) -> None:
    """Remove and recreate an extraction root."""
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)


def check_zip_entries(zip_path: Path) -> None:
    """Reject ZIPs with traversal entry names, bomb-scale contents, or both."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise ValueError(f"ZIP has {len(infos)} entries (max {MAX_ZIP_ENTRIES}).")
        total_uncompressed = sum(info.file_size for info in infos)
        if total_uncompressed > MAX_ZIP_UNCOMPRESSED:
            raise ValueError(
                f"ZIP expands to {total_uncompressed} bytes "
                f"(max {MAX_ZIP_UNCOMPRESSED})."
            )
        for info in infos:
            name = info.filename
            normalized = name.replace("\\", "/")
            if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
                raise ValueError(f"ZIP entry has absolute path: {name}")
            if any(part == ".." for part in normalized.split("/")):
                raise ValueError(f"ZIP entry traverses parent dirs: {name}")
            if (
                info.compress_size > 0
                and info.file_size / info.compress_size > MAX_ZIP_RATIO
            ):
                raise ValueError(
                    f"ZIP entry {name} has compression ratio "
                    f">{MAX_ZIP_RATIO} (decompression bomb)."
                )


def extract_zip_into_candidates(zip_path: Path, extract_root: Path) -> Path:
    """
    Extract a ZIP into the configured extraction root.

    If the archive contains a single top-level directory, return that directory.
    Otherwise return the extraction root itself.
    """
    check_zip_entries(zip_path)
    clear_extracted_root(extract_root)

    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_root)

    children = [p for p in extract_root.iterdir() if p.name != "__MACOSX"]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return extract_root


def find_skill_dirs(root: Path) -> list[Path]:
    """Return directories under root (inclusive) that contain a SKILL.md."""
    dirs: set[Path] = set()
    for path in root.rglob("*"):
        if path.is_file() and path.name.lower() == "skill.md":
            dirs.add(path.parent)
    if (root / "SKILL.md").is_file():
        dirs.add(root)
    return sorted(dirs, key=lambda p: (len(p.parts), str(p).lower()))


def json_has_mcp_servers(path: Path) -> bool:
    """Return True if a JSON file has an mcpServers key."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return False
    return isinstance(data, dict) and "mcpServers" in data


def find_mcp_config(root: Path) -> Path | None:
    """Find an MCP config JSON in a directory."""
    for name in MCP_CONFIG_NAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    for candidate in sorted(root.glob("*.json")):
        if json_has_mcp_servers(candidate):
            return candidate
    return None


def looks_like_mcp_server_source(root: Path) -> bool:
    """Heuristic: directory contains MCP server source code."""
    package_json = root / "package.json"
    if package_json.is_file():
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
            deps: dict[str, Any] = {}
            for key in ("dependencies", "devDependencies", "peerDependencies"):
                block = data.get(key)
                if isinstance(block, dict):
                    deps.update(block)
            if any("modelcontextprotocol" in name for name in deps):
                return True
        except (json.JSONDecodeError, OSError):
            pass

    for manifest in ("pyproject.toml", "requirements.txt"):
        path = root / manifest
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            if re.search(r'(^|["\s])mcp([\[<>=~"\s]|$)', text, flags=re.MULTILINE):
                return True
    return False


def classify_artifact(root: Path) -> tuple[str, dict[str, Any]]:
    """
    Classify an extracted artifact.

    Returns
    -------
    tuple[str, dict[str, Any]]
        Kind (skill | skill_collection | plugin | mcp_config | mcp_server |
        unknown) and details (skill_dirs, mcp_config_path, ...).
    """
    if root.is_file():
        if root.suffix.lower() == ".json" and json_has_mcp_servers(root):
            return "mcp_config", {"mcp_config_path": str(root)}
        if root.name.lower() == "skill.md":
            return "skill", {"skill_dirs": [str(root.parent)]}
        return "unknown", {}

    plugin_manifest = None
    for candidate in (root / ".claude-plugin" / "plugin.json", root / "plugin.json"):
        if candidate.is_file():
            plugin_manifest = candidate
            break

    skill_dirs = find_skill_dirs(root)
    mcp_config = find_mcp_config(root)

    if plugin_manifest is not None:
        return "plugin", {
            "plugin_manifest": str(plugin_manifest),
            "skill_dirs": [str(p) for p in skill_dirs],
            "mcp_config_path": str(mcp_config) if mcp_config else None,
        }

    mcp_config_str = str(mcp_config) if mcp_config else None

    if (root / "SKILL.md").is_file():
        return "skill", {"skill_dirs": [str(root)], "mcp_config_path": mcp_config_str}

    if len(skill_dirs) == 1:
        return "skill", {
            "skill_dirs": [str(skill_dirs[0])],
            "mcp_config_path": mcp_config_str,
        }

    if len(skill_dirs) > 1:
        return "skill_collection", {
            "skill_dirs": [str(p) for p in skill_dirs],
            "mcp_config_path": mcp_config_str,
        }

    if mcp_config is not None:
        return "mcp_config", {"mcp_config_path": mcp_config_str}

    if looks_like_mcp_server_source(root):
        return "mcp_server", {"mcp_config_path": None}

    return "unknown", {}


# ---------------------------------------------------------------------------
# Stage: GenDigital (ClawHub reputation lookup)
# ---------------------------------------------------------------------------


def run_gendigital(target: Target) -> StageResult:
    """Run the GenDigital reputation lookup for ClawHub URLs."""
    if not target.url or not is_clawhub(target.url):
        return stage_skipped("Not a ClawHub URL target.")

    try:
        response = requests.post(
            GENDIGITAL_API,
            json={"skillUrl": target.url},
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        result = response.json()
    except requests.RequestException as exc:
        return stage_failed([f"GenDigital lookup error: {exc}"])

    severity = str(result.get("severity", "")).upper().strip()
    reasons = [str(r) for r in (result.get("reasons") or [])]

    if severity in GENDIGITAL_PASS_SEVERITIES:
        return stage_passed(severity=severity, raw=result)

    detail = [f"GenDigital severity={severity or 'UNKNOWN'}"]
    detail.extend(f"GenDigital reason: {r}" for r in reasons)
    return stage_failed(detail, severity=severity, raw=result)


def run_clawhub_audit(target: Target) -> StageResult:
    """
    Fetch ClawHub's own security audit for a ClawHub URL into
    data.registry (surfaced as audit.registry).

    Fail-soft and verdict-neutral: it never returns "failed", so fail_on
    semantics are unchanged; an unreachable API is a skipped stage.
    """
    if not target.url or not is_clawhub(target.url):
        return stage_skipped("Not a ClawHub URL target.")

    owner, slug = clawhub_owner_and_slug(target.url)
    try:
        response = requests.get(
            CLAWHUB_SCAN_API.format(slug=quote(slug, safe="")),
            params={"owner": owner} if owner else None,
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        body = response.json()
    except (requests.RequestException, ValueError) as exc:
        return stage_skipped(f"ClawHub audit unavailable: {exc}")
    if not isinstance(body, dict):
        return stage_skipped("ClawHub audit unavailable: unexpected response shape.")

    try:
        registry = clawhub_registry(body, response.url)
    except (AttributeError, TypeError) as exc:
        return stage_skipped(f"ClawHub audit unavailable: unexpected response shape ({exc}).")
    return stage_passed(registry=registry)


def clawhub_registry(body: dict[str, Any], endpoint: str) -> dict[str, Any]:
    """The registry block from a /skills/{slug}/scan response."""
    security = body.get("security") or {}
    moderation = body.get("moderation") or {}
    scanners = security.get("scanners") or {}
    return {
        "endpoint": endpoint,
        # clean | suspicious | malicious | pending | error | None
        "status": security.get("status"),
        "has_warnings": security.get("hasWarnings"),
        "checked_at": security.get("checkedAt"),
        "version": (body.get("version") or {}).get("version"),
        "malware_blocked": moderation.get("isMalwareBlocked"),
        "suspicious": moderation.get("isSuspicious"),
        "scanners": {
            name: s.get("normalizedStatus") or s.get("status")
            for name, s in scanners.items()
            if isinstance(s, dict)
        },
    }


# ---------------------------------------------------------------------------
# Stage: in-house static red flags (URLs, env vars, credentials, payloads)
# ---------------------------------------------------------------------------


def strip_markdown_fenced_code(text: str) -> str:
    """Remove fenced code blocks from Markdown to reduce doc false positives."""
    return re.sub(r"```.*?```", "", text, flags=re.DOTALL)


def read_text_for_scanning(file_path: Path, rules: StaticRules) -> tuple[str, str]:
    """
    Read content for static analysis.

    Returns
    -------
    tuple[str, str]
        (raw text, prose text). For Markdown, prose has fenced code stripped
        so documentation links don't trip the external-API policy; the raw
        text keeps fences because that's exactly where payloads hide.
    """
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    if file_path.suffix.lower() in rules.markdown_extensions:
        return text, strip_markdown_fenced_code(text)
    return text, text


def file_is_interesting_text(file_path: Path, rules: StaticRules) -> bool:
    """Return True if the file should be examined by the static scanner."""
    if not file_path.is_file():
        return False
    suffix = file_path.suffix.lower()
    if suffix and suffix not in rules.text_extensions:
        return False
    if file_path.stat().st_size > rules.max_file_bytes:
        return False
    return True


def extract_urls(text: str) -> list[str]:
    """Extract URLs from text."""
    return re.findall(r"https?://[^\s)\"'>]+", text, flags=re.IGNORECASE)


def url_host(url: str) -> str | None:
    """Lower-cased host of a URL without userinfo or port; None if unparseable."""
    try:
        return urlparse(url).netloc.lower().split("@")[-1].split(":")[0]
    except ValueError:
        return None


def domain_is_allowed(url: str, rules: StaticRules) -> bool:
    """
    Return True if a URL's host is allowlisted.

    Subdomains inherit their parent: "python.org" also allows
    "docs.python.org". The dot in the suffix test keeps lookalikes such as
    "evilgithub.com" from matching "github.com".
    """
    netloc = url_host(url)
    if netloc is None:
        return False
    return any(
        netloc == domain or netloc.endswith(f".{domain}")
        for domain in rules.allowed_domains
    )


def detect_external_api_usage(
    text: str, file_path: Path, rules: StaticRules
) -> list[dict[str, str]]:
    """
    Detect required third-party API / middleware / credential usage.

    Two signals:
    - Any URL outside the domain allowlist flags directly.
    - Declared API/gateway/credential patterns flag only alongside a
      dependency marker (base URLs, bearer auth, API keys, OAuth brokers),
      so marketplace metadata prose does not trip the policy.
    """
    findings: list[dict[str, str]] = []
    lowered = text.lower()

    matched = [rule for rule in rules.external_api if rule.regex.search(lowered)]

    urls = extract_urls(text)
    operational_urls = [url for url in urls if not domain_is_allowed(url, rules)]

    has_dependency_marker = any(
        marker in lowered for marker in rules.dependency_markers
    )

    if operational_urls or (matched and has_dependency_marker):
        if operational_urls:
            sample = operational_urls[0]
            rule_id = "external-url"
            description = "URL outside the allowed_domains list"
        else:
            sample = "external API / middleware dependency"
            rule_id = matched[0].id
            description = matched[0].description
        findings.append(
            {
                "type": "external_api_dependency",
                "rule": rule_id,
                "description": description,
                "file": str(file_path),
                "pattern": "external_api_dependency",
                "match": sample[:300],
                "hosts": sorted(
                    {h for h in map(url_host, operational_urls) if h and HOSTNAME_RE.match(h)}
                ),
            }
        )

    return findings


def declared_requires(skill_md: str) -> dict[str, set[str]]:
    """
    Binaries and env vars a SKILL.md frontmatter declares under any nested
    `requires` key - the ClawHub/OpenClaw convention
    (metadata: {"clawdbot": {"requires": {"bins": [...], "env": [...]}}}).
    """
    match = re.match(r"^---\s*\n(.*?)\n---", skill_md, flags=re.DOTALL)
    if not match:
        return {}
    import yaml  # load_static_rules already required it

    found: dict[str, set[str]] = {"bins": set(), "env": set()}
    seen: set[int] = set()  # YAML aliases share nodes: visit each once

    def walk(node: Any) -> None:
        if id(node) in seen:
            return
        seen.add(id(node))
        if isinstance(node, str) and node.lstrip().startswith("{"):
            try:
                node = json.loads(node)
            except json.JSONDecodeError:
                return
        if isinstance(node, dict):
            req = node.get("requires")
            if isinstance(req, dict):
                for key, bucket in (("bins", "bins"), ("anyBins", "bins"), ("env", "env")):
                    if isinstance(req.get(key), list):
                        found[bucket].update(str(v) for v in req[key])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    # Frontmatter is untrusted: a self-referencing or deeply nested document
    # must not take the static stage down with it.
    try:
        walk(yaml.safe_load(match.group(1)))
    except (yaml.YAMLError, RecursionError):
        return {}
    return {k: v for k, v in found.items() if v}


def run_static_scan(root: Path, rules: StaticRules) -> StageResult:
    """
    In-house conservative static red-flag scan.

    Flags high-confidence payload/execution patterns, env/secret access near
    network/shell/exfil context in non-Markdown files, and required
    third-party APIs / gateways / credential requests. Every pattern comes
    from static-rules.yaml, so operators tune coverage there.
    """
    findings: list[dict[str, Any]] = []
    env_names: set[str] = set()
    code_hosts: set[str] = set()
    hook_files: list[str] = []
    declared: dict[str, set[str]] = {}
    files = [root] if root.is_file() else list(root.rglob("*"))

    for file_path in files:
        if not file_is_interesting_text(file_path, rules):
            continue
        try:
            raw_text, prose_text = read_text_for_scanning(file_path, rules)
        except OSError:
            continue

        # Exec payloads are scanned in the RAW text: Markdown code fences are
        # where instruction-file payloads live, not a false-positive source.
        # A hit in a documentation file is still recorded, but as an "exec
        # pattern in docs" (a README install line) rather than a rejection.
        in_docs = file_path.suffix.lower() in rules.doc_extensions
        for rule in rules.high_confidence:
            for match in rule.regex.finditer(raw_text):
                findings.append(
                    {
                        "type": "high_confidence",
                        "rule": rule.id,
                        "description": rule.description,
                        "file": str(file_path),
                        "pattern": rule.pattern,
                        "match": match.group(0)[:300],
                        "in_docs": in_docs,
                    }
                )

        findings.extend(detect_external_api_usage(prose_text, file_path, rules))

        # Audit facts (report["audit"]): recorded, never rejecting.
        rel = file_path.name if file_path == root else file_path.relative_to(root).as_posix()
        if file_path.name.lower() == "hooks.json" or (
            file_path.name.lower().startswith("settings")
            and file_path.suffix.lower() == ".json"
            and '"hooks"' in raw_text
        ):
            hook_files.append(rel)
        if file_path.name.lower() == "skill.md":
            for key, values in declared_requires(raw_text).items():
                declared.setdefault(key, set()).update(values)
        if not in_docs:
            code_hosts.update(
                h for h in map(url_host, extract_urls(raw_text)) if h and HOSTNAME_RE.match(h)
            )
            env_names.update(ENV_READ_RE.findall(raw_text))
            env_names.update(
                n for n in SHELL_VAR_RE.findall(raw_text) if SECRET_NAME_RE.search(n)
            )

        if file_path.suffix.lower() in rules.markdown_extensions:
            continue

        env_hit = next(
            (r for r in rules.env_access if r.regex.search(raw_text)), None
        )
        secret_hit = next(
            (r for r in rules.secret_names if r.regex.search(raw_text)), None
        )
        context_hit = next(
            (r for r in rules.suspicious_context if r.regex.search(raw_text)), None
        )

        if (env_hit or secret_hit) and context_hit:
            trigger = env_hit or secret_hit
            findings.append(
                {
                    "type": "contextual_secret_handling",
                    "rule": f"{trigger.id}+{context_hit.id}",
                    "description": (
                        f"{trigger.description} near {context_hit.description}"
                    ),
                    "file": str(file_path),
                    "pattern": "env/secret + suspicious_context",
                    "match": (
                        "Detected env/secret access near networking, shelling, "
                        "or exfiltration context."
                    ),
                }
            )

    # Every finding stays in `findings`; doc-only exec hits are bucketed
    # separately and do not reject on their own.
    in_docs_findings = [f for f in findings if f.get("in_docs")]
    blocking = [f for f in findings if not f.get("in_docs")]
    data = {
        "findings": findings,
        "exec_patterns_in_docs": in_docs_findings,
        "env_names": sorted(env_names),
        "url_hosts_in_code": sorted(code_hosts),
        "hook_files": sorted(hook_files),
        "declared_requires": {k: sorted(v) for k, v in declared.items()},
    }
    if blocking:
        reasons = [
            f"Static scan {f['type']} [{f.get('rule', '?')}] in {f['file']}: "
            f"{f['match']}"
            for f in blocking
        ]
        return stage_failed(reasons, **data)
    return stage_passed(**data)


# ---------------------------------------------------------------------------
# Stage: Cisco cisco-ai-skill-scanner
# ---------------------------------------------------------------------------


def cisco_scan_one(
    skill_dir: Path, uv_launcher: list[str], settings: Settings
) -> dict[str, Any]:
    """Run cisco-ai-skill-scanner on one skill directory, returning parsed JSON."""
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "cisco.json"
        cmd = uv_launcher + [
            "--from",
            f"cisco-ai-skill-scanner=={CISCO_SKILL_SCANNER_VERSION}",
            "skill-scanner",
            "scan",
            str(skill_dir),
            "--format",
            "json",
            "--output",
            str(out_path),
        ]

        # cisco_analyzer_enabled() composes the toggle, the master llm switch,
        # and any required credential, so the command matches the banner.
        for analyzer, flag in CISCO_ANALYZER_FLAGS.items():
            if settings.cisco_analyzer_enabled(analyzer):
                cmd.append(flag)

        rc, out, err = run_cmd(cmd)
        parsed: dict[str, Any] | None = None
        if out_path.exists():
            try:
                parsed = json.loads(out_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                parsed = None

    return {
        "skill_dir": str(skill_dir),
        "exit_code": rc,
        "stdout_tail": out[-2000:],
        "stderr_tail": err[-2000:],
        "report": parsed,
    }


def run_cisco(
    kind: str,
    details: dict[str, Any],
    uv_launcher: list[str],
    settings: Settings,
) -> StageResult:
    """Run the Cisco skill scanner over every contained skill directory."""
    skill_dirs = [Path(p) for p in details.get("skill_dirs") or []]
    if not skill_dirs:
        return stage_skipped(f"No SKILL.md content in this {kind} artifact.")

    reasons: list[str] = []
    runs: list[dict[str, Any]] = []

    for skill_dir in skill_dirs:
        result = cisco_scan_one(skill_dir, uv_launcher, settings)
        runs.append(result)

        report = result["report"]
        if report is None:
            reasons.append(
                f"Cisco scan error for {skill_dir} "
                f"(exit={result['exit_code']}): {result['stderr_tail'][:300]}"
            )
            continue

        # Exit 0 is Cisco's only "completed" code as invoked (findings never
        # raise it without --fail-on-severity). A parseable report from an
        # errored/timed-out run may be partial - fail closed.
        if result["exit_code"] != 0:
            reasons.append(
                f"Cisco scan did not complete for {skill_dir} "
                f"(exit={result['exit_code']}): {result['stderr_tail'][:300]}"
            )
            continue

        for finding in report.get("findings") or []:
            severity = str(finding.get("severity", "")).lower()
            if meets_threshold(severity, settings.fail_on):
                reasons.append(
                    f"Cisco {finding.get('severity')} {finding.get('rule_id')} "
                    f"in {finding.get('file_path')}: {finding.get('title')}"
                )

    if reasons:
        return stage_failed(reasons, runs=runs)
    return stage_passed(runs=runs)


# ---------------------------------------------------------------------------
# Stage: NVIDIA SkillSpector
# ---------------------------------------------------------------------------


def skillspector_scan_one(
    skill_dir: Path, uv_launcher: list[str], settings: Settings
) -> dict[str, Any]:
    """Run SkillSpector on one skill directory, returning parsed JSON."""
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "spector.json"
        cmd = uv_launcher + [
            "--from",
            f"{SKILLSPECTOR_GIT_URL}@{SKILLSPECTOR_GIT_REF}",
            "skillspector",
            "scan",
            str(skill_dir),
            "--format",
            "json",
            "--output",
            str(out_path),
        ]
        use_llm = (
            settings.llm
            and settings.skillspector_llm
            and os.environ.get("SKILLSPECTOR_PROVIDER")
        )
        if not use_llm:
            cmd.append("--no-llm")

        rc, out, err = run_cmd(cmd)
        parsed: dict[str, Any] | None = None
        if out_path.exists():
            try:
                parsed = json.loads(out_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                parsed = None

    return {
        "skill_dir": str(skill_dir),
        "exit_code": rc,
        "stdout_tail": out[-2000:],
        "stderr_tail": err[-2000:],
        "report": parsed,
    }


def run_skillspector(
    kind: str,
    details: dict[str, Any],
    uv_launcher: list[str],
    settings: Settings,
) -> StageResult:
    """Run NVIDIA SkillSpector over every contained skill directory."""
    skill_dirs = [Path(p) for p in details.get("skill_dirs") or []]
    if not skill_dirs:
        return stage_skipped(f"No SKILL.md content in this {kind} artifact.")

    reasons: list[str] = []
    runs: list[dict[str, Any]] = []

    for skill_dir in skill_dirs:
        result = skillspector_scan_one(skill_dir, uv_launcher, settings)
        runs.append(result)
        report = result["report"]

        # Exit 0 = risk<=50, 1 = risk>50; both are completed scans. Exit 2 can
        # still produce a report (execution_successful=false).
        if report is None:
            reasons.append(
                f"SkillSpector scan error for {skill_dir} "
                f"(exit={result['exit_code']}): {result['stderr_tail'][:300]}"
            )
            continue
        if (
            result["exit_code"] not in (0, 1)
            or report.get("execution_successful") is False
        ):
            reasons.append(
                f"SkillSpector did not complete analysis for {skill_dir} "
                f"(exit={result['exit_code']}, execution_successful="
                f"{report.get('execution_successful')})"
            )
            continue

        assessment = report.get("risk_assessment") or {}
        recommendation = str(assessment.get("recommendation", "")).upper()
        if recommendation == "DO_NOT_INSTALL":
            reasons.append(
                f"SkillSpector recommendation DO_NOT_INSTALL for {skill_dir} "
                f"(risk score {assessment.get('score')})"
            )

        for issue in report.get("issues") or []:
            severity = str(issue.get("severity", "")).lower()
            if meets_threshold(severity, settings.fail_on):
                location = issue.get("location") or {}
                reasons.append(
                    f"SkillSpector {issue.get('severity')} {issue.get('id')} "
                    f"({issue.get('category')}) in {location.get('file')}"
                )

    if reasons:
        return stage_failed(reasons, runs=runs)
    return stage_passed(runs=runs)


# ---------------------------------------------------------------------------
# Stage: snyk-agent-scan (skills + MCP configs)
# ---------------------------------------------------------------------------


def agent_scan_issue_is_ignorable(issue: dict[str, Any]) -> bool:
    """Return True only for issues that are irrelevant MCP registry noise."""
    code = str(issue.get("code", "")).upper().strip()
    message = str(issue.get("message", "")).lower().strip()
    if code in IGNORABLE_AGENT_SCAN_ISSUE_CODES:
        return True
    return any(
        re.search(pattern, message)
        for pattern in IGNORABLE_AGENT_SCAN_MESSAGE_PATTERNS
    )


def label_entry_has_signal(entry: Any) -> bool:
    """Return True if a label object or nested list contains any truthy signal."""
    if isinstance(entry, dict):
        return any(bool(value) for value in entry.values())
    if isinstance(entry, list):
        return any(label_entry_has_signal(item) for item in entry)
    return bool(entry)


def collect_agent_scan_errors(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect top-level and server-level errors from one scan entry."""
    errors: list[dict[str, Any]] = []
    top_level_error = entry.get("error")
    if isinstance(top_level_error, dict):
        errors.append(top_level_error)
    for server in entry.get("servers") or []:
        if isinstance(server, dict) and isinstance(server.get("error"), dict):
            errors.append(server["error"])
    return errors


def run_snyk_agent_scan(
    kind: str,
    root: Path,
    details: dict[str, Any],
    uv_launcher: list[str],
) -> StageResult:
    """
    Run snyk-agent-scan on the artifact.

    Skill paths and MCP config paths are POSITIONAL arguments in 0.5.x
    (the 0.4.x `--skills <path>` flag no longer exists). Without SNYK_TOKEN
    the tool exits 1 with no output at all, so the stage is pre-gated.
    """
    if not os.environ.get("SNYK_TOKEN"):
        return stage_skipped(
            "SNYK_TOKEN is not set (snyk-agent-scan exits silently without it)."
        )

    mcp_config_path = details.get("mcp_config_path")

    if kind == "skill":
        skill_dirs = details.get("skill_dirs") or []
        scan_args = [str(Path(skill_dirs[0]) / "SKILL.md") if skill_dirs else str(root)]
    elif kind == "mcp_config":
        scan_args = [mcp_config_path or str(root)]
    elif kind == "mcp_server":
        if not mcp_config_path:
            return stage_skipped("MCP server source has no MCP config file to scan.")
        scan_args = [mcp_config_path]
    else:
        scan_args = [str(root)]

    # An MCP config embedded in a skill/plugin artifact must be scanned too,
    # not just the skill content.
    if mcp_config_path and mcp_config_path not in scan_args:
        scan_args.append(mcp_config_path)

    cmd = uv_launcher + [
        f"snyk-agent-scan=={SNYK_AGENT_SCAN_VERSION}",
        "scan",
        *scan_args,
        "--json",
        "--print-errors",
    ]
    rc, out, err = run_cmd(cmd)

    parsed: dict[str, Any] | None = None
    if out.strip():
        try:
            parsed = json.loads(out)
        except json.JSONDecodeError:
            parsed = None

    if parsed is None:
        return stage_failed(
            [
                f"snyk-agent-scan produced no parseable JSON "
                f"(exit={rc}): {err[-300:] or out[-300:] or 'no output'}"
            ],
            exit_code=rc,
            stdout_tail=out[-2000:],
            stderr_tail=err[-2000:],
        )

    reasons: list[str] = []
    active_issues: list[dict[str, Any]] = []
    ignored_issues: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    labels_found = 0

    for _, entry in parsed.items():
        if not isinstance(entry, dict):
            continue
        for issue in entry.get("issues") or []:
            if agent_scan_issue_is_ignorable(issue):
                ignored_issues.append(issue)
            else:
                active_issues.append(issue)
        labels_found += sum(
            1 for item in (entry.get("labels") or []) if label_entry_has_signal(item)
        )
        errors.extend(collect_agent_scan_errors(entry))

    for issue in active_issues:
        reasons.append(
            f"snyk-agent-scan issue {issue.get('code')}: {issue.get('message')}"
        )
    if labels_found:
        reasons.append(f"snyk-agent-scan: {labels_found} meaningful label group(s)")
    for error in errors:
        reasons.append(
            f"snyk-agent-scan {error.get('category')}: {error.get('message')}"
        )
    if rc != 0:
        reasons.append(f"snyk-agent-scan exit_code={rc}")

    data = {
        "exit_code": rc,
        "scan_args": scan_args,
        "active_issues": active_issues,
        "ignored_issues": ignored_issues,
        "errors": errors,
        "labels_found": labels_found,
        "raw_json": parsed,
    }
    if reasons:
        return stage_failed(reasons, **data)
    return stage_passed(**data)


# ---------------------------------------------------------------------------
# Stages: Snyk CLI (SCA + SAST)
# ---------------------------------------------------------------------------


def snyk_output_is_auth_error(out: str, err: str) -> bool:
    """Return True if a Snyk CLI failure is an authentication problem."""
    combined = f"{out}\n{err}".lower()
    return any(marker in combined for marker in SNYK_AUTH_ERROR_MARKERS)


def run_snyk_sca(root: Path, snyk_cli: str | None, settings: Settings) -> StageResult:
    """
    Run `snyk test --all-projects` (open-source dependency CVEs).

    Exit codes: 0 clean, 1 vulns found, 2 error, 3 no supported manifests
    (treated as a pass: most skills ship no dependency manifests).
    """
    if snyk_cli is None:
        return stage_skipped("snyk CLI is not installed / not on PATH.")
    if root.is_file():
        return stage_skipped("Single-file target has no dependency manifests.")

    rc, out, err = run_cmd([snyk_cli, "test", "--json", "--all-projects", str(root)])

    if rc == 3:
        return stage_passed(
            note="No supported dependency manifests found.", exit_code=rc
        )
    if rc == 2:
        if snyk_output_is_auth_error(out, err):
            return stage_skipped(
                "snyk CLI is not authenticated (run `snyk auth` or set SNYK_TOKEN)."
            )
        return stage_failed(
            [f"snyk test error (exit=2): {(err or out)[-300:]}"],
            exit_code=rc,
            stderr_tail=err[-2000:],
        )

    projects: list[dict[str, Any]] = []
    if out.strip():
        try:
            parsed = json.loads(out)
            projects = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            return stage_failed(
                [f"snyk test produced unparseable JSON (exit={rc})."],
                exit_code=rc,
                stdout_tail=out[-2000:],
            )

    reasons: list[str] = []
    vuln_summaries: list[dict[str, Any]] = []
    for project in projects:
        if not isinstance(project, dict):
            continue
        for vuln in project.get("vulnerabilities") or []:
            severity = str(vuln.get("severity", "")).lower()
            vuln_summaries.append(
                {
                    "id": vuln.get("id"),
                    "severity": severity,
                    "package": vuln.get("packageName"),
                    "version": vuln.get("version"),
                    "title": vuln.get("title"),
                }
            )
            if meets_threshold(severity, settings.fail_on):
                reasons.append(
                    f"Snyk SCA {severity} {vuln.get('id')} in "
                    f"{vuln.get('packageName')}@{vuln.get('version')}: "
                    f"{vuln.get('title')}"
                )

    if rc not in (0, 1):
        reasons.append(f"snyk test unexpected exit_code={rc}")

    data = {"exit_code": rc, "vulnerabilities": vuln_summaries}
    if reasons:
        return stage_failed(reasons, **data)
    return stage_passed(**data)


SARIF_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low"}


def run_snyk_code(root: Path, snyk_cli: str | None, settings: Settings) -> StageResult:
    """
    Run `snyk code test` (SAST). Output is SARIF; level maps
    error->high, warning->medium, note->low (Snyk Code has no critical tier).
    Exit 3 = no supported source files = pass.
    """
    if snyk_cli is None:
        return stage_skipped("snyk CLI is not installed / not on PATH.")
    if root.is_file():
        return stage_skipped("Single-file target: no source tree to analyze.")

    rc, out, err = run_cmd([snyk_cli, "code", "test", "--json", str(root)])

    if rc == 3:
        return stage_passed(
            note="No supported source files for Snyk Code.", exit_code=rc
        )
    if rc == 2:
        if snyk_output_is_auth_error(out, err):
            return stage_skipped(
                "snyk CLI is not authenticated for Snyk Code "
                "(run `snyk auth`; org must have Snyk Code enabled)."
            )
        return stage_failed(
            [f"snyk code test error (exit=2): {(err or out)[-300:]}"],
            exit_code=rc,
            stderr_tail=err[-2000:],
        )

    findings: list[dict[str, Any]] = []
    reasons: list[str] = []
    if out.strip():
        try:
            sarif = json.loads(out)
        except json.JSONDecodeError:
            return stage_failed(
                [f"snyk code test produced unparseable JSON (exit={rc})."],
                exit_code=rc,
                stdout_tail=out[-2000:],
            )
        for run in sarif.get("runs") or []:
            for result in run.get("results") or []:
                level = str(result.get("level", "warning")).lower()
                severity = SARIF_LEVEL_TO_SEVERITY.get(level, "high")
                locations = result.get("locations") or [{}]
                phys = locations[0].get("physicalLocation") or {}
                uri = (phys.get("artifactLocation") or {}).get("uri", "?")
                message = (result.get("message") or {}).get("text", "")
                findings.append(
                    {
                        "rule_id": result.get("ruleId"),
                        "level": level,
                        "severity": severity,
                        "file": uri,
                        "message": message,
                    }
                )
                if meets_threshold(severity, settings.fail_on):
                    reasons.append(
                        f"Snyk Code {severity} {result.get('ruleId')} in {uri}: "
                        f"{message[:200]}"
                    )

    if rc not in (0, 1):
        reasons.append(f"snyk code test unexpected exit_code={rc}")

    data = {"exit_code": rc, "findings": findings}
    if reasons:
        return stage_failed(reasons, **data)
    return stage_passed(**data)


# ---------------------------------------------------------------------------
# Verdict & reporting
# ---------------------------------------------------------------------------

STAGE_ORDER = ALL_STAGES


def compute_verdict(
    kind: str,
    details: dict[str, Any],
    stages: dict[str, StageResult],
) -> tuple[str, list[str]]:
    """
    Decide approved/rejected from stage results.

    Rules:
    - Any failed stage rejects.
    - Skill content (skill / skill_collection) requires the offline core
      (static + cisco + skillspector) to have run and passed.
    - Any artifact carrying an MCP config (mcp_config kind, or a config
      embedded in a skill/plugin) requires snyk_agent_scan to have run;
      skipped-unconfigured means unverifiable -> rejected.
    - mcp_server source requires Snyk Code to have run (static regex alone is
      too thin for source artifacts).
    - Unknown packaging rejects with a contract hint.

    A stage the operator turned off (status "disabled") is NOT treated as a
    verification failure - disabling is a deliberate choice - but it is
    reported as a coverage gap by coverage_notes().
    """
    reasons: list[str] = []

    for name in STAGE_ORDER:
        result = stages.get(name)
        if result and result.status == "failed":
            reasons.extend(result.reasons)

    if kind == "unknown":
        reasons.append(
            "Unrecognized packaging: expected SKILL.md, plugin.json, an MCP "
            "config JSON, or MCP server source. See the ZIP packaging "
            "contract in skill-scanner.py / README.md."
        )

    if kind in ("skill", "skill_collection"):
        for core in ("cisco", "skillspector"):
            result = stages.get(core)
            if result and result.status == "skipped":
                reasons.append(
                    f"Core scanner {core} did not run: {'; '.join(result.reasons)}"
                )

    has_mcp_config = kind == "mcp_config" or bool(details.get("mcp_config_path"))
    if has_mcp_config:
        result = stages.get("snyk_agent_scan")
        if result and result.status == "skipped":
            reasons.append(
                "Artifact carries an MCP config that cannot be verified: "
                f"snyk-agent-scan did not run ({'; '.join(result.reasons)})."
            )

    if kind == "mcp_server":
        result = stages.get("snyk_code")
        if result and result.status == "skipped":
            reasons.append(
                "MCP server source cannot be verified: Snyk Code did not run "
                f"({'; '.join(result.reasons)})."
            )

    return ("rejected" if reasons else "approved"), reasons


def coverage_notes(stages: dict[str, StageResult]) -> list[str]:
    """
    Describe reduced coverage: stages the operator disabled, and stages that
    could not run. Approving an artifact with coverage gaps is weaker
    evidence than a full pass, so surface them alongside the verdict.
    """
    notes: list[str] = []
    for name in STAGE_ORDER:
        result = stages.get(name)
        if not result:
            continue
        if result.status == "disabled":
            notes.append(f"{name}: disabled by configuration - not scanned.")
        elif result.status == "skipped":
            notes.append(f"{name}: {'; '.join(result.reasons)}")
    return notes


CREDENTIAL_WORDS = {
    "API", "APIKEY", "KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD",
    "CREDENTIAL", "CREDENTIALS", "AUTH", "PAT", "ACCESS", "CLIENT", "PRIVATE",
}


def account_of(env_name: str) -> str:
    """OPENAI_API_KEY -> "openai"; "" when the name has no service prefix."""
    # ponytail: naming heuristic; a host->service map is the upgrade if it misleads.
    prefix: list[str] = []
    for part in env_name.split("_"):
        if part in CREDENTIAL_WORDS:
            break
        prefix.append(part)
    return "-".join(prefix).lower()


def build_audit(report: dict[str, Any], rules: StaticRules) -> dict[str, Any]:
    """
    ClawHub-style summary of a finished report: what to do with it (status),
    what it can reach (blast_radius -> risk_level) and what it needs.

    Derived only from recorded stage data, so it also works on old reports.
    It never changes approved/rejected - that stays fail_on's job.

    status: not-scanned (scan errored or no stage ran) > review (risky code,
    Cisco high+, SkillSpector DO_NOT_INSTALL, Snyk agent issue, secret near
    network/shell code, SCA vulnerabilities, registry flag) > runs-commands
    (process spawning in code, exec lines only in docs, Snyk Code findings)
    > links-only (URLs outside the allowlist, Snyk install errors) > clean.
    """
    cfg = rules.audit
    stages = report.get("stages") or {}

    def data(name: str) -> dict[str, Any]:
        return (stages.get(name) or {}).get("data") or {}

    def failed(name: str) -> bool:
        return (stages.get(name) or {}).get("status") == "failed"

    static = data("static")
    findings = static.get("findings") or []

    def in_docs(f: dict[str, Any]) -> bool:
        # external_api findings carry no in_docs flag (they block in docs too).
        return f.get("in_docs", Path(f.get("file", "")).suffix.lower() in rules.doc_extensions)

    def hosts(f: dict[str, Any]) -> list[str]:
        if "hosts" in f:
            return f["hosts"]
        return [url_host(f.get("match", "")) or ""] if f.get("rule") == "external-url" else []

    exec_hits = [f for f in findings if f.get("type") == "high_confidence"]
    code_exec = sorted({f["rule"] for f in exec_hits if not in_docs(f)})
    doc_exec = sorted({f["rule"] for f in exec_hits if in_docs(f)})
    command_rules = set(cfg["command_rules"])
    risky = [r for r in code_exec if r not in command_rules]
    commands = [r for r in code_exec if r in command_rules]
    external = [f for f in findings if f.get("type") == "external_api_dependency"]
    # Every URL host in code, allowlisted or not; reports older than this
    # field only know the non-allowlisted ones from external-url findings.
    code_hosts = static.get("url_hosts_in_code")
    if code_hosts is None:
        code_hosts = sorted(
            {h for f in external if not in_docs(f) for h in hosts(f) if HOSTNAME_RE.match(h)}
        )
    doc_hosts = {h for f in external if in_docs(f) for h in hosts(f) if HOSTNAME_RE.match(h)}
    contextual = sorted(
        {f["rule"] for f in findings if f.get("type") == "contextual_secret_handling"}
    )

    review: list[str] = []
    if risky:
        review.append("danger-code:" + ",".join(risky))
    if contextual:
        review.append("secret-near-net")
    cisco_high = any(
        severity_rank(f.get("severity", "")) >= SEVERITY_ORDER["high"]
        for run in data("cisco").get("runs") or []
        for f in (run.get("report") or {}).get("findings") or []
    )
    if cisco_high:
        review.append("cisco:high+")
    if any(
        str(((run.get("report") or {}).get("risk_assessment") or {}).get("recommendation", "")).upper()
        == "DO_NOT_INSTALL"
        for run in data("skillspector").get("runs") or []
    ):
        review.append("skillspector:do-not-install")
    if failed("gendigital"):
        review.append(f"gendigital:{data('gendigital').get('severity') or 'error'}")
    if failed("snyk_agent_scan"):
        review.append("snyk-agent")
    if failed("snyk_sca") and data("snyk_sca").get("vulnerabilities"):
        review.append("snyk-sca:vulns")
    # Cisco/SkillSpector failing below high (or erroring) still failed fail_on.
    if failed("cisco") and not cisco_high:
        review.append("cisco:failed")
    if failed("skillspector") and "skillspector:do-not-install" not in review:
        review.append("skillspector:failed")

    commands_tier: list[str] = []
    if commands:
        commands_tier.append("cmd-code:" + ",".join(commands))
    if doc_exec:
        commands_tier.append("exec-doc:" + ",".join(doc_exec))
    if failed("snyk_code") and data("snyk_code").get("findings"):
        commands_tier.append("snyk-code")

    links: list[str] = []
    if external:
        links.append("external-urls")
    if failed("snyk_sca") and not data("snyk_sca").get("vulnerabilities"):
        links.append("snyk-sca-error")
    if failed("snyk_code") and not data("snyk_code").get("findings"):
        links.append("snyk-code-error")

    # A rejection nothing above explains (a core scanner or MCP check that
    # could not run) is a coverage gap: never let it read as clean.
    if (
        report.get("status") == "rejected"
        and not (review or commands_tier or links)
        and report.get("kind") != "unknown"
    ):
        review.append("rejected:coverage")

    ran = any(s.get("status") in ("passed", "failed") for s in stages.values())
    if report.get("error") or not ran:
        own_status = "not-scanned"
    elif review:
        own_status = "review"
    elif commands_tier:
        own_status = "runs-commands"
    elif links:
        own_status = "links-only"
    else:
        own_status = "clean"

    registry = data("clawhub_audit").get("registry")
    status = own_status
    if registry:
        flagged = bool(
            registry.get("status") in ("suspicious", "malicious")
            or registry.get("malware_blocked")
            or registry.get("suspicious")
        )
        registry = dict(registry)
        registry["disagreement"] = (
            flagged != (own_status == "review")
            if registry.get("status") in ("clean", "suspicious", "malicious")
            and own_status != "not-scanned"
            else None
        )
        if flagged and status != "not-scanned":
            status = "review"
            review.append(f"registry:{registry.get('status')}")

    details = report.get("kind_details") or {}
    mcp = [Path(p).name for p in [details.get("mcp_config_path")] if p]
    if not mcp and report.get("kind") in ("mcp_config", "mcp_server"):
        mcp = [report["kind"]]
    env_names = static.get("env_names") or []
    blast_radius = {
        "shell": code_exec,
        "shell_in_docs": doc_exec,
        "network_hosts": code_hosts,
        "doc_link_hosts": len(doc_hosts),
        "credentials_env": sorted(set(env_names) | {f"rule:{r}" for r in contextual}),
        "hooks": static.get("hook_files") or [],
        "mcp_servers": mcp,
        "files_outside_repo": sorted(set(code_exec) & set(cfg["outside_repo_rules"])),
    }
    score = sum(w for axis, w in cfg["risk_weights"].items() if blast_radius.get(axis))
    risk_level = "low"
    for level, threshold in sorted(cfg["risk_levels"].items(), key=lambda kv: kv[1]):
        if score >= threshold:
            risk_level = level

    declared = static.get("declared_requires") or {}
    binaries = set(declared.get("bins") or [])
    for rule in code_exec:
        binaries.update(cfg["rule_binaries"].get(rule) or [])
    keys = sorted(
        {n for n in env_names if SECRET_NAME_RE.search(n)} | set(declared.get("env") or [])
    )
    info = ["not-a-skill-package"] if report.get("kind") == "unknown" else []

    return {
        "status": status,
        "drivers": review + commands_tier + links + info,
        "risk_level": risk_level,
        "risk_score": score,
        "blast_radius": blast_radius,
        "needs": {
            "binaries": sorted(binaries),
            "keys": keys,
            "accounts": sorted({account_of(k) for k in keys if SECRET_NAME_RE.search(k)} - {""}),
        },
        "scanners": {name: s.get("status") for name, s in stages.items()},
        "registry": registry,
    }


def copy_to_bucket(src: Path, bucket_dir: Path, name: str) -> Path:
    """Copy a candidate file to an approval/rejection bucket."""
    dest = bucket_dir / name
    if dest.exists():
        dest.unlink()
    shutil.copy2(src, dest)
    return dest


def write_report(report_name: str, report: dict[str, Any]) -> Path:
    """Write a JSON report to reports/."""
    path = REPORTS_DIR / f"{report_name}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def scan_target(
    target: Target,
    uv_launcher: list[str],
    snyk_cli: str | None,
    settings: Settings,
    rules: StaticRules,
) -> dict[str, Any]:
    """Acquire, classify, and scan a single target through every stage."""
    report: dict[str, Any] = {
        "report_id": target.slug,
        "slug": target.slug,
        "source": target.source,
        "url": target.url,
        "input_path": str(target.path) if target.path else None,
        "kind": None,
        "kind_details": {},
        "duration_seconds": None,
        "coverage_notes": [],
        "status": "rejected",
        "failure_reasons": [],
        "audit": None,
        "stages": {},
        "approved_path": None,
        "rejected_path": None,
        "extracted_root": None,
        "error": None,
    }

    extract_root = EXTRACTED_DIR / target.slug
    zip_path: Path | None = None
    stages: dict[str, StageResult] = {}
    scan_started = time.monotonic()

    try:
        # -- Acquire ---------------------------------------------------------
        if target.url:
            if is_clawhub(target.url):
                zip_path = download_clawhub_zip(target)
            elif is_github(target.url):
                zip_path = download_github_zip(target)
            else:
                raise ValueError(
                    f"Only ClawHub and GitHub URLs are downloadable; got: "
                    f"{target.url}. Package other sources as ZIPs into "
                    "candidates/."
                )
        elif target.path and target.path.suffix.lower() == ".zip":
            zip_path = target.path

        if zip_path is not None:
            if not zip_path.exists():
                raise FileNotFoundError(f"Candidate ZIP does not exist: {zip_path}")
            if not zipfile.is_zipfile(zip_path):
                raise ValueError(f"Candidate is not a valid ZIP file: {zip_path}")
            root = extract_zip_into_candidates(zip_path, extract_root)
            report["extracted_root"] = str(root.resolve())
        elif target.path is not None:
            if not target.path.exists():
                raise FileNotFoundError(f"Target path does not exist: {target.path}")
            root = target.path
        else:
            raise ValueError(f"Target has neither URL nor path: {target}")

        # A bare SKILL.md file target scans as its parent directory so every
        # stage sees the same scope (bundled files included).
        if root.is_file() and root.name.lower() == "skill.md":
            root = root.parent

        # -- Classify --------------------------------------------------------
        kind, details = classify_artifact(root)
        report["kind"] = kind
        report["kind_details"] = details

        n_skill_dirs = len(details.get("skill_dirs") or [])
        if n_skill_dirs > MAX_SKILL_DIRS:
            raise ValueError(
                f"Artifact contains {n_skill_dirs} SKILL.md directories "
                f"(max {MAX_SKILL_DIRS}); rejecting to bound scanner fan-out."
            )

        # -- Stages ----------------------------------------------------------
        stage_calls = {
            "gendigital": (run_gendigital, (target,)),
            "static": (run_static_scan, (root, rules)),
            "cisco": (run_cisco, (kind, details, uv_launcher, settings)),
            "skillspector": (
                run_skillspector,
                (kind, details, uv_launcher, settings),
            ),
            "snyk_agent_scan": (
                run_snyk_agent_scan,
                (kind, root, details, uv_launcher),
            ),
            "snyk_sca": (run_snyk_sca, (root, snyk_cli, settings)),
            "snyk_code": (run_snyk_code, (root, snyk_cli, settings)),
            "clawhub_audit": (run_clawhub_audit, (target,)),
        }
        for name in ALL_STAGES:
            if not settings.stage_enabled(name):
                stages[name] = stage_disabled(name)
                continue
            fn, fn_args = stage_calls[name]
            stages[name] = run_timed(fn, *fn_args)

        status, reasons = compute_verdict(kind, details, stages)
        report["status"] = status
        report["failure_reasons"] = reasons
        report["coverage_notes"] = coverage_notes(stages)

    except Exception as exc:  # noqa: BLE001 - every target must yield a report
        report["error"] = str(exc)
        label = "Download failed" if isinstance(exc, DownloadError) else "Runtime error"
        report["failure_reasons"] = [f"{label}: {exc}"]
        report["status"] = "rejected"

    finally:
        report["stages"] = {name: result.to_dict() for name, result in stages.items()}
        report["duration_seconds"] = round(time.monotonic() - scan_started, 1)
        if not settings.keep_extracted and extract_root.exists():
            shutil.rmtree(extract_root, ignore_errors=True)

    report["audit"] = build_audit(report, rules)

    # -- Bucket the ZIP (directory targets are report-only) ------------------
    bucket_name = target.zip_name or (zip_path.name if zip_path else None)
    if zip_path is not None and zip_path.exists() and bucket_name:
        if report["status"] == "approved":
            bucket_dir, stale_dir, key = APPROVED_DIR, REJECTED_DIR, "approved_path"
        else:
            bucket_dir, stale_dir, key = REJECTED_DIR, APPROVED_DIR, "rejected_path"
        # A verdict change must not leave the previous run's copy in the
        # opposite bucket.
        stale = stale_dir / bucket_name
        if stale.exists():
            stale.unlink()
        report[key] = str(copy_to_bucket(zip_path, bucket_dir, bucket_name))

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan AI agent skills, plugins, and MCP servers/configs. With no "
            "targets, scans everything in candidates/ plus targets.yaml."
        )
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="ClawHub URLs, ZIP paths, directories, or MCP config JSON files.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Path to targets.yaml (default: alongside this script).",
    )
    parser.add_argument(
        "--fail-on",
        choices=sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get),
        default=None,
        help=(
            f"Reject on findings at or above this severity "
            f"(default {DEFAULT_FAIL_ON})."
        ),
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        default=None,
        help=(
            "Enable LLM analyzers where configured "
            "(CISCO_SKILL_SCANNER_LLM_API_KEY, SKILLSPECTOR_PROVIDER)."
        ),
    )
    parser.add_argument(
        "--osv",
        action="store_true",
        default=None,
        help="Enable Cisco OSV.dev dependency lookups (network, no key).",
    )
    parser.add_argument(
        "--skip",
        default=None,
        metavar="STAGES",
        help=(
            "Comma-separated scanner stages to disable for this run, "
            f"overriding settings.scanners. Stages: {', '.join(ALL_STAGES)}."
        ),
    )
    parser.add_argument(
        "--only",
        default=None,
        metavar="STAGES",
        help="Comma-separated scanner stages to run; all others are disabled.",
    )
    parser.add_argument(
        "--no-update",
        action="store_true",
        help=(
            "Skip the update-scanners.py pre-step (use the existing "
            "scanner-pins.json / fallback pins; for offline or "
            "deterministic runs)."
        ),
    )
    return parser.parse_args(argv)


def parse_stage_list(value: str | None) -> list[str]:
    """Parse a comma-separated --skip/--only list, rejecting unknown names."""
    if not value:
        return []
    names = [item.strip() for item in value.split(",") if item.strip()]
    unknown = [name for name in names if name not in ALL_STAGES]
    if unknown:
        raise ValueError(
            f"Unknown scanner stage(s): {', '.join(unknown)}. "
            f"Valid stages: {', '.join(ALL_STAGES)}."
        )
    return names


def build_settings(args: argparse.Namespace, yaml_settings: dict[str, Any]) -> Settings:
    """Merge yaml settings with CLI overrides (CLI wins)."""
    settings = Settings(config_path=args.config)

    fail_on = str(yaml_settings.get("fail_on", DEFAULT_FAIL_ON)).lower()
    if fail_on in SEVERITY_ORDER:
        settings.fail_on = fail_on
    settings.llm = bool(yaml_settings.get("llm", True))
    settings.osv = bool(yaml_settings.get("osv", False))

    # settings.scanners: per-stage on/off. Unlisted stages keep their default.
    yaml_scanners = yaml_settings.get("scanners") or {}
    if not isinstance(yaml_scanners, dict):
        raise ValueError("settings.scanners must be a mapping of stage -> bool.")
    unknown = [name for name in yaml_scanners if name not in ALL_STAGES]
    if unknown:
        raise ValueError(
            f"Unknown stage(s) in settings.scanners: {', '.join(unknown)}. "
            f"Valid stages: {', '.join(ALL_STAGES)}."
        )
    for name, enabled in yaml_scanners.items():
        settings.scanners[name] = bool(enabled)

    # settings.cisco: Cisco's optional analyzers. Legacy top-level llm/osv
    # still apply so older configs keep working.
    settings.cisco_analyzers["llm"] = settings.llm
    settings.cisco_analyzers["osv"] = settings.osv
    yaml_cisco = yaml_settings.get("cisco") or {}
    if not isinstance(yaml_cisco, dict):
        raise ValueError("settings.cisco must be a mapping of analyzer -> bool.")
    unknown = [name for name in yaml_cisco if name not in CISCO_ANALYZER_FLAGS]
    if unknown:
        raise ValueError(
            f"Unknown Cisco analyzer(s): {', '.join(unknown)}. "
            f"Valid analyzers: {', '.join(CISCO_ANALYZER_FLAGS)}."
        )
    for name, enabled in yaml_cisco.items():
        settings.cisco_analyzers[name] = bool(enabled)

    yaml_spector = yaml_settings.get("skillspector") or {}
    if not isinstance(yaml_spector, dict):
        raise ValueError("settings.skillspector must be a mapping of option -> bool.")
    settings.skillspector_llm = bool(yaml_spector.get("llm", True))

    if args.fail_on is not None:
        settings.fail_on = args.fail_on
    if args.llm is not None:
        settings.llm = args.llm
        settings.cisco_analyzers["llm"] = args.llm
    if args.osv is not None:
        settings.osv = args.osv
        settings.cisco_analyzers["osv"] = args.osv

    only = parse_stage_list(getattr(args, "only", None))
    if only:
        settings.scanners = {name: name in only for name in ALL_STAGES}
    for name in parse_stage_list(getattr(args, "skip", None)):
        settings.scanners[name] = False

    return settings


def collect_targets(args: argparse.Namespace) -> tuple[list[Target], dict[str, Any]]:
    """Build the scan queue: CLI targets only, or yaml + candidates/."""
    yaml_targets, yaml_settings = load_yaml_config(args.config)

    if args.targets:
        targets = [make_target(spec, source="cli") for spec in args.targets]
    else:
        targets = yaml_targets + discover_candidates()

    targets = dedupe_targets(targets)
    uniquify_slugs(targets)
    return targets, yaml_settings


def audit_line(audit: dict[str, Any]) -> str:
    """One console line: status, risk, drivers, needs, registry."""
    drivers = ", ".join(audit["drivers"]) or "none"
    needs = "; ".join(
        f"{k} {', '.join(v[:6])}{' ...' if len(v) > 6 else ''}"
        for k, v in audit["needs"].items()
        if v
    )
    line = (
        f"Audit: {audit['status']} | risk {audit['risk_level']} | "
        f"drivers {drivers[:160]}{'...' if len(drivers) > 160 else ''}"
    )
    if needs:
        line += f" | needs {needs}"
    if audit.get("registry"):
        reg = audit["registry"]
        line += f" | ClawHub {reg.get('status')}"
        if reg.get("disagreement"):
            line += " (disagrees)"
    return line


def summary_row(report: dict[str, Any], report_path: Path) -> dict[str, Any]:
    """Build a concise summary entry."""
    skipped = [
        f"{name}: {'; '.join(stage['reasons'])}"
        for name, stage in report["stages"].items()
        if stage["status"] == "skipped"
    ]
    disabled = [
        name
        for name, stage in report["stages"].items()
        if stage["status"] == "disabled"
    ]
    stage_durations = {
        name: stage["data"].get("duration_seconds")
        for name, stage in report["stages"].items()
        if stage["status"] not in ("disabled",)
    }
    return {
        "slug": report["slug"],
        "kind": report["kind"],
        "source": report["source"],
        "url": report["url"],
        "input_path": report["input_path"],
        "status": report["status"],
        "audit_status": (report.get("audit") or {}).get("status"),
        "risk_level": (report.get("audit") or {}).get("risk_level"),
        "duration_seconds": report.get("duration_seconds"),
        "stage_durations": stage_durations,
        "path": report["approved_path"] or report["rejected_path"],
        "report": str(report_path),
        "failure_reasons": report["failure_reasons"],
        "skipped_stages": skipped,
        "disabled_stages": disabled,
    }


def main() -> None:
    """Entry point."""
    # Scanner output tails can contain U+FFFD and arbitrary Unicode; never let
    # a cp1252 console abort the run mid-summary.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    ensure_dirs()
    args = parse_args(sys.argv[1:])

    # First step: refresh every upstream scanner to its latest release.
    # Failures are non-fatal - an offline run scans with the last known pins.
    if not args.no_update:
        update_script = BASE_DIR / "update-scanners.py"
        rc, out, err = run_cmd([sys.executable, str(update_script)], timeout=420)
        if out.strip():
            print(out.strip())
        if rc != 0:
            print(
                f"Pin update failed (exit={rc}); continuing with existing "
                f"pins. {err.strip()[:200]}"
            )
        resolve_pins()

    uv_launcher = detect_uv_launcher()
    if uv_launcher is None:
        raise RuntimeError(
            "No working uv launcher found. Install uv "
            "(https://docs.astral.sh/uv/), restart the terminal, then rerun."
        )

    snyk_cli = detect_snyk_cli()
    try:
        static_rules = load_static_rules(STATIC_RULES_FILE)
        targets, yaml_settings = collect_targets(args)
        settings = build_settings(args, yaml_settings)
    except (ValueError, RuntimeError) as exc:
        # Configuration mistakes are user errors, not crashes - a traceback
        # would bury the one line that says what to fix.
        print(f"Configuration error: {exc}")
        raise SystemExit(2) from None

    if not targets:
        print(
            "No targets found. Drop ZIPs/dirs/MCP configs into candidates/, "
            f"add links to {args.config}, or pass targets on the command line."
        )
        return

    print(f"Scanner: {USER_AGENT}")
    print(f"Launcher: {' '.join(uv_launcher)}")
    print(
        f"Cisco skill-scanner: cisco-ai-skill-scanner=={CISCO_SKILL_SCANNER_VERSION}"
    )
    print(f"SkillSpector: {SKILLSPECTOR_GIT_URL}@{SKILLSPECTOR_GIT_REF}")
    print(
        f"snyk-agent-scan: {SNYK_AGENT_SCAN_VERSION} "
        f"(SNYK_TOKEN {'set' if os.environ.get('SNYK_TOKEN') else 'NOT set'})"
    )
    print(f"snyk CLI: {snyk_cli or 'NOT FOUND'}")
    enabled_stages = [name for name in ALL_STAGES if settings.stage_enabled(name)]
    disabled_stages = [name for name in ALL_STAGES if not settings.stage_enabled(name)]
    cisco_on = [
        name
        for name in CISCO_ANALYZER_FLAGS
        if settings.cisco_analyzer_enabled(name)
    ]
    print(f"Fail threshold: {settings.fail_on}")
    print(f"Scanners ON:  {', '.join(enabled_stages) or '(none)'}")
    if disabled_stages:
        print(f"Scanners OFF: {', '.join(disabled_stages)}")
    print(
        f"Cisco analyzers: {', '.join(cisco_on) or '(core only)'} | "
        f"SkillSpector LLM: {settings.llm and settings.skillspector_llm}"
    )
    disabled_note = (
        f", {len(static_rules.disabled_ids)} disabled "
        f"({', '.join(static_rules.disabled_ids[:5])}"
        f"{', ...' if len(static_rules.disabled_ids) > 5 else ''})"
        if static_rules.disabled_ids
        else ""
    )
    print(
        f"Static rules: {static_rules.enabled_count} enabled{disabled_note} | "
        f"{len(static_rules.allowed_domains)} allowed domains"
    )
    print(f"Targets: {len(targets)}")

    summary: dict[str, Any] = {
        "scanner_version": USER_AGENT,
        "pins": {
            "cisco_ai_skill_scanner": CISCO_SKILL_SCANNER_VERSION,
            "skillspector": f"{SKILLSPECTOR_GIT_URL}@{SKILLSPECTOR_GIT_REF}",
            "snyk_agent_scan": SNYK_AGENT_SCAN_VERSION,
            "snyk_cli": snyk_cli,
        },
        "settings": {
            "fail_on": settings.fail_on,
            "llm": settings.llm,
            "osv": settings.osv,
            "scanners": settings.scanners,
            "cisco": settings.cisco_analyzers,
            "skillspector": {"llm": settings.skillspector_llm},
            "static_rules": {
                "file": str(STATIC_RULES_FILE),
                "enabled": static_rules.enabled_count,
                "disabled": static_rules.disabled_ids,
                "allowed_domains": len(static_rules.allowed_domains),
            },
        },
        "approved": [],
        "rejected": [],
        "errors": [],
    }

    run_started = time.monotonic()
    for target in targets:
        print(f"\n=== Scanning {target.slug} ({target.url or target.path})")
        report = scan_target(target, uv_launcher, snyk_cli, settings, static_rules)
        report_path = write_report(target.slug, report)

        print(f"Kind: {report['kind']}")
        print(f"Status: {report['status']}")
        print(audit_line(report["audit"]))
        print(f"Duration: {report.get('duration_seconds')}s")
        print(f"Report: {report_path}")

        row = summary_row(report, report_path)
        if row["disabled_stages"]:
            print(f"  (disabled) {', '.join(row['disabled_stages'])}")
        static_data = report["stages"].get("static", {}).get("data", {})
        if static_data.get("exec_patterns_in_docs"):
            print(
                f"  (docs) {len(static_data['exec_patterns_in_docs'])} exec pattern(s) "
                "in documentation files - recorded, not rejecting"
            )
        if report["status"] == "approved":
            summary["approved"].append(row)
            for note in row["skipped_stages"]:
                print(f"  (skipped) {note}")
        else:
            summary["rejected"].append(row)
            for reason in report["failure_reasons"][:5]:
                print(f"  - {reason}")
            if len(report["failure_reasons"]) > 5:
                print(f"  ... {len(report['failure_reasons']) - 5} more reason(s)")
            if report["error"]:
                summary["errors"].append(
                    {"slug": target.slug, "error": report["error"]}
                )

    summary["total_duration_seconds"] = round(time.monotonic() - run_started, 1)

    summary_path = REPORTS_DIR / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(
        f"\nApproved: {len(summary['approved'])} | "
        f"Rejected: {len(summary['rejected'])} | "
        f"Total: {summary['total_duration_seconds']}s"
    )
    print(f"Summary written to: {summary_path}")


if __name__ == "__main__":
    main()
