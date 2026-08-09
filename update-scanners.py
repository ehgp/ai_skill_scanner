#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["requests"]
# ///
"""
Resolve the latest releases of every upstream scanner and record them in
scanner-pins.json, which skill-scanner.py reads at startup.

Runs automatically as skill-scanner.py's first step (skip with --no-update);
also runnable standalone:  uv run update-scanners.py

Sources (all primary):
- cisco-ai-skill-scanner : PyPI JSON API
- snyk-agent-scan        : PyPI JSON API
- SkillSpector           : GitHub releases API (latest tag)
- snyk CLI               : npm registry; updated in place via `npm install -g`
                           when outdated and npm is available.

Pin precedence in skill-scanner.py: environment variable > scanner-pins.json
> hardcoded fallback. Lookup failures keep the previous pin and are reported,
never fatal - an offline run still scans with the last known versions.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent
PINS_FILE = BASE_DIR / "scanner-pins.json"
TIMEOUT = 30
HEADERS = {"User-Agent": "skill-scanner-updater/1.0"}


def fetch_json(url: str) -> dict | None:
    try:
        response = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as exc:
        print(f"  lookup failed: {url} ({exc})")
        return None


def latest_pypi_version(package: str) -> str | None:
    data = fetch_json(f"https://pypi.org/pypi/{package}/json")
    return data["info"]["version"] if data else None


def latest_github_release_tag(repo: str) -> str | None:
    data = fetch_json(f"https://api.github.com/repos/{repo}/releases/latest")
    return data.get("tag_name") if data else None


def local_snyk_cli_version(snyk_cli: str) -> str | None:
    try:
        proc = subprocess.run(
            [snyk_cli, "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return proc.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def update_snyk_cli() -> dict:
    """Report the snyk CLI's local vs latest version; upgrade via npm if stale."""
    status: dict = {"local": None, "latest": None, "action": "skipped"}

    snyk_cli = shutil.which("snyk")
    npm = shutil.which("npm")
    data = fetch_json("https://registry.npmjs.org/snyk/latest")
    status["latest"] = data.get("version") if data else None
    status["local"] = local_snyk_cli_version(snyk_cli) if snyk_cli else None

    if snyk_cli is None:
        status["action"] = "not installed (npm install -g snyk)"
        return status
    if status["latest"] is None:
        status["action"] = "latest unknown (npm registry unreachable)"
        return status
    if status["local"] == status["latest"]:
        status["action"] = "up to date"
        return status
    if npm is None:
        status["action"] = f"outdated ({status['local']}); npm not found to upgrade"
        return status

    print(f"  upgrading snyk CLI {status['local']} -> {status['latest']} ...")
    proc = subprocess.run(
        [npm, "install", "-g", "snyk@latest"],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if proc.returncode == 0:
        status["action"] = f"upgraded {status['local']} -> {status['latest']}"
        status["local"] = status["latest"]
    else:
        status["action"] = f"upgrade failed: {proc.stderr.strip()[:200]}"
    return status


def main() -> None:
    previous: dict = {}
    if PINS_FILE.exists():
        try:
            previous = json.loads(PINS_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            previous = {}

    print("Resolving latest scanner releases...")

    cisco = latest_pypi_version("cisco-ai-skill-scanner")
    agent_scan = latest_pypi_version("snyk-agent-scan")
    spector_tag = latest_github_release_tag("NVIDIA/skillspector")
    snyk_cli = update_snyk_cli()

    pins = {
        "cisco_ai_skill_scanner": cisco
        or previous.get("cisco_ai_skill_scanner"),
        "skillspector_git_ref": spector_tag
        or previous.get("skillspector_git_ref"),
        "snyk_agent_scan": agent_scan or previous.get("snyk_agent_scan"),
        "snyk_cli": snyk_cli,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    PINS_FILE.write_text(json.dumps(pins, indent=2), encoding="utf-8")

    print(f"  cisco-ai-skill-scanner : {pins['cisco_ai_skill_scanner']}")
    print(f"  skillspector           : {pins['skillspector_git_ref']}")
    print(f"  snyk-agent-scan        : {pins['snyk_agent_scan']}")
    print(f"  snyk CLI               : {snyk_cli['local']} ({snyk_cli['action']})")
    print(f"Pins written to: {PINS_FILE}")


if __name__ == "__main__":
    main()
