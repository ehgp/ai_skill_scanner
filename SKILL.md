---
name: ai-skill-scanner
description: >-
  Security-scan AI agent artifacts - Claude/Codex skills, plugins, and MCP
  servers/configs - BEFORE installing or trusting them. Runs multiple
  independent engines (Cisco AI Defense skill-scanner, NVIDIA SkillSpector,
  Snyk agent-scan, Snyk CLI SCA/SAST, ClawHub reputation lookup, plus an
  in-house URL/credential/payload policy scan) and buckets each candidate
  into approved/ or rejected/ with a full JSON findings report. Use this
  whenever the user wants to vet, audit, scan, or check the safety of a
  skill, plugin, or MCP server; asks "is this skill safe to install?"; wants
  to screen a ClawHub or GitHub skill, a marketplace download, a SKILL.md, a
  plugin.json bundle, or an mcpServers config before adding it; or mentions
  prompt injection, data exfiltration, or supply-chain risk in agent tooling.
  Also use it to re-screen artifacts after updates. Do NOT use it for
  authoring or improving skills, or for general security review of
  application source code - it is a pre-install gate for third-party agent
  artifacts.
---

# AI Skill Scanner

A fail-closed security gate for AI agent artifacts. Candidates are classified
(skill, skill collection, plugin, MCP config, MCP server) and run through
every applicable engine; findings at or above the configured severity reject
the candidate. A rejected artifact should NOT be installed - tell the user
what was found and why.

## Prerequisites

- Python 3.10+ and `uv` on PATH. Each scanner engine is fetched on demand via
  `uvx`, and uv provisions any interpreter an engine itself needs.
- Network access for the automatic engine-update pre-step and for URL
  targets; `--no-update` with local path targets gives a fully offline run.
- Optional cloud engines activate via `.env` in this skill's directory (copy
  `.env.example`, which documents every variable): `SNYK_TOKEN` (Snyk
  agent-scan; use the legacy UUID API token, not a `snyk_...` PAT), an
  authenticated `snyk` CLI, VirusTotal / Cisco AI Defense keys, and LLM
  analyzer configuration (cloud keys or a local OpenAI-compatible endpoint).
- Without any of those, the offline core still runs: the in-house static
  policy scan, Cisco's static/YARA/bytecode/pipeline/behavioral analyzers,
  and SkillSpector's 68 offline patterns.

## Workflow

1. **Get the candidate into scannable form.**
   - ClawHub listing URL or GitHub repo URL: pass it directly (the scanner
     downloads it).
   - A skill/plugin directory or MCP config JSON on disk: pass the path
     directly.
   - Anything else (a skill embedded in a larger repo, an attachment):
     package it per the ZIP contract below and drop it into `candidates/`
     inside this skill's directory.

2. **Run the scan.** Invoke the script by its path in THIS skill's directory
   (the one containing this SKILL.md) - your working directory does not
   matter, because candidates/, reports/, approved/, and rejected/ all
   resolve relative to the script itself:

   ```bash
   uv run <this-skill-dir>/skill-scanner.py <url-or-path> [<more targets>...]
   ```

   With no arguments it scans everything in the skill directory's
   `candidates/` plus every entry in its `targets.yaml`. Useful flags:
   `--fail-on {critical,high,medium,low,info}` (built-in default: medium -
   note the shipped `targets.yaml` may set a different default; CLI flags
   win), `--llm` (enable LLM analyzers where configured), `--only a,b` /
   `--skip a,b` (run or disable specific engines: gendigital, static, cisco,
   skillspector, snyk_agent_scan, snyk_sca, snyk_code), `--no-update` (skip
   the automatic update of scanner engines to their latest releases - use
   for offline or reproducible runs).

   Engines can also be switched on/off persistently in `targets.yaml` under
   `settings.scanners`, with Cisco's optional analyzers under
   `settings.cisco`. Individual static-scan keywords live in
   `static-rules.yaml`, where each rule has an `enabled` flag and findings
   report the rule `id` that fired. Reach for `--skip` or a rule toggle when
   a check is slow, unavailable, or demonstrably noisy for the user's
   codebase - never to make a rejection disappear.

3. **Read the verdict.** Console output shows per-target status and the top
   failure reasons. Full detail is in `reports/<slug>.json` (per stage:
   passed / failed / skipped with reasons) and `reports/summary.json`.
   ZIP candidates are copied to `approved/` or `rejected/`.

4. **Report to the user.** State the verdict, the engines that produced each
   finding, and the concrete findings (rule id, file, severity). Always pass
   on the report's `coverage_notes`: a stage skipped for missing credentials
   means reduced coverage (and for MCP artifacts, automatic rejection as
   unverifiable), and a stage disabled by configuration means the approval
   rests on fewer engines than a full pass.

## ZIP packaging contract (for packaging candidates from a repo)

Create a ZIP containing ONE top-level directory named after the artifact,
holding at its root one of:

| Root contents | Classified as |
|---|---|
| `SKILL.md` (+ bundled files) | skill |
| several subdirs, each with `SKILL.md` | skill collection |
| `.claude-plugin/plugin.json` or `plugin.json` | plugin |
| `mcp.json` / `.mcp.json` / `mcp_config.json` / any `*.json` with `mcpServers` | MCP config |
| MCP server source (`@modelcontextprotocol/sdk` or Python `mcp` dependency) | MCP server |

`SKILL.md` at the ZIP root is also accepted; a bare MCP config `*.json` can be
dropped into `candidates/` directly. Malformed packaging is rejected with a
contract hint. ZIPs are screened for path traversal and decompression bombs
before extraction.

## Interpreting common outcomes

- **Rejected with prompt-injection / exfiltration / command-taint findings**:
  genuine red flags - do not install; quote the findings to the user.
- **Rejected only by the external-API policy**: the artifact requires a
  third-party API, gateway, or credential. This is policy, not malware -
  name the host and let the user decide. To relax it, add the domain to
  `allowed_domains` in `static-rules.yaml` (subdomains are covered
  automatically) and rescan. Never allowlist a raw-file host or a webhook
  endpoint to quiet a finding - those are the actual delivery and
  exfiltration channels.
- **Rejected because a core engine could not run**: an environment problem
  (missing token, unreachable LLM endpoint). Fix the environment and rescan
  rather than trusting a partially-scanned artifact.
- **LLM-analyzer findings vary between runs**: semantic analysis is
  non-deterministic; rerun or raise `--fail-on` when a MEDIUM-only rejection
  looks marginal.

Full documentation - engine table, `targets.yaml` schema, `.env` reference,
version pinning, update mechanics - is in [README.md](README.md).
