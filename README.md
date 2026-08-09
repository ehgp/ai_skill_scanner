# ai_skill_scanner

Security gate for AI agent artifacts — **skills, plugins, and MCP servers/configs**
— before they are installed. Every candidate runs through a pipeline of five
independent scanners plus an in-house static pass; findings at or above the
configured severity reject the candidate into `rejected/`, clean candidates land
in `approved/`, and every run writes a full JSON report to `reports/`.

## Install as an agent skill (Claude Code / Codex)

This repo doubles as an [Agent Skill](SKILL.md): once installed, your agent
scans candidate skills/plugins/MCP servers before you install them.

```bash
# Claude Code (personal skills)
git clone https://github.com/ehgp/ai_skill_scanner "$HOME/.claude/skills/ai-skill-scanner"

# Codex
git clone https://github.com/ehgp/ai_skill_scanner "$HOME/.codex/skills/ai-skill-scanner"
```

Then ask your agent things like *"scan https://clawhub.ai/owner/some-skill
before I install it"* or *"is this plugin in ./downloads/foo.zip safe?"*.
Project-scoped installs work too (`.claude/skills/ai-skill-scanner` inside a
repo). Requirements: Python 3.10+ and [uv](https://docs.astral.sh/uv/) on
PATH (uv provisions each scanner engine's own interpreter automatically);
optional tokens in `.env` unlock the cloud engines (see below).

## Scanners

| Stage | Tool | Covers | Needs |
|---|---|---|---|
| `gendigital` | GenDigital lookup API | ClawHub URL reputation | network |
| `static` | in-house regex/policy scan | exec payloads (`curl\|bash`, `eval`, …), shell invocations, env-var & credential access near network/shell context, required third-party APIs / gateways / URLs | nothing |
| `cisco` | [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) (`cisco-ai-skill-scanner==2.0.13`) | prompt injection, data exfiltration, command taint pipelines, YARA, bytecode, AST dataflow (`--use-behavioral`) | nothing (offline) |
| `skillspector` | [NVIDIA/skillspector](https://github.com/NVIDIA/skillspector) (`@v2.8.2`, git install — not on PyPI) | 68 patterns / 17 categories: prompt injection, anti-refusal, exfiltration, taint tracking, YARA, MCP tool poisoning; risk score 0–100 | nothing (offline, `--no-llm`) |
| `snyk_agent_scan` | [snyk/agent-scan](https://github.com/snyk/agent-scan) (`snyk-agent-scan==0.5.16`) | skill + MCP-config prompt-injection / toxic-flow analysis | `SNYK_TOKEN` |
| `snyk_sca` | [snyk/cli](https://github.com/snyk/cli) `snyk test --all-projects` | CVEs in dependency manifests | `snyk` CLI, auth |
| `snyk_code` | [snyk/cli](https://github.com/snyk/cli) `snyk code test` | SAST on bundled source code | `snyk` CLI, auth, Snyk Code enabled |

Unconfigured cloud stages are **skipped with a recorded reason** — with two
fail-closed exceptions: any artifact carrying an MCP config (standalone or
embedded in a skill/plugin) is rejected as unverifiable when `snyk_agent_scan`
cannot run, and MCP *server source* is rejected when Snyk Code cannot run.
For skill content the offline core (`static` + `cisco` + `skillspector`) must
run and pass. The in-house static pass scans Markdown **including fenced code
blocks** for exec payloads (fences are where instruction-file payloads live);
fences are stripped only for the external-API prose policy.

## Usage

```bash
# Scan everything in candidates/ plus all links in targets.yaml
uv run skill-scanner.py

# Scan explicit targets only
uv run skill-scanner.py https://clawhub.ai/owner/some-skill ./candidates/x.zip C:/path/to/skill-dir

# Stricter threshold, enable LLM analyzers
uv run skill-scanner.py --fail-on low --llm
```

`uv run` resolves the inline dependencies (`requests`, `pyyaml`); plain
`python skill-scanner.py` works too if both are installed.

## Tuning the static rules

Every pattern the `static` stage looks for lives in
[static-rules.yaml](static-rules.yaml) — nothing is hardcoded in the scanner.
Set `enabled: false` on any rule to switch that keyword off:

```yaml
high_confidence:
  - id: powershell-command-switch
    enabled: false        # stop flagging PowerShell invocations
    description: powershell/pwsh invoked with a command, encoded payload, or script switch
    pattern: |-
      \b(?:powershell|pwsh)...
```

The file holds five rule groups (`high_confidence`, `env_access`,
`secret_names`, `suspicious_context`, `external_api`), plus the plain lists
`dependency_markers` (phrases that turn an external-API mention into a real
finding) and `allowed_domains`, and a `scan_scope` block for which file types
and sizes get read. Findings carry the rule `id` that fired, so a noisy rule
in a report is easy to trace back and switch off:

```
Static scan high_confidence [curl-pipe-shell] in SKILL.md: curl http://... | bash
```

`allowed_domains` matches subdomains automatically — `python.org` also allows
`docs.python.org` — while the required dot keeps lookalikes like
`evilgithub.com` from matching `github.com`. It ships with documentation,
standards, license, and package-registry domains, plus the RFC 2606
placeholder hosts (`example.com` and friends) that can never be a real
endpoint. Deliberately **not** allowlisted: `raw.githubusercontent.com` and
webhook hosts like `hooks.slack.com` or `api.telegram.org`, which are real
payload-delivery and exfiltration channels.

The file is required. If it is missing, unparseable, or has every rule
disabled, the scanner refuses to start rather than silently passing every
artifact — use `--skip static` if you genuinely want the stage off, so the
omission is recorded in the report.

After editing rules, check them against known-good and known-bad text:

```bash
uv run tests/test_static_rules.py
```

It asserts that each sample matches the rule it should, that ordinary prose
and documentation don't match anything, and that the domain allowlist accepts
doc hosts while still flagging raw-file and webhook hosts.

### A note on the shell-invocation rule

Naming a shell is not a finding — `powershell` and `pwsh` appear constantly in
prose ("requires PowerShell 7"), in code-fence language tags, and in markdown
tables. The rule fires only on **invocation**: a command switch
(`-Command`, `-EncodedCommand`, `-File`, `-ExecutionPolicy`, `-ArgumentList`,
…), an inline quoted command, a `.ps1` script argument, or something piped
into the shell. On two real plugin repos this removed 33 of 36 PowerShell
findings; the 3 survivors were genuine `spawn('powershell.exe', ['-NoProfile',
…])` calls.

One deliberate blind spot: a bare `cmd | powershell | othercmd` mid-pipeline
is not matched, because distinguishing it from a markdown table row costs more
false positives than it prevents misses — real payloads in that shape carry a
switch or a quoted command, which the other alternatives catch.

## Enabling and disabling scanners

Every engine has an on/off switch in `targets.yaml` under `settings`:

```yaml
settings:
  fail_on: high
  llm: true            # master switch for LLM-backed analysis in any engine

  scanners:            # whole engines
    gendigital: true
    static: true
    cisco: true
    skillspector: true
    snyk_agent_scan: true
    snyk_sca: true
    snyk_code: true

  cisco:               # Cisco's optional analyzers (core always runs)
    behavioral: true
    llm: true
    osv: false
    virustotal: true   # dormant until CISCO_VIRUSTOTAL_API_KEY is set
    aidefense: true    # dormant until CISCO_AI_DEFENSE_API_KEY is set
    trigger: false
    meta: false
    adjudicate: false

  skillspector:
    llm: true
```

Per-run overrides: `--only static,cisco` runs just those engines, `--skip
snyk_sca,snyk_code` turns those off. An unknown stage name is rejected with
the valid list rather than silently ignored. `--llm` / `--osv` still work as
CLI overrides of the master switches.

An LLM-backed analyzer runs only when three things agree: its own toggle, the
`llm` master switch, and the presence of its credential. The startup banner
prints the **effective** set, so what it lists is what actually ran.

**Disabled is not the same as unavailable.** An engine that *could not* run
(missing token, unreachable endpoint) is fail-closed — for MCP artifacts and
skill cores that rejects the candidate. An engine you deliberately switched
off does not fail the verdict, but every disabled stage is recorded in the
report's `coverage_notes` and printed as `(disabled)`, because an approval
with engines switched off is weaker evidence than a full pass.

## Runtime expectations

Measured on a desktop workstation (2026-08-08) over the **same 7 targets** —
5 single skills plus 2 multi-skill GitHub plugin repos — with all seven
scanner stages on. The only difference is whether LLM-backed analysis is
enabled, and it dominates everything else:

| Configuration | Wall clock | Per single skill |
|---|---|---|
| All stages, **LLM analyzers off** | **19.6 min** | ~30 s |
| All stages, **LLM on** (local 12B model) + VirusTotal + AI Defense + OSV | **89 min** | 41–210 s |

Per-target breakdown of the LLM-off run — multi-skill repos dominate because
Cisco and SkillSpector run once per contained skill:

| Target | Kind | LLM off | LLM on |
|---|---|---|---|
| oh-my-claudecode (GitHub) | plugin, ~30 skills | 730 s | 3454 s |
| superpowers (GitHub) | plugin, ~14 skills | 263 s | 1401 s |
| code-review | single skill | 58 s | 98 s |
| database-operations | single skill | 32 s | 68 s |
| docker-compose | single skill | 31 s | 210 s |
| github | single skill | 31 s | 41 s |
| dockerfile-generator | single skill | 30 s | 69 s |

Rules of thumb: a single skill costs **~30 s** without LLM analysis and
**1–4 min** with it; a multi-skill repo costs roughly **25 s per contained
skill** without LLM and **1.5–2 min per skill** with it. Cisco is usually
the slowest stage; on skills that reach the cloud, `snyk_agent_scan` can be.

Every report records `duration_seconds` per target and per stage
(`stage_durations` in `reports/summary.json`), so you can see exactly where
time went and which target took the longest.

## Keeping scanners current

**[update-scanners.py](update-scanners.py) runs automatically as the first
step of every scan**: it resolves the latest release of each upstream scanner
(PyPI for `cisco-ai-skill-scanner` and `snyk-agent-scan`, GitHub releases for
SkillSpector, the npm registry for the Snyk CLI — upgrading it in place via
`npm install -g` when stale) and writes them to `scanner-pins.json`
(gitignored). Pin precedence: **env var > scanner-pins.json > hardcoded
fallback**. Lookup failures are non-fatal — an offline run scans with the
last known pins. Skip the pre-step with `--no-update` for offline or
deterministic runs, or run it standalone:

```bash
uv run update-scanners.py
```

## Intake — three merged sources

1. **`candidates/` drops** — ZIPs, bare directories, or MCP config `*.json`
   files placed in `candidates/` are discovered automatically.
2. **`targets.yaml`** — paste link lists (ClawHub skill URLs or GitHub repo
   URLs, fetched as default-branch zipballs) or local paths; also holds
   default settings (`fail_on`, `llm`, `osv`). Secrets do NOT go here — they
   live in `.env`.
3. **CLI arguments** — when given, *only* those targets are scanned.

## ZIP packaging contract

For an LLM (or human) packaging a candidate from a repository of skills:
create a ZIP containing **one top-level directory** named after the artifact,
holding at its root one of:

| Content at the top-level dir root | Classified as |
|---|---|
| `SKILL.md` (+ any bundled files) | `skill` |
| several subdirectories, each with its own `SKILL.md` | `skill_collection` |
| `.claude-plugin/plugin.json` or `plugin.json` (with `commands/`, `agents/`, `skills/`, `hooks/`, `.mcp.json` as needed) | `plugin` |
| `mcp.json`, `.mcp.json`, `mcp_config.json`, `claude_desktop_config.json`, or any `*.json` with an `mcpServers` key | `mcp_config` |
| MCP server source (`package.json` depending on `@modelcontextprotocol/sdk`, or Python depending on `mcp`) | `mcp_server` |

`SKILL.md` at the ZIP root (no wrapper directory) is also accepted, and a bare
MCP config `*.json` (including dot-named files like `.mcp.json`) can be dropped
into `candidates/` directly. Anything else is rejected as `unknown` packaging.

Guardrails on untrusted input: ZIPs with absolute paths or `..` entries are
rejected before extraction, as are decompression bombs (>10k entries, >1 GiB
uncompressed, or >200x per-entry compression ratio); artifacts with more than
50 `SKILL.md` directories are rejected to bound scanner fan-out. `candidates/`
subdirectories prefixed with `_` are scanner workspace: ClawHub downloads land
in `candidates/_downloads/` and extractions in `candidates/_extracted/` —
neither is picked up as a drop.

## Environment

- Python 3.10+ and `uv` on PATH (each scanner engine runs via `uvx`, which
  provisions any interpreter that engine needs — SkillSpector's 3.12+
  requirement is satisfied by uv, not your host Python).
- Secrets and toggles live in **`.env`** (gitignored; copy from
  `.env.example`, which documents every variable). The scanner auto-loads it;
  a variable already set in the real environment always wins.
- Optional: `SNYK_TOKEN`, authenticated `snyk` CLI,
  `CISCO_SKILL_SCANNER_LLM_API_KEY` (+`--llm`), `SKILLSPECTOR_PROVIDER` +
  provider key / `OPENAI_BASE_URL` / `SKILLSPECTOR_MODEL` (+`--llm`),
  `CISCO_VIRUSTOTAL_API_KEY` and `CISCO_AI_DEFENSE_API_KEY` (auto-enable
  those Cisco analyzers when set; mapped to the tool's native var names).
- Version pins override via env or `.env`: `CISCO_SKILL_SCANNER_VERSION`,
  `SKILLSPECTOR_GIT_REF`, `SNYK_AGENT_SCAN_VERSION`.

> Note: the PyPI package named `skill-scanner` (0.3.x) is **not** Cisco's
> scanner — the real package is `cisco-ai-skill-scanner`. The pin here targets
> the correct one.
