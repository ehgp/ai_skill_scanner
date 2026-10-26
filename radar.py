#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
ai-radar: weekly diff of three AI feeds -> dated digest + scanner targets.

Sources (contracts verified in radar/SOURCES.md):
    gittrend   https://gittrend.io/api/trending?category=<topic>  keyless
    curatedai  https://www.curatedai.net/tools.json               keyless
    aa         Artificial Analysis /api/v2/data/llms/models       ARTIFICIAL_ANALYSIS_API_KEY

Every run diffs against radar/state.json ("seen" sets + last metrics), so a second
run reports zero new items. Outputs:
    reports/radar/RADAR-<date>_<HHMMSS>.md   digest
    reports/radar/targets-<date>_<HHMMSS>.txt new skill-like GitHub repos, one URL per line
    radar/candidates.yaml                    same repos, accumulated in targets.yaml entry form
    radar/snapshots/<ISO-week>/<source>.json normalized feed data (last 12 weeks kept)

Usage:
    uv run radar.py                    # all sources (aa skipped without a key)
    uv run radar.py --sources gittrend,curatedai
    uv run radar.py --scan             # then run skill-scanner.py on the new targets
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
RADAR_DIR = BASE_DIR / "radar"
STATE_FILE = RADAR_DIR / "state.json"
SNAPSHOT_DIR = RADAR_DIR / "snapshots"
CANDIDATES_FILE = RADAR_DIR / "candidates.yaml"
OUT_DIR = BASE_DIR / "reports" / "radar"
ROSTER_FILE = Path.home() / ".obsidian/Vault/reference/standards/agent-model-roster.md"
KEEP_WEEKS = 12

UA = "ai-radar/0.1 (weekly personal digest; github.com/ehgp/ai_skill_scanner)"
GITTREND_URL = "https://gittrend.io/api/trending"
# Order matters: a repo listed in several topics is reported under the first.
GITTREND_TOPICS = ("ai-skills", "mcp", "ai-coding-assistant", "ai-agent", "ai-memory")
SKILL_TOPICS = ("ai-skills", "mcp")
CURATEDAI_URL = "https://www.curatedai.net/tools.json"
TOOL_MODALITIES = {
    "LLMs", "IDEs & Coding Tools", "AI Assistants", "Agentic Browsers",
    "Infrastructure", "Multimodal Reasoning",
}
AA_URL = "https://artificialanalysis.ai/api/v2/data/llms/models"
AA_KEY_ENV = "ARTIFICIAL_ANALYSIS_API_KEY"
RISING_RATIO = 1.5  # seen repo whose trendingScore grew >= 50% since the last run
DELTA_FLAG = 0.05   # roster metric change worth flagging
SOURCES = ("gittrend", "curatedai", "aa")


class MissingCredential(LookupError):
    """An optional feed was skipped because its API key is absent."""


def load_env_file(path: Path) -> None:
    """Same .env convention as skill-scanner.py: the real environment wins."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip("'\"")
        if key.strip() and value:
            os.environ.setdefault(key.strip(), value)


def get_json(url: str, headers: dict | None = None, attempts: int = 3):
    """GET a JSON document; retries transient failures (5xx, 429, network)."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json", **(headers or {})})
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504) or attempt == attempts:
                raise RuntimeError(f"HTTP {exc.code} from {url}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == attempts:
                raise RuntimeError(f"{type(exc).__name__} from {url}: {exc}") from exc
        time.sleep(2 * attempt)


# ---------------------------------------------------------------- fetchers --

def fetch_gittrend(limit: int) -> dict[str, dict]:
    """Top `limit` repos per topic, keyed by fullName (first topic wins)."""
    unfiltered = get_json(f"{GITTREND_URL}?limit=1")["pagination"]["total"]
    repos: dict[str, dict] = {}
    for topic in GITTREND_TOPICS:
        page = get_json(f"{GITTREND_URL}?category={topic}&limit={limit}")
        if page["pagination"]["total"] == unfiltered:
            raise RuntimeError(f"category {topic!r} was ignored (unfiltered list returned); slug changed?")
        for r in page["data"]:
            repos.setdefault(r["fullName"], {
                "fullName": r["fullName"],
                "topic": topic,
                "stars": r.get("stars") or 0,
                "starsToday": r.get("starsToday") or 0,
                "trendingScore": r.get("trendingScore") or 0,
                "language": r.get("language"),
                "createdAt": r.get("createdAt"),
                "topics": r.get("topics") or [],
                "tags": r.get("tags") or [],
                "summary": r.get("summary") or r.get("description") or "",
            })
        time.sleep(1)
    return repos


def fetch_curatedai() -> dict[str, dict]:
    keep = ("name", "tagline", "modalities", "pricing", "hasApi", "openSource", "addedAt", "officialUrl", "curatedaiUrl")
    return {t["id"]: {k: t.get(k) for k in keep} for t in get_json(CURATEDAI_URL)["tools"]}


def fetch_aa() -> dict[str, dict]:
    key = os.environ.get(AA_KEY_ENV)
    if not key:
        raise MissingCredential(f"skipped: set {AA_KEY_ENV} (free key from the Artificial Analysis Insights Platform)")
    models = {}
    for m in get_json(AA_URL, headers={"x-api-key": key})["data"]:
        ev, pr = m.get("evaluations") or {}, m.get("pricing") or {}
        models[m["id"]] = {
            "name": m.get("name"),
            "slug": m.get("slug"),
            "creator": (m.get("model_creator") or {}).get("name"),
            "intelligence": ev.get("artificial_analysis_intelligence_index"),
            "coding": ev.get("artificial_analysis_coding_index"),
            "price_blended": pr.get("price_1m_blended_3_to_1"),
            "tok_s": m.get("median_output_tokens_per_second"),
            "ttft_s": m.get("median_time_to_first_token_seconds"),
        }
    return models


# ------------------------------------------------------------------- diffs --

def is_skill_like(repo: dict) -> bool:
    """ai-skills/mcp topic, or a topic/tag that names skills, MCP, or a coding agent."""
    if repo["topic"] in SKILL_TOPICS:
        return True
    for label in repo["topics"] + repo["tags"]:
        label = label.lower()
        parts = label.split("-")
        if {"skill", "skills", "mcp"} & set(parts) or label in {"model-context-protocol", "claude-code", "codex"}:
            return True
    return False


def diff_repos(seen: dict, fetched: dict, prev_run: str | None) -> dict:
    new = [r for name, r in fetched.items() if name not in seen]
    rising = []
    for name, r in fetched.items():
        old = (seen.get(name) or {}).get("score") or 0
        if old > 0 and r["trendingScore"] >= old * RISING_RATIO:
            rising.append({**r, "prev_score": old, "ratio": r["trendingScore"] / old})
    rising.sort(key=lambda r: r["ratio"], reverse=True)
    gone = [n for n, v in seen.items() if prev_run and v.get("last_seen") == prev_run and n not in fetched]
    return {"new": new, "rising": rising[:10], "gone": gone}


def diff_tools(seen: dict, fetched: dict) -> dict:
    new = [{"id": i, **t} for i, t in fetched.items() if i not in seen]
    relevant = [t for t in new if (t["openSource"] or t["hasApi"]) and TOOL_MODALITIES & set(t["modalities"] or [])]
    gone = [{"id": i, **v} for i, v in seen.items() if v.get("present") and i not in fetched]
    return {"new": new, "relevant": relevant, "gone": gone}


def pct(new, old):
    return None if new is None or not old else (new - old) / old


def tokens(s: str) -> list[str]:
    return sorted(re.findall(r"[a-z]+|\d+", (s or "").lower()))


def match_roster(roster_id: str, models: dict) -> tuple[str, dict] | None:
    """Exact token match on slug, else a variant containing the roster tokens (prefer xhigh, then best index)."""
    want = tokens(roster_id)
    exact = [(i, m) for i, m in models.items() if tokens(m["slug"]) == want]
    if exact:
        return exact[0]
    variants = [(i, m) for i, m in models.items() if not set(want) - set(tokens(m["slug"]))
                and len(tokens(m["slug"])) <= len(want) + 2]
    if not variants:
        return None
    return max(variants, key=lambda im: ("xhigh" in tokens(im[1]["slug"]), im[1]["intelligence"] or 0))


def diff_aa(seen: dict, fetched: dict, roster: list[str]) -> dict:
    rows = []
    for rid in roster:
        hit = match_roster(rid, fetched)
        if not hit:
            rows.append({"roster": rid, "model": None})
            continue
        mid, m = hit
        old = seen.get(mid) or {}
        deltas = {k: pct(m[k], old.get(k)) for k in ("intelligence", "price_blended", "tok_s")}
        flag = any(d is not None and abs(d) > DELTA_FLAG for d in deltas.values())
        rows.append({"roster": rid, "model": m, "deltas": deltas, "flag": flag})
    new = [m for i, m in fetched.items() if i not in seen]
    new.sort(key=lambda m: m["intelligence"] or 0, reverse=True)
    return {"roster": rows, "new": new}


def read_roster() -> list[str]:
    """Model ids from the Vault roster table (4th column, backticked)."""
    if not ROSTER_FILE.is_file():
        return []
    ids = []
    for line in ROSTER_FILE.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.split("|")]
        if len(cells) > 5 and cells[4].startswith("`"):
            mid = cells[4].strip("`")
            if mid not in ids:
                ids.append(mid)
    return ids


# ----------------------------------------------------------------- outputs --

def cell(text, width: int = 140) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).replace("|", "\\|")
    return text if len(text) <= width else text[: width - 1] + "…"


def fmt(v, spec: str = ",.0f") -> str:
    return "–" if v is None else format(v, spec)


def fmt_pct(d) -> str:
    return "–" if d is None else f"{d:+.1%}"


def render(stamp: str, week: str, status: dict, repos: dict | None, tools: dict | None,
           aa: dict | None, targets: list[str], scanned: list[str], targets_file: Path | None) -> str:
    out = [f"# AI radar — {stamp.replace('_', ' ')} ({week})", ""]
    out.append("Sources: " + "; ".join(f"**{s}** {msg}" for s, msg in status.items()))
    out.append("")
    if repos is not None:
        out.append(f"## New trending repos ({len(repos['new'])})")
        out.append("")
        if not repos["new"]:
            out += ["0 new repos since the last run.", ""]
        for topic in GITTREND_TOPICS:
            rows = [r for r in repos["new"] if r["topic"] == topic]
            if not rows:
                continue
            out += [f"### {topic} ({len(rows)})", "", "| Repo | Score | Stars | Today | Skill-like | Summary |", "|---|---:|---:|---:|---|---|"]
            for r in sorted(rows, key=lambda r: r["trendingScore"], reverse=True):
                out.append(f"| [{r['fullName']}](https://github.com/{r['fullName']}) | {fmt(r['trendingScore'])} | "
                           f"{fmt(r['stars'])} | {fmt(r['starsToday'])} | {'yes' if is_skill_like(r) else ''} | {cell(r['summary'])} |")
            out.append("")
        out += [f"## Rising already-seen repos ({len(repos['rising'])})", ""]
        if repos["rising"]:
            out += ["| Repo | Score | Was | × |", "|---|---:|---:|---:|"]
            out += [f"| [{r['fullName']}](https://github.com/{r['fullName']}) | {fmt(r['trendingScore'])} | "
                    f"{fmt(r['prev_score'])} | {r['ratio']:.1f} |" for r in repos["rising"]]
        else:
            out.append(f"None grew by ≥ {RISING_RATIO - 1:.0%} since the last run.")
        out += ["", f"{len(repos['gone'])} repo(s) left the tracked topic lists since the last run.", ""]
    if tools is not None:
        other = len(tools["new"]) - len(tools["relevant"])
        out += [f"## New tools — curatedai ({len(tools['relevant'])} relevant, {other} other)", ""]
        out.append("Filter: open source or has an API, and a modality in " + ", ".join(sorted(TOOL_MODALITIES)) + ".")
        out.append("")
        if tools["relevant"]:
            out += ["| Tool | Added | Pricing | OSS | API | Modalities | Tagline |", "|---|---|---|---|---|---|---|"]
            for t in sorted(tools["relevant"], key=lambda t: t["addedAt"] or "", reverse=True):
                link = f"[{cell(t['name'], 60)}]({t['officialUrl'] or t['curatedaiUrl']})"
                out.append(f"| {link} ([entry]({t['curatedaiUrl']})) | {t['addedAt']} | {t['pricing']} | "
                           f"{'yes' if t['openSource'] else ''} | {'yes' if t['hasApi'] else ''} | "
                           f"{cell(', '.join(t['modalities'] or []), 60)} | {cell(t['tagline'])} |")
        else:
            out.append("0 new relevant tools since the last run.")
        if tools["gone"]:
            out += ["", "Removed from the directory: " + ", ".join(t.get("name") or t["id"] for t in tools["gone"])]
        out += ["", "Tool data: CuratedAI (https://www.curatedai.net).", ""]
    out += ["## Roster deltas — Artificial Analysis", ""]
    if aa is None:
        out.append(f"Not available this run ({status.get('aa', 'not requested')}).")
    else:
        out += ["| Roster id | AA model | Intelligence | Δ | $/1M blended | Δ | tok/s | Δ | Flag |",
                "|---|---|---:|---:|---:|---:|---:|---:|---|"]
        for row in aa["roster"]:
            m = row["model"]
            if m is None:
                out.append(f"| `{row['roster']}` | not on AA | | | | | | | |")
                continue
            d = row["deltas"]
            out.append(f"| `{row['roster']}` | {cell(m['name'], 50)} | {fmt(m['intelligence'], '.1f')} | {fmt_pct(d['intelligence'])} | "
                       f"{fmt(m['price_blended'], '.2f')} | {fmt_pct(d['price_blended'])} | {fmt(m['tok_s'], '.0f')} | "
                       f"{fmt_pct(d['tok_s'])} | {'**>5%**' if row['flag'] else ''} |")
        out += ["", f"New models on AA since the last run: {len(aa['new'])}"]
        for m in aa["new"][:15]:
            out.append(f"- {m['name']} ({m['creator']}) — intelligence {fmt(m['intelligence'], '.1f')}, "
                       f"${fmt(m['price_blended'], '.2f')}/1M blended, {fmt(m['tok_s'], '.0f')} tok/s")
        out += ["", "Model data: Artificial Analysis (https://artificialanalysis.ai/)."]
    out += ["", f"## Scanner queue ({len(targets)})", ""]
    if scanned:
        out.append(f"Skipped {len(scanned)} new skill-like repo(s) that already have a report in reports/: "
                   + ", ".join(scanned))
        out.append("")
    if targets:
        out.append(f"Targets file: `{targets_file.relative_to(BASE_DIR).as_posix()}`")
        out += ["", "```bash", "uv run skill-scanner.py " + " ".join(targets), "```"]
    else:
        out.append("No new skill-like repos to scan.")
    return "\n".join(out) + "\n"


def append_candidates(targets: list[str], repos: dict, stamp: str) -> None:
    if not CANDIDATES_FILE.exists():
        CANDIDATES_FILE.write_text(
            "# Radar candidates in targets.yaml entry form. Review, then copy entries into\n"
            "# targets.yaml by hand -- never auto-merged. Appended by radar.py.\n"
            "targets:\n", encoding="utf-8")
    with CANDIDATES_FILE.open("a", encoding="utf-8") as fh:
        for url in targets:
            r = repos[url.removeprefix("https://github.com/")]
            fh.write(f"  - {url}  # {stamp} {r['topic']} score {r['trendingScore']:,.0f}\n")


def prune_snapshots() -> None:
    weeks = sorted(p for p in SNAPSHOT_DIR.iterdir() if p.is_dir())
    for old in weeks[:-KEEP_WEEKS]:
        shutil.rmtree(old)


# -------------------------------------------------------------------- main --

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Weekly AI feed radar -> digest + scanner targets.")
    ap.add_argument("--sources", default=",".join(SOURCES), help=f"comma list from {','.join(SOURCES)}")
    ap.add_argument("--limit", type=int, default=100, help="repos per gittrend topic (API max 100)")
    ap.add_argument("--scan", action="store_true", help="run skill-scanner.py on the new targets")
    args = ap.parse_args(argv)
    wanted = [s.strip() for s in args.sources.split(",") if s.strip()]
    if unknown := set(wanted) - set(SOURCES):
        ap.error(f"unknown source(s): {', '.join(sorted(unknown))}")

    load_env_file(BASE_DIR / ".env")
    now = datetime.now()
    today, stamp = now.date().isoformat(), now.strftime("%Y-%m-%d_%H%M%S")
    iso = now.isocalendar()
    week = f"{iso[0]}-W{iso[1]:02d}"
    state = json.loads(STATE_FILE.read_text(encoding="utf-8")) if STATE_FILE.exists() else {}
    runs = state.setdefault("runs", {})
    snap_dir = SNAPSHOT_DIR / week
    snap_dir.mkdir(parents=True, exist_ok=True)

    fetchers = {"gittrend": lambda: fetch_gittrend(min(args.limit, 100)), "curatedai": fetch_curatedai, "aa": fetch_aa}
    status: dict[str, str] = {}
    fetched: dict[str, dict] = {}
    for src in wanted:
        try:
            fetched[src] = fetchers[src]()
            status[src] = f"ok ({len(fetched[src])} items)"
            (snap_dir / f"{src}.json").write_text(json.dumps(fetched[src], indent=1, ensure_ascii=False), encoding="utf-8")
        except MissingCredential as exc:
            status[src] = str(exc)
        except Exception as exc:  # a failed source never blocks the digest
            status[src] = f"FAILED: {exc}"
    prune_snapshots()

    repos = tools = aa = None
    targets: list[str] = []
    scanned: list[str] = []
    if "gittrend" in fetched:
        seen = state.setdefault("gittrend", {})
        repos = diff_repos(seen, fetched["gittrend"], runs.get("gittrend"))
        for r in repos["new"]:
            if not is_skill_like(r):
                continue
            if (BASE_DIR / "reports" / f"{r['fullName'].replace('/', '__')}.json").exists():
                scanned.append(r["fullName"])
            else:
                targets.append(f"https://github.com/{r['fullName']}")
        for name, r in fetched["gittrend"].items():
            seen.setdefault(name, {"first_seen": today})
            seen[name].update(score=r["trendingScore"], stars=r["stars"], last_seen=stamp)
        runs["gittrend"] = stamp
    if "curatedai" in fetched:
        seen = state.setdefault("curatedai", {})
        tools = diff_tools(seen, fetched["curatedai"])
        for tid, v in seen.items():
            v["present"] = tid in fetched["curatedai"]
        for tid, t in fetched["curatedai"].items():
            seen.setdefault(tid, {"first_seen": today, "name": t["name"], "present": True})
        runs["curatedai"] = stamp
    if "aa" in fetched:
        seen = state.setdefault("aa", {})
        aa = diff_aa(seen, fetched["aa"], read_roster())
        for mid, m in fetched["aa"].items():
            seen[mid] = {**m, "first_seen": (seen.get(mid) or {}).get("first_seen", today)}
        runs["aa"] = stamp

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    targets_file = OUT_DIR / f"targets-{stamp}.txt" if targets else None
    if targets_file:
        targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
        append_candidates(targets, fetched["gittrend"], stamp)
    digest = OUT_DIR / f"RADAR-{stamp}.md"
    digest.write_text(render(stamp, week, status, repos, tools, aa, targets, scanned, targets_file), encoding="utf-8")
    STATE_FILE.write_text(json.dumps(state, indent=1, ensure_ascii=False), encoding="utf-8")

    for src, msg in status.items():
        print(f"{src}: {msg}")
    if repos is not None:
        print(f"new repos: {len(repos['new'])} (skill-like targets: {len(targets)}, already scanned: {len(scanned)}); rising: {len(repos['rising'])}")
    if tools is not None:
        print(f"new tools: {len(tools['new'])} (relevant: {len(tools['relevant'])}); removed: {len(tools['gone'])}")
    if aa is not None:
        print(f"new AA models: {len(aa['new'])}; roster flags: {sum(r.get('flag', False) for r in aa['roster'])}")
    print(f"digest: {digest.relative_to(BASE_DIR).as_posix()}")
    if targets_file:
        print(f"targets: {targets_file.relative_to(BASE_DIR).as_posix()}")
    if args.scan and targets:
        return subprocess.run(["uv", "run", "skill-scanner.py", *targets], cwd=BASE_DIR).returncode
    return 1 if any(m.startswith("FAILED") for m in status.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
