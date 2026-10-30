#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""radar.py diff logic: fixture snapshots -> expected new / rising / gone / roster match."""
import sys
import io
import os
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import radar  # noqa: E402


def repo(name, topic="ai-agent", score=100.0, topics=(), tags=()):
    return {"fullName": name, "topic": topic, "trendingScore": score, "stars": 1, "starsToday": 0,
            "topics": list(topics), "tags": list(tags), "summary": ""}


def main() -> None:
    # Repos: a/new is new, b/up rose 2x, c/flat is unchanged, d/gone left the list.
    seen = {"b/up": {"score": 100, "last_seen": "R1"}, "c/flat": {"score": 100, "last_seen": "R1"},
            "d/gone": {"score": 100, "last_seen": "R1"}, "e/old": {"score": 100, "last_seen": "R0"}}
    fetched = {"a/new": repo("a/new"), "b/up": repo("b/up", score=200), "c/flat": repo("c/flat")}
    d = radar.diff_repos(seen, fetched, "R1")
    assert [r["fullName"] for r in d["new"]] == ["a/new"], d["new"]
    assert [r["fullName"] for r in d["rising"]] == ["b/up"], d["rising"]
    assert d["gone"] == ["d/gone"], d["gone"]  # e/old left before the last run: not re-reported
    # Second run over the same data reports nothing new.
    seen2 = {**seen, "a/new": {"score": 100, "last_seen": "R2"}, "b/up": {"score": 200, "last_seen": "R2"}}
    d2 = radar.diff_repos(seen2, fetched, "R2")
    assert not d2["new"] and not d2["rising"], d2

    # Skill-like: topic or label based, not summary prose.
    assert radar.is_skill_like(repo("x/y", topic="mcp"))
    assert radar.is_skill_like(repo("x/y", topics=["agent-skills"]))
    assert radar.is_skill_like(repo("x/y", tags=["claude-code"]))
    assert not radar.is_skill_like(repo("x/y", topics=["llm", "skillet"]))

    # Tools: relevant = (OSS or API) and an agent/coding modality; gone = previously present.
    tool = {"name": "T", "modalities": ["LLMs"], "openSource": False, "hasApi": True, "addedAt": "2026-10-19"}
    fetched_t = {"t1": tool, "t2": {**tool, "modalities": ["Text → Video"]}, "t3": {**tool, "hasApi": False}}
    dt = radar.diff_tools({"t0": {"present": True}, "tx": {"present": False}}, fetched_t)
    assert [t["id"] for t in dt["new"]] == ["t1", "t2", "t3"]
    assert [t["id"] for t in dt["relevant"]] == ["t1"]
    assert [t["id"] for t in dt["gone"]] == ["t0"]

    # Roster match: exact slug first, else the xhigh variant; deltas flag > 5 %.
    m = lambda slug, i: {"name": slug, "slug": slug, "creator": "x", "intelligence": i, "price_blended": 1.0, "tok_s": 100.0}
    models = {"1": m("gpt-6-1-sol-low", 60), "2": m("gpt-6-1-sol-xhigh", 70), "3": m("claude-opus-5-5", 65)}
    assert radar.match_roster("gpt-6.1-sol", models)[0] == "2"
    assert radar.match_roster("claude-opus-5-5", models)[0] == "3"
    assert radar.match_roster("gpt-6-luna", models) is None
    da = radar.diff_aa({"3": {**models["3"], "intelligence": 60}}, models, ["claude-opus-5-5"])
    assert da["roster"][0]["flag"] and round(da["roster"][0]["deltas"]["intelligence"], 3) == 0.083
    assert {x["slug"] for x in da["new"]} == {"gpt-6-1-sol-low", "gpt-6-1-sol-xhigh"}

    # A malformed source fails the run; an absent optional API credential skips it.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        with patch.multiple(radar, BASE_DIR=root, RADAR_DIR=root / "radar",
                            STATE_FILE=root / "radar" / "state.json",
                            SNAPSHOT_DIR=root / "radar" / "snapshots",
                            OUT_DIR=root / "reports" / "radar"):
            with patch.object(radar, "get_json", return_value={"error": "upstream unavailable"}):
                output = io.StringIO()
                with redirect_stdout(output):
                    assert radar.main(["--sources", "curatedai"]) == 1
                assert "curatedai: FAILED: 'tools'" in output.getvalue()
            with patch.dict(os.environ, {radar.AA_KEY_ENV: ""}):
                output = io.StringIO()
                with redirect_stdout(output):
                    assert radar.main(["--sources", "aa"]) == 0
                assert "aa: skipped: set ARTIFICIAL_ANALYSIS_API_KEY" in output.getvalue()
    print("test_radar: ALL PASS")


if __name__ == "__main__":
    main()
