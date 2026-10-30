# Radar feed contracts (verified 2026-10-19)

What `radar.py` actually calls, checked with live requests on 2026-10-19 (UA `ai-radar/0.1`).
Re-check here first when a source starts failing; the digest names the failing source.

## gittrend.io — `GET https://gittrend.io/api/trending` (keyless, CC0)

- Response: `{"data": [...], "pagination": {"page", "limit", "total", "totalPages", "hasMore"}}`.
- Record fields: `id, fullName, owner, name, description, language, stars, forks, topics[],
  createdAt, summary, difficulty, tags[], starsToday, trendingScore`.
- Params that work: `category=<topic slug>` (`ai-agent` 1,042 repos, `ai-coding-assistant` 398,
  `ai-memory` 120, `ai-skills` 518, `mcp` 400), `page`, `limit` (default 20, **capped at 100**),
  `language=<Name>` (case-sensitive: `Python` works, `python` returns 0).
- Params that are **ignored**: `topic`, `period`, `since`, `sort`, `q`. There is no weekly window;
  the list is today's velocity ranking.
- Trap: an unknown `category` silently returns the unfiltered list (total 12,989). `radar.py`
  fetches the unfiltered total once and treats a category with the same total as a failure.
- `llms.txt` at `https://gittrend.io/llms.txt` lists the topic slugs.

## curatedai.net — `GET https://www.curatedai.net/tools.json` (keyless)

- The apex `curatedai.net` 308-redirects to `www.`; call `www.` directly. ~660 KB.
- Response: `{"meta": {...}, "tools": [...]}`; 404 tools on 2026-10-19.
- Tool fields: `id, name, tagline, description, answer, modalities[], pricing, platforms[], hasApi,
  openSource, addedAt (YYYY-MM-DD), bestForTag, bestFor[], officialUrl, curatedaiUrl`.
- `modalities` values (no "agents" or "coding" literal): `LLMs`, `IDEs & Coding Tools`,
  `Multimodal Reasoning`, `AI Assistants`, `Agentic Browsers`, `Infrastructure`,
  `Multi-Service Platforms`, plus media ones (`Text → Image`, `Image → Video`, ...).
- `pricing` values: `Freemium`, `Paid`, `Free`, `Unknown`, `Enterprise`, `proprietary`.
- No stability promise; `llms.txt` asks for attribution to CuratedAI.

## Artificial Analysis — `GET https://artificialanalysis.ai/api/v2/data/llms/models` (free key)

- **Key required**: header `x-api-key`; without it `401 {"error":"API key is required"}`. The path
  captured by REA (`/api/v2/language/models`) also returns 401 and is not in the docs.
- Free key: create an account on the Artificial Analysis Insights Platform. Docs
  (`https://artificialanalysis.ai/documentation`): free API limited to 1,000 requests/day; keep
  the key server-side and cache responses; **attribution to https://artificialanalysis.ai/ is
  required** (the digest prints it).
- Documented response: `{"status", "prompt_options", "data": [{id (stable), name, slug,
  model_creator{id,name,slug}, evaluations{artificial_analysis_intelligence_index,
  artificial_analysis_coding_index, ...}, pricing{price_1m_blended_3_to_1, price_1m_input_tokens,
  price_1m_output_tokens}, median_output_tokens_per_second, median_time_to_first_token_seconds}]}`.
- Not in the free API: per-provider speed/latency, 7/30/90-day windows, cache pricing,
  "cost per index task" (commercial API only).
- `radar.py` reads the key from `ARTIFICIAL_ANALYSIS_API_KEY` (environment or `.env`); without it
  the AA section is skipped with a note. The response shape above is from the docs — not yet
  seen live, because no key exists on this machine.
