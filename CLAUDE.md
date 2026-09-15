# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

PenMaster Security — an autonomous penetration-testing agent. A Python loop (`agent_loop.py`) sends goals to a local LLM (Qwen 2.5, served by LM Studio's OpenAI-compatible API), parses the model's JSON tool-call response, and executes it against a Flask tool-execution server (`mcp_server.py`) running Kali Linux security tools. It is designed to run unattended, with no per-call user confirmation, against targets the operator is authorized to test.

Because this repo's purpose is offensive security tooling, treat any code changes here as changes to a real attack/exploitation pipeline, not a demo — see "Security-sensitive code" below.

## Running it

There is no dependency manifest (no `requirements.txt`/`pyproject.toml`) and no test suite in this repo. Runtime deps observed in source: `flask`, `requests`.

```bash
# Terminal 1 — tool execution server (must be running first)
python3 mcp_server.py          # Flask, binds 0.0.0.0:8000

# Terminal 2 — agent loop (needs LM Studio reachable at OLLAMA_URL, see below)
python3 agent_loop.py
```

Agent loop commands (typed at the `>>>` prompt):
- `engage <target>` — full autonomous recon (masscan → nmap) then attack loop over every discovered port
- `<any other text>` — treated as a single freeform goal, model produces one tool chain
- `exit` / Ctrl+C — ends the session and shells out to `report_generator.py <logfile>` to generate an HTML report. **That script is gitignored and not present in this repo** — it must exist locally at `/home/bigkali/security-agent/report_generator.py` for report generation to work.

## Architecture

```
agent_loop.py  ──(HTTP, JSON tool-call)──►  mcp_server.py (Flask :8000)  ──►  subprocess → Kali tools
     │                                              │
     ├──► agent_cache.py (NegativeCache)      ToolExecutor.execute_tool() dispatches
     │    persistent cross-session             on `tool` name to one _run_* method
     │    failure blacklist                    per tool, each building a shell command
     │                                          string and running it via subprocess.
     └──► LM Studio (OpenAI-compatible
          /v1/chat/completions) — the
          actual reasoning/tool-selection
          happens here, not in this repo
```

**`agent_loop.py`** owns the control flow:
- `SYSTEM_PROMPT` tells the model which tools exist, exact Hydra service-name strings, wordlist escalation order (fast → medium → full rockyou.txt), and the required output shape: `{"chain": [{"tool": ..., ...params}]}`, JSON only.
- `call_model()` posts to `OLLAMA_URL` and `parse_model_response()` strips markdown fences and extracts the first `{...}` blob — the model is not trusted to return clean JSON.
- `AgentMemory` (defined inline in `agent_loop.py`, distinct from `memory.py` — see below) tracks open/tried ports and findings for one engagement and drives `run_recon()` → `run_attack_loop()`.
- `execute_step()` POSTs a single tool-call dict to `mcp_server.py` at `MCP_URL` and returns `(stdout, success_bool)`.
- Every tool call is gated through `agent_cache.NegativeCache.should_attempt()` before execution, and outcomes are fed back via `record_success()`/`record_failure()`.
- Custom `EmojiFormatter` logging: log messages use `[TAG]` markers (`[SCAN]`, `[ATTACK]`, `[SUCCESS]`, `[FAIL]`, `[ERROR]`, `[MEMORY]`, `[MODEL]`, `[TOOL]`, ...) which the formatter strips and replaces with an emoji icon. When adding logging, follow this same `[TAG]` convention so it renders correctly, and add new tags to `EmojiFormatter.ICONS` in both `agent_loop.py` and `mcp_server.py` if introducing a new one (the two formatters are duplicated, not shared).

**`mcp_server.py`** is the execution boundary — a single Flask route (`POST /`) that takes `{"tool": ..., ...params}`, validates `tool` against `SUPPORTED_TOOLS`, and dispatches to a `_run_*` method on `ToolExecutor`. Each `_run_*` builds a shell command from user/model-supplied params and runs it via `_execute_command()`, which:
- auto-retries once with `sudo` on a permission-denied error,
- classifies failures into `error_type` buckets (`permission_denied`, `command_not_found`, `timeout`, `command_failed`) with a `recovery_suggestion` string the model can act on,
- has a 7200s (2 hour) subprocess timeout per call.

`SUPPORTED_TOOLS` in `mcp_server.py` is the source of truth for what the server can execute — it currently lists more tools than `README.md`'s table or `agent_loop.py`'s `SYSTEM_PROMPT` document, so the three can drift out of sync. When adding a tool, update all three: `SUPPORTED_TOOLS`, the `execute_tool()` dispatch + new `_run_*` method, and the model-facing tool list in `agent_loop.py`'s `SYSTEM_PROMPT` (otherwise the model won't know the tool exists).

**`agent_cache.py`** (`NegativeCache`) — SHA-256 fingerprints each tool-call dict (all fields except `_meta`, order-independent) and persists to `failure_cache.json`. First failure: warn + retry allowed. Second failure on the same fingerprint: `permanently_blocked = True` forever (across all future sessions, not just the current one) until a success on that exact fingerprint clears it. This is why identical failing calls should not be retried indefinitely — the cache is deliberately global/persistent state, not a per-run cache.

**`memory.py`** and **`logger.py`** are standalone modules — grep confirms neither is imported by `agent_loop.py` or `mcp_server.py`. They implement a separate short-term/episodic/long-term JSONL memory store and a JSON session logger+replay tool (`python3 logger.py logs/session_TIMESTAMP.json` replays a session), added in recent PRs but not yet wired into the live agent loop. Don't assume they run during `engage` — check current imports before relying on their state being populated.

## Environment / config that's hardcoded, not parameterized

These are Python constants at the top of files, not env vars or CLI flags — edit in place for a different environment:

- `agent_loop.py` / `mcp_server.py`: `LOG_DIR = "/home/bigkali/security-agent/logs"` (absolute path, machine-specific)
- `agent_cache.py`: `CACHE_DIR = "/home/bigkali/security-agent"` → `failure_cache.json`
- `agent_loop.py`: `OLLAMA_URL = "http://192.168.0.39:1234/v1/chat/completions"` (LM Studio host:port, despite the name this is LM Studio's OpenAI-compatible endpoint, not Ollama) and the exact model id string `"qwen2.5-14b-instruct-abliterated-abliterated"` sent in the payload — must match what's loaded in LM Studio.
- `agent_loop.py`: `MCP_URL = "http://localhost:8000"`
- `mcp_server.py`: Flask binds `0.0.0.0:8000` (not localhost-only) — `docs/MCP-SERVER.md` explicitly warns this server should never be exposed to untrusted networks, so be careful changing the bind address or adding auth-free routes.

## Security-sensitive code

This server executes attacker-supplied and LLM-generated strings directly in shell commands (`subprocess.run(command, shell=True, ...)`) across nearly every `_run_*` method in `mcp_server.py`, and `run_command` executes an arbitrary command outright with no allowlist. This is intentional — the tool's entire purpose is autonomous exploitation — but it means:
- There is no sandboxing between the agent's tool selection and real command execution beyond the `SUPPORTED_TOOLS` name check.
- `_execute_command` auto-escalates to `sudo` on permission errors without confirmation.
- Only ever point this at targets/networks the operator is authorized to test (per `SECURITY.md`/`CODE_OF_CONDUCT.md`).
- When modifying `_run_*` methods, preserve or improve shell-argument handling; don't casually concatenate untrusted input into commands beyond the existing pattern without considering injection risk from the model's own output.


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:1105d646 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->
