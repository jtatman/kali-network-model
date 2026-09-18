# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

PenMaster Security — an autonomous penetration-testing agent, forked and retargeted for a distributed lab topology. A single Python process (`agent.py`) drives a REPL, sends goals to a model served by Ollama (native `/api/chat`, structured JSON output — not LM Studio, not the OpenAI-compat shim), parses the model's tool-chain response, and dispatches each tool call in-process to `tools.py`, which builds a shell command string and runs it via `remote_exec.py` over SSH (or `docker exec`) against a separate Kali execution target. There is no local Flask server and no local tool execution anymore — that was the old, retired architecture; see "History" below if you find a reference to it.

Because this repo's purpose is offensive security tooling, treat any code changes here as changes to a real attack/exploitation pipeline, not a demo — see "Security-sensitive code" below. Only ever point it at targets/networks the operator is authorized to test (see README.md's Scope section).

## Running it

No test suite exists. Runtime dependency: `requests` (see `requirements.txt`).

```bash
cp .env.example .env   # fill in OLLAMA_HOST/OLLAMA_MODEL, EXEC_MODE, SSH_*/DOCKER_CONTAINER
python3 agent.py
```

`CONFIG.validate()` runs at startup and fails fast with a clear message if required env vars are missing — there is no partial/degraded startup mode.

REPL commands (typed at the `>>>` prompt):
- `engage <target> [ports]` — full autonomous recon (nmap) then attack loop over every discovered port. Optional comma-separated `ports` restricts recon to an explicit list instead of a full 1-65535 sweep (deterministic path, no model call — see `run_full_engagement` in `agent.py`).
- `<any other text>` — treated as a single freeform goal; if it names a target and explicitly restricts scanning to specific ports, it's silently routed to the same deterministic `run_full_engagement` path as `engage` (confirmed the model does not reliably honor an inline port restriction otherwise — see `agent.py`'s `_PORT_SCOPE_RE` comment). Otherwise it's a single model-planned tool chain.
- `exit` / Ctrl+C — ends the session, closes the JSON session log, and calls `report_generator.generate()` in-process to write a Markdown report to `REPORT_DIR`.

## Architecture

```
agent.py (REPL, control loop, Ollama /api/chat calls)
     │
     ├──► tools.py (ToolExecutor.execute_tool() dispatches on `tool` name
     │     to one _run_* method, each building a shell command string)
     │         │
     │         └──► remote_exec.py (run() — SSH "direct"/"docker", or
     │               "local_docker" via this machine's own `docker exec`)
     │                     │
     │                     └──► subprocess → Kali tools on the remote target
     │
     ├──► agent_cache.py (NegativeCache) — persistent cross-session
     │     failure blacklist, fingerprints each tool-call dict
     ├──► logger.py (AgentLogger) — structured JSON session log,
     │     the source report_generator.py reads from
     └──► logging_setup.py — shared EmojiFormatter/setup_logger(),
           human-readable [TAG]-marker log (see below)
```

**`agent.py`** owns the control flow:
- `SYSTEM_PROMPT` documents every real tool and param name, exact Hydra service-name strings, wordlist escalation order (fast → medium → full rockyou.txt), and the CVE/known-exploit workflow (searchsploit/metasploit search before blind credential brute force).
- `CHAIN_JSON_SCHEMA` constrains the model's `chain[].tool` field to a real `tools.SUPPORTED_TOOLS` enum via Ollama's `format` field (grammar-constrained decoding) — the model can no longer hallucinate a nonexistent tool name, which is the direct fix for the old SUPPORTED_TOOLS/SYSTEM_PROMPT/README drift problem. `"additionalProperties": true` on the chain-item schema is load-bearing, not decoration — without it Ollama's constrained decoder silently drops every tool param and only ever emits `{"tool": "..."}`, confirmed empirically.
- `parse_model_response()` is now just `json.loads` with a narrow fallback — no markdown-fence-stripping/brace-hunting, since structured output makes the response trustworthy by construction.
- `AgentMemory` tracks open/tried ports, findings, and successful/failed attacks for one engagement; drives `run_recon()` → `run_attack_loop()`.
- `run_attack_loop()` gives the model up to `MAX_ATTACK_ROUNDS` (5) re-planning rounds per port, feeding back a compressed record of each round's real tool output (`compress_tool_output` — deterministic truncation, never an LLM-generated summary, to avoid reintroducing hallucination risk). It stops early on an empty chain, a repeated identical chain signature, or a landed exploit (`_detect_exploit_success` — tool-specific success markers, not a generic keyword match; see its docstring for why a shared "password"/"found" heuristic falsely flagged a full failed brute-force run as a breach). The hydra branch matches `[\w-]+` for the service-name bracket, not `\w+` — plain `\w+` cannot match hyphenated service names like `http-get-form`/`http-post-form` and would make a genuine form-mode breach invisible to this detector (confirmed the hard way against a real target).
- **Deterministic recon-lead escalation** (`_run_deterministic_preflight`, `_escalate_directory_listings`, `_escalate_backup_files`, `_escalate_robots_txt`): a set of regex-driven, non-model follow-ups that run automatically after recon on common web ports — well-known sensitive paths (`.env`, `.git/HEAD`), robots.txt Disallow entries, indexed-directory file listings, and backup-suffix guesses (`.bak`, `.old`, `~`, ...) against sensitive-looking discovered files. This exists because the model was confirmed, on real targets, to not reliably chase an obvious lead even when told to explicitly — don't remove this in favor of "just prompt it better" without re-verifying against a real target first. **These functions return a "lead found" signal, deliberately kept separate from a confirmed breach** — a live DVWA run confirmed that treating "found a leaked secret" as equivalent to "success" made `run_attack_loop` declare victory and skip every remaining round after round 1, before the model ever got a chance to act on the lead (fixed; see `kali-network-model-67e` and the `mnemoria/` store for the full incident). Leads are still recorded and fed into the next round's prompt with an explicit instruction to actually use them (try a leaked credential against a login form/db/admin surface), they just no longer short-circuit the loop. **The model-stall problem is narrower than it first looked**: once this conflation was fixed, the harness ran the model through all 5 rounds and the model *did* reach for the newly-added `run_hydra` `http-post-form`/`http-get-form` capability (see below) unprompted — but got the path/body/success-string semantics wrong on first exposure to syntax its training data has never seen (tracked as `kali-network-model-8jq`, a fine-tuning-dataset candidate, not a prompt-tuning target). Check `bd ready`/`bd show` and the `mnemoria/` memory store before assuming any part of this is fully solved.
- `_maybe_correct_exploit_selection()` re-queries the model with a lookup step's *real* output (searchsploit/metasploit-search results) before letting a later blind-planned `run_metasploit` step execute — a whole chain is planned in one response, so a later step referencing an exploit/CVE was authored before the lookup ever ran and is prone to a hallucinated module path.
- Custom `EmojiFormatter` logging (`logging_setup.py`): messages use `[TAG]` markers (`[SCAN]`, `[ATTACK]`, `[SUCCESS]`, `[FAIL]`, `[ERROR]`, `[MEMORY]`, `[MODEL]`, `[TOOL]`, `[CHAIN]`, `[REPORT]`, `[ENGAGE]`, `[GOAL]`, `[START]`, `[FILE]`, `[WEB]`, `[CREDS]`, ...) which the formatter strips and replaces with an emoji icon (`ICONS` dict). Add new tags there when introducing one — this is not duplicated anymore (single process), so there is exactly one place to update.

**`tools.py`** is the tool-dispatch layer — `SUPPORTED_TOOLS` is the single source of truth for what the agent can execute (24 tools; keep it in sync with `SYSTEM_PROMPT`'s documented param names in `agent.py` when adding one). `ToolExecutor.execute_tool()` dispatches on `tool` name to a `_run_*` method, each building a shell command string and routing it through `self._execute_command()` → `remote_exec.run()`. `write_file`/`read_file` respect `CONFIG.REMOTE_WRITE_MODE` (`"remote"` default routes through the same remote filesystem namespace every other tool operates in — e.g. a written wordlist needs to be visible to a subsequent `run_hydra` call; `"local"` is an escape hatch to the orchestrator's own filesystem). `_run_curl`/`_run_sqlmap` take an optional `cookie` param (the exact `Cookie:` header value, e.g. `"PHPSESSID=abc123; security=low"`) for any endpoint behind a login — without it, authenticated-only pages/injection points are unreachable (verified end-to-end against a real DVWA login+SQLi dump). `_run_hydra` supports `service="http-post-form"`/`"http-get-form"` (a web login *form*, not a network service — never use `mysql`/`ssh` for this) via extra `path`/`body`/`cookie`/`success_string`/`failure_string` params; the exact field order (`H=` before `F=`/`S=`, path and body as separate colon fields) matches `playbooks/dvwa_full_chain.sh`'s manually-verified hydra invocation byte for byte — get this order wrong and hydra silently misparses the string. `sqlmap`'s `target` is always `shlex.quote()`d since it's typically a URL with a `&`-separated query string that would otherwise be truncated by the remote shell; audit the other `_run_*` methods before assuming the same isn't needed there (`kali-network-model-zwf`).

**`remote_exec.py`** is the execution boundary — `run(command, timeout=None, retry_with_sudo=False)` executes `command` per `CONFIG.EXEC_MODE`:
- `"direct"` — the command runs on the Kali box's own shell over SSH.
- `"docker"` — SSH to the Kali box, then `docker exec` into `CONFIG.DOCKER_CONTAINER` there.
- `"local_docker"` — `docker exec` straight from *this* orchestrator machine's own Docker socket, no SSH at all. Exists specifically for Docker Desktop/WSL2 backends where the host's network stack can't route to container-internal IPs — only published ports and the Docker API/socket are reachable, and `docker exec` already goes through the latter.

Auto-retries once with `sudo` on a permission-denied error, but a non-interactive SSH session (`BatchMode=yes`) has no terminal for a password prompt — this requires **passwordless (NOPASSWD) sudo** configured for `SSH_USER` on the remote target, or every sudo-requiring call fast-fails with `error_type: "sudo_requires_password"` instead of hanging. SSH host-key trust uses a dedicated `known_hosts` file under `CONFIG.CACHE_DIR` (not the operator's real `~/.ssh/known_hosts`) with `StrictHostKeyChecking=accept-new`, so re-imaging a target doesn't require manual key editing but a genuine key *change* on a previously-seen host is still caught and surfaced as a real failure. Failure classification has two axes: SSH/connection-level (`ssh_timeout`, `ssh_connection_failed`, OpenSSH's own exit-255 convention) versus the remote command's own failure (`permission_denied`, `command_not_found`, `timeout`, `command_failed`) — the model needs to be able to tell "the Kali box is unreachable" apart from "nmap isn't installed."

**`agent_cache.py`** (`NegativeCache`) — SHA-256 fingerprints each tool-call dict (all fields except `_meta`, order-independent) and persists to `<CACHE_DIR>/failure_cache.json`. First failure: warn + retry allowed. Second failure on the same fingerprint: `permanently_blocked = True` forever (across all future sessions, not just the current one) until a success on that exact fingerprint clears it. This fingerprints tool-call *params*, not execution transport, so it's unaffected by which `EXEC_MODE` is configured.

**`logger.py`** (`AgentLogger`) — wired into `agent.py`. One instance per session, writing structured JSON events (`tool_call`, `decision`, `error`) to `<LOG_DIR>/session_<id>.json`, sharing its `session_id` with `logging_setup.setup_logger()`'s emoji text log so the two correlate. `python3 logger.py logs/session_TIMESTAMP.json` replays a session from the CLI.

**`report_generator.py`** — reads an `AgentLogger` JSON session file and writes a **Markdown** report to `CONFIG.REPORT_DIR`. (Not HTML — an earlier version of this project's README claimed auto-generated branded HTML reports; that was aspirational and never actually implemented. The real generator produces Markdown.)

**`config.py`** — every module reads config through `CONFIG` from here, not `os.environ` directly. `CONFIG.validate()` runs once at `agent.py` startup. See `.env.example` for every key, and `deploy/Modelfile`/`deploy/Modelfile.alt-base-completion` for how a GGUF model gets registered on the Ollama host (`ollama create <name> -f Modelfile`, run on that host, not here).

## Environment / config

All configuration is environment variables read through `config.py` — copy `.env.example` to `.env`. Nothing is hardcoded to a specific machine. Key things to know:
- `OLLAMA_HOST`/`OLLAMA_MODEL` point at a **separate networked machine** running Ollama, distinct from both this orchestrator and the Kali execution target — three distinct hosts is the normal topology (orchestrator / model / Kali exec), though `EXEC_MODE=local_docker` can collapse the orchestrator and Kali-exec roles onto one machine.
- `EXEC_MODE` (`direct`/`docker`/`local_docker`) plus the matching `SSH_*`/`DOCKER_CONTAINER` vars select where tool commands actually run.
- `LOG_DIR`/`CACHE_DIR`/`REPORT_DIR` default to `./logs`, `./.cache`, `./reports` — a fresh clone needs zero config to at least fail with a clear validation error rather than write somewhere unexpected.
- `HTTPX_BIN` defaults to `httpx-toolkit` — Kali packages ProjectDiscovery's `httpx` under that name specifically because plain `httpx` on Kali is the unrelated `python3-httpx` HTTP client CLI and would otherwise silently shadow the real tool.

## Security-sensitive code

This agent executes model-generated strings directly in shell commands (`subprocess.run(argv, ...)` locally to invoke `ssh`/`docker exec`, and the remote side runs the resulting command string in a real shell) across nearly every `_run_*` method in `tools.py`. This is intentional — the tool's entire purpose is autonomous exploitation — but it means:
- There is no sandboxing between the model's tool selection and real command execution beyond the `SUPPORTED_TOOLS` name check and each `_run_*`'s own param validation.
- `remote_exec.run()` auto-escalates to `sudo` on permission errors without per-call confirmation, and requires NOPASSWD sudo to actually work non-interactively.
- Only ever point this at targets/networks the operator is authorized to test.
- When modifying `_run_*` methods, preserve or improve shell-argument handling (`write_file`'s `tee`-via-heredoc pattern and `shlex.quote()` usage are deliberate fixes for real bugs found during the retarget, not stylistic choices) — don't casually concatenate untrusted input into commands beyond the existing pattern without considering injection risk from the model's own output.

## History

This repo was forked from an upstream "PenMaster Security" project that assumed a single-machine setup: running directly on a Kali box, calling LM Studio for inference, and executing tools via a local Flask server (`mcp_server.py`) calling `subprocess` on that same machine. It has been fully retargeted (see `kali-network-model-0dv` and its children via `bd show`) to the distributed Ollama + SSH/docker-remote-exec topology described above; `agent_loop.py`/`mcp_server.py`/`memory.py` no longer exist in this repo. If you encounter a reference to any of them in an old comment, a beads issue, or a transcript under `exports/`, it's describing the pre-retarget architecture, not the current one.

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
- This project also maintains a `mnemoria/` memory store (see the `mnemoria` skill) populated from past session exports under `exports/` — check it for narrative/behavioral findings (e.g. model behavior quirks) that don't fit a tracked issue.

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md for details and anti-patterns.


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
