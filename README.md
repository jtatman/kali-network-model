<img width="1200" height="783" alt="Final_EDIT" src="https://github.com/user-attachments/assets/fe9aafc5-294b-43f5-b20f-4ff1305bf0d8" />

-----

# 🔐 PenMaster Security (kali-network-model fork)

**Autonomous AI-powered penetration testing agent — local model, no API keys, no cloud inference.**

A single Python orchestrator (`agent.py`) talks to an LLM served by [Ollama](https://ollama.com) on a networked host, decides what to run based on the model's structured JSON response, and executes real Kali Linux tools against a separate target host over SSH (or `docker exec`). It runs recon, drives an adaptive attack loop, and writes a Markdown pentest report at session end.

This is a customized fork of the original single-machine PenMaster Security project (see **Credit & License** below) — it has been retargeted from a same-box LM Studio + local Flask tool server into a three-role distributed lab setup. It is not being maintained as a general-purpose public project; treat it as a personal/lab tool you run against infrastructure you own or are explicitly authorized to test.

-----

## Scope & Authorization

**Only ever point this at systems you own or have explicit written authorization to test.** This agent runs unattended, with no per-call confirmation, and will attempt real exploitation (credential brute force, RCE, SQL injection, etc.) against whatever target it's given. It has no allowlist beyond the tool names it knows how to call — there is no sandboxing between the model's tool choice and real command execution on the target. Misuse against systems you don't control is illegal in most jurisdictions. This project is intended for isolated lab environments and authorized engagements (e.g. local honeypot/container targets on a network you control) — not for scanning or attacking arbitrary hosts on the internet.

If you find a security issue in the *agent's own code* (as opposed to a finding it produces about a target), open an issue or contact the maintainer directly — there's no formal disclosure program here, this is a personal fork.

-----

## Architecture

```
agent.py  (REPL: engage <target> / recon <target> / freeform goal / exit)
     │
     ├──► Ollama  (separate networked host, native /api/chat,
     │     JSON-schema-constrained tool-chain output)
     │
     ├──► tools.py  (ToolExecutor — dispatches "tool" name to a
     │     _run_* method that builds a real shell command string)
     │         │
     │         └──► remote_exec.py  (SSH "direct" / SSH+"docker" /
     │               "local_docker" via this machine's own docker exec)
     │                     │
     │                     └──► Kali Linux tools on the remote target
     │
     ├──► agent_cache.py   (persistent cross-session negative-experience cache)
     ├──► logger.py        (structured JSON session log)
     └──► report_generator.py  (Markdown pentest report on exit)
```

Three logical roles, three machines by default (can be collapsed — see **Setup**):
1. **Orchestrator** (this repo) — talks to the model, parses tool calls, drives recon/attack logic, writes logs and reports.
2. **Model host** — runs Ollama, serving a quantized GGUF model registered via a checked-in `deploy/Modelfile`.
3. **Kali execution target** — a real or containerized Kali Linux box where the actual scanning/exploitation tools run, reached over SSH.

-----

## What It Does

- 🔍 Autonomous recon — nmap-driven port/service discovery, optionally scoped to an explicit port list
- ⚔️ Adaptive attack loop — re-plans against a port for up to 5 rounds, feeding the model its own prior real tool output instead of single-shot planning
- 🔗 Deterministic recon-lead escalation — automatically follows up on `.env`/`.git` exposure, `robots.txt` Disallow entries, indexed directory listings, and backup-file guesses (`.bak`/`.old`/`~`) without waiting on the model to notice them
- 🧠 Persistent negative-experience cache — learns which exact tool calls fail across ALL sessions (fail twice, permanently blacklisted) and never wastes time on them again
- 📝 Auto-generates a Markdown pentest report from a structured JSON session log on exit (Ctrl+C or `exit`)
- 🔒 No cloud inference and no API keys — the model runs locally on your own network via Ollama

-----

## Tool Arsenal (25 tools)

Source of truth: `SUPPORTED_TOOLS` in `tools.py`.

| Tool               | Purpose                                   |
|--------------------|--------------------------------------------|
| `run_masscan`      | Fast port discovery                        |
| `run_nmap`         | Deep service/version scanning              |
| `run_naabu`        | Fast port discovery, piped into `run_nuclei`/`run_command` |
| `run_netstat`      | Local socket state (falls back to `ss`)    |
| `run_nikto`        | Web vulnerability scanning                 |
| `run_gobuster`     | Web directory/file brute forcing           |
| `run_ffuf`         | Fast web fuzzing                           |
| `run_nuclei`       | Template-based vulnerability scanning      |
| `run_katana`       | Web crawling                               |
| `run_httpx`        | HTTP probing / tech fingerprinting         |
| `run_subfinder`    | Subdomain enumeration                      |
| `run_enum4linux`   | SMB/Samba enumeration                      |
| `run_sqlmap`       | SQL injection testing (`cookie` param for session-gated pages) |
| `run_hydra`        | Credential brute forcing (`service="http-post-form"`/`"http-get-form"` for web login forms) |
| `run_medusa`       | Fast parallel credential brute forcing     |
| `run_ncrack`       | Network authentication cracking            |
| `run_john`         | Hash cracking                              |
| `run_searchsploit`| Exploit lookup (offline exploit-db)        |
| `run_metasploit`   | Framework exploitation (raw `msfconsole` commands) |
| `run_setoolkit`    | Social engineering attacks                 |
| `run_curl`         | Arbitrary HTTP requests                    |
| `run_wget`         | File retrieval                             |
| `run_command`      | Execute any shell command                  |
| `write_file`       | Write a file (remote or local, see `.env`) |
| `read_file`        | Read a file (remote or local, see `.env`)  |

-----

## Sovereign Agent Layer v1 — Negative Experience Cache

`agent_cache.py`'s `NegativeCache` fingerprints every tool call (tool + params, order-independent). Fail once — warn and allow a retry. Fail the *same* fingerprint twice — permanently blacklisted, across every future session, until a success on that exact fingerprint clears it. The agent never wastes cycles re-running an attack it has already proven doesn't work.

-----

## Setup

### Prerequisites

- **Orchestrator machine** (runs this repo): Python 3.8+, `ssh`/`docker` CLIs on `PATH` as needed for your `EXEC_MODE`.
- **Model host**: [Ollama](https://ollama.com) installed, reachable over the network, with enough VRAM to run your chosen GGUF quantization (a small local machine without a real GPU will not be enough — run Ollama on a separate box with a real GPU).
- **Kali execution target**: a Kali Linux box or container with the tools above installed, reachable over SSH (directly, or via a host that can `docker exec` into it).

### 1. Register a model on the Ollama host

This repo ships a Modelfile template, not a model — build and register it **on the Ollama host itself**:

```bash
scp your-model.gguf ollama-host:/path/to/models/
# on the Ollama host, after editing the FROM path in deploy/Modelfile:
ollama create pentest-agent -f deploy/Modelfile
```

`deploy/Modelfile` documents why **BaronLLM** (`AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF`, an offensive-security fine-tune of Llama-3.1-8B-Instruct) is the recommended base: it has a correctly embedded chat template and instruct EOS token, and in empirical A/B testing through this agent's real Ollama pipeline it followed structured tool-call parameter naming far more reliably than other "kali-pentester" community fine-tunes built from a raw base checkpoint (which need the alternate `deploy/Modelfile.alt-base-completion` template and, even then, tend to emit generic `param1`/`param2` keys instead of real ones). `temperature 0.3` matches BaronLLM's own model-card recommendation for deterministic reasoning tasks while leaving enough room to switch tools when a chain stalls. Check any new GGUF's embedded template with `gguf_dump.py --no-tensors <file>` before assuming either Modelfile profile applies.

### 2. Prepare the Kali execution target

Whatever box or container runs the tools needs, beyond a base Kali install:
- `seclists`, `medusa`, `subfinder`, `nuclei`, `katana`, and `httpx-toolkit` (ProjectDiscovery's httpx is packaged under this name on Kali — plain `httpx` is an unrelated Python HTTP client CLI and will silently shadow the real tool if you override `HTTPX_BIN`).
- `/usr/share/wordlists/rockyou.txt` actually unpacked (`gunzip` it — it ships gzipped on Kali).
- `nuclei -update-templates` run at least once.
- If it's a **container**: `--cap-add=NET_RAW --cap-add=NET_ADMIN` at container-run time — nmap needs these capabilities even running as root inside the container. If you provision it interactively, `docker commit` the container afterward or your changes vanish on restart/recreation.
- **NOPASSWD sudo** for the SSH user (or run as root) — the agent's auto-sudo-retry uses a non-interactive SSH session (`BatchMode=yes`), which has no terminal for a password prompt and will fast-fail instead of hanging if this isn't configured.
- A reachable `sshd`. If your Kali target is a container behind Docker Desktop/WSL2, note that the orchestrator's network stack generally cannot route to the container's bridge-network IP directly — either publish the container's SSH port and use `EXEC_MODE=direct` against the host+published-port, or use `EXEC_MODE=local_docker` if the orchestrator itself has access to the same Docker daemon.

### 3. Configure and run

```bash
cp .env.example .env   # edit: OLLAMA_HOST, OLLAMA_MODEL, EXEC_MODE, SSH_*/DOCKER_CONTAINER
python3 agent.py
```

`config.py` validates required settings at startup and fails fast with a specific message if something's missing — see `.env.example` for every key and what each `EXEC_MODE` needs.

-----

## Usage

```bash
python3 agent.py

>>> engage 10.0.0.5              # full autonomous recon + attack across all ports
>>> engage 10.0.0.5 21,80,3306   # restrict recon to an explicit port list
>>> run nmap on 10.0.0.5         # single freeform goal, one model-planned chain
>>> exit                         # closes the session log, writes a Markdown report
```

-----

## Stack

- **Model**: a quantized GGUF model registered on a networked Ollama host (BaronLLM recommended — see Setup)
- **Orchestrator**: Python, single process (`agent.py`), no web framework
- **Tool execution**: Kali Linux, real or containerized, reached over SSH / `docker exec`
- **Inference**: 100% on infrastructure you control — no cloud API calls, no API keys

-----

## Project Status

Actively being adapted for this environment — see `bd ready` / `bd show <id>` for tracked work (this repo uses [beads](https://github.com/gastownhall/beads) for issue tracking) and the `mnemoria/` memory store for narrative findings from past sessions (model-behavior quirks, infra gotchas) that don't fit a tracked issue.

The "model stalls in enumeration" problem turned out to be partly a harness bug: the deterministic recon-escalation logic was treating any leaked-secret discovery as a confirmed breach and skipping the rest of the attack loop before the model (or anything else) ever tried to use the lead — fixed and verified against a live target. Web-login-form brute force (`run_hydra` with `service="http-post-form"`/`"http-get-form"`) and authenticated-session support (`cookie` on `run_curl`/`run_sqlmap`) are now implemented and verified end-to-end against a real DVWA target (login → session cookie → SQLi dump; login-form brute force finding the real credential). What remains is narrower: the model reaches for these newly-added capabilities once documented, but gets their (fork-specific, never-seen-in-training) parameter syntax wrong on first exposure — the concrete motivation for the planned `qwen3:4b` fine-tune mentioned in `mnemoria/`, rather than something more prompt-tuning is expected to fix.

-----

## Credit & License

Forked from the original PenMaster Security project. All original tool-integration logic, prompt design, and the negative-experience-cache concept trace back to that upstream work; this fork's changes are the Ollama/SSH-remote-exec retarget, the deterministic recon-escalation logic, and the accompanying documentation.

MIT — see `LICENSE`.
