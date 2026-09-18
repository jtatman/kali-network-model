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
`--filter SUBSTRING`, `--verified-only`, `--shuffle`, `--out PATH`. The
`--out`/`--shuffle` pair is the farming mechanism: point a different
machine's `.env` at its own Kali target, run
`pipeline_chain_builder.py --shuffle --out machineN_output.jsonl` there
independently, copy the output file back, then run
`scripts/merge_pipeline_chain_outputs.py machineN_output.jsonl [...]`
once to dedupe everything into the canonical
`pipeline_chains_generated.jsonl` — no need to labor over every step in
one session when the same candidate list can run unattended on multiple
machines in parallel.

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

## Known gaps

- **Severe tool-usage imbalance, confirmed by a live evaluation pass this
  session.** `run_command` accounts for 1012/1192 chain steps (85%);
  `run_nmap` is next at 110; everything else is single digits. 9 of the 25
  `SUPPORTED_TOOLS` have zero *structured* examples (`run_masscan`,
  `run_naabu`, `run_netstat`, `run_nikto`, `read_file`, `run_ncrack`,
  `run_medusa`, `run_setoolkit`, `run_katana`), and 4 of those
  (`run_netstat`, `run_ncrack`, `run_medusa`, `run_katana`) have **zero
  representation anywhere**, including as raw `run_command` text. A
  fine-tune on this corpus as-is won't see real examples of those tools.
  Still true after this pass — the new templates use structured
  `run_gobuster`/`run_hydra`/`run_sqlmap` calls where they're gated behind
  `stage_2`/the override (not yet run live), but everything that's
  actually landed in the corpus so far is still `run_command` shell pipes
  (masscan/naabu/httpx/nuclei/nmap chains). Prioritize `run_netstat`/
  `run_ncrack`/`run_medusa`/`run_katana` specifically when adding new
  templates.
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
