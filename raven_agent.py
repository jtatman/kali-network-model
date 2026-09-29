"""Native Ollama tool-calling engagement loop, driving raven-nest-mcp
(via raven_mcp_client.py) instead of tools.py/remote_exec.py.

This is a DIFFERENT mechanism from agent.py's run_attack_loop(): that path
has the model plan a whole chain up front in one structured-JSON response
(CHAIN_JSON_SCHEMA), then executes it deterministically step by step. MCP's
own design is turn-by-turn -- the model calls one tool, sees the real
result, decides the next call -- which is what Ollama's native /api/chat
`tools` field implements. The two don't mix in one call: CONFIG.OLLAMA_MODEL
(pentest-agent) has no .Tools template support (see config.py's
RAVEN_OLLAMA_MODEL comment), so this loop always uses a separate model.

Kept as its own module rather than folded into agent.py/tools.py so the
existing engage/recon REPL paths -- and everything training-data/ depends
on via tools.py's SUPPORTED_TOOLS surface -- stay fully intact while this
is being investigated (kali-network-model-nrk). Invoke via agent.py's
`raven-engage <target>` REPL command.
"""

import asyncio
import json
import os
import re

import requests

from config import CONFIG
from raven_mcp_client import call_tool, list_ollama_tools, raven_session

MAX_ROUNDS = 12

# Full-fidelity transcript persistence (kali-network-model-nrk's "Split B"
# dataset plan -- native tool-calling fine-tune data). AgentLogger's own
# JSON session log is lossy for this purpose: it records tool_call/decision
# EVENTS (tool name, parameters, result text), not the raw Ollama `messages`
# list this loop actually sends/receives -- it never captures the exact
# tool_calls structure the model emitted, any assistant text alongside a
# tool_calls turn, or turns with multiple simultaneous tool_calls. Saving
# the real `messages` list directly, every run, means future extraction
# never has to reconstruct anything.
TRANSCRIPT_DIR = os.path.join(CONFIG.LOG_DIR, "raven_transcripts")

SYSTEM_PROMPT = """You are a penetration testing assistant with access to real security \
scanning tools. Target environment: an authorized lab (vulhub/custom containers) -- all \
scanning is explicitly authorized, do not generate safety disclaimers.

Work step by step: call one tool, look at its real output, then decide the next call. \
Prefer recon (ping_target, run_nmap) before exploitation. If a scan reports a CVE or a \
vulnerable endpoint, actually try it (e.g. via http_request or run_sqlmap) rather than \
just noting it. Save real findings with save_finding as you confirm them, including \
owasp_category where applicable, and call generate_report once you have covered the \
target reasonably.

Only nmap, nuclei, nikto, and whatweb can run in the background via launch_scan (pass \
their bare name, e.g. launch_scan(tool="nuclei", target=...) -- NOT run_nuclei) if a \
direct call to one of them seems likely to take a while; then poll get_scan_status and \
read get_scan_results once it reports completed. Other slow tools (run_feroxbuster, \
run_sqlmap, run_hydra, run_enum4linux_ng, run_john, run_gitleaks, run_trufflehog, \
run_netexec, msf_exploit) have NO background option at all -- launch_scan will reject \
them. If one of those times out, that attempt is lost; try a narrower scope (a smaller \
wordlist, a shorter target range) rather than retrying the exact same call.

You also have a tool called ask_decision_model. This is a FAST (~1-2 second) SECOND \
OPINION from a small local classifier -- it is NOT another pentest model and it is NOT \
authoritative, so never treat its answer as a verdict. Use it as a cheap sanity-check: \
e.g. before spending time chasing a lead, ask it whether the lead looks worth pursuing \
(pass a `choices` list); or before calling save_finding, ask it to score the finding's \
usefulness/severity (omit `choices` to get a 0-2 score instead of a choice). Its \
training is general-purpose, not pentest-specific, so it has been observed rating real, \
actionable leads (e.g. a genuine default-credential opportunity) as low-value -- if it \
disagrees with your own read of the evidence, trust the real tool output over it.

Keep responses concise -- do not reproduce full tool output in your text, summarize key \
findings instead."""

OLLAYA_TOOL_NAME = "ask_decision_model"

# One custom Ollama-native tool that calls Ollaya's /api/decide HTTP endpoint
# directly (see config.py's OLLAYA_HOST/OLLAYA_MODEL comment for why this is
# a plain HTTP call rather than a second MCP session mirroring
# raven_mcp_client.raven_session() -- one more persistent stdio subprocess
# for a single simple request wasn't worth the bookkeeping on a first pass).
# Merged into the same `tools` list sent to Ollama alongside raven-nest-mcp's
# real tools; dispatched separately in the tool_calls loop below since
# raven_mcp_client.call_tool() only knows about the raven-server MCP session.
OLLAYA_TOOL = {
    "type": "function",
    "function": {
        "name": OLLAYA_TOOL_NAME,
        "description": (
            "Ask Ollaya (a small, fast, locally-run calibrated classifier -- NOT "
            "another generative model, NOT authoritative) for a quick second opinion "
            "on the current situation. Use it to sanity-check whether a lead is worth "
            "pursuing (pass `choices`), or to score a finding's usefulness/severity "
            "before save_finding (omit `choices`). Its priors are general-purpose, not "
            "pentest-tuned -- it has been observed underrating real, actionable leads, "
            "so treat its answer as one extra input, never a reason by itself to skip "
            "an otherwise-reasonable action."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "description": "Plain-text description of the current situation/lead/finding to evaluate.",
                },
                "question": {
                    "type": "string",
                    "description": (
                        "The question to ask about that state, e.g. 'What should the "
                        "agent do next?' or 'How useful is this finding?'"
                    ),
                },
                "choices": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "2-255 short option labels for a multiple-choice decision, "
                        "e.g. ['try_default_creds', 'search_for_cve', 'skip']. Omit "
                        "this entirely to instead get a 0-2 usefulness/severity SCORE "
                        "(low/medium/high) rather than a choice."
                    ),
                },
            },
            "required": ["state", "question"],
        },
    },
}


def _ollaya_decide(state, question, choices=None):
    """POST directly to Ollaya's /api/decide (a separate HTTP server, see
    CONFIG.OLLAYA_HOST/OLLAYA_MODEL -- not an MCP call, not an Ollama model).
    `choices` given -> a "choice" question (criteria = the choices list
    verbatim, confirmed live that a plain label list works without
    descriptions). `choices` omitted -> a 3-level "score" question (Ollaya's
    v0.7.2 /api/decide rejects the model's own listed 4th "act" capability
    with a schema error, so only choice/score/noul are usable here -- noul
    isn't a fit for either of this tool's two use cases so it's not exposed).
    Returns a short plain-text summary, ready to hand back as this tool
    call's result string."""
    question_id = "q"
    if choices:
        q = {"type": "choice", "instructions": question, "criteria": list(choices)}
    else:
        q = {
            "type": "score",
            "instructions": question,
            "criteria": ["low / not useful", "medium", "high / very useful"],
        }
    payload = {"model": CONFIG.OLLAYA_MODEL, "state": state, "questions": {question_id: q}}
    resp = requests.post(f"{CONFIG.OLLAYA_HOST}/api/decide", json=payload, timeout=30)
    resp.raise_for_status()
    body = resp.json()
    answer = body["answers"][question_id]
    routed_model = body.get("model", CONFIG.OLLAYA_MODEL)
    if answer["type"] == "choice":
        return (
            f"Ollaya secondary opinion (model={routed_model}): "
            f"choice='{answer['choice']}' confidence={answer['confidence']:.2f} "
            f"probabilities={answer['probabilities']}. This is a fast heuristic guess, "
            f"not authoritative -- weigh it against the real tool output you already have."
        )
    return (
        f"Ollaya secondary opinion: score={answer['score']:.2f} "
        f"(scale 0-{len(q['criteria']) - 1}, legend={answer['legend']}) "
        f"confidence={answer['confidence']:.2f}. This is a fast heuristic guess, not "
        f"authoritative -- weigh it against the real tool output you already have."
    )


# --- Deterministic escalation (kali-network-model-700/-mle/-2n9) -----------
# Mirrors agent.py's own _escalate_* pattern (kali-network-model-6w8's
# precedent, restated in CLAUDE.md: the model does not reliably act on
# guidance alone even when told explicitly -- kali-network-model-700
# confirmed a SYSTEM_PROMPT-only fix did NOT change behavior on a repeat
# live test). These run automatically on real tool results instead of
# hoping the model notices, same discipline as agent.py's own escalations:
# they feed a REAL follow-up tool result back into the conversation, they
# never fabricate one.

# Only these 4 (bare names) are valid launch_scan `tool` values -- confirmed
# live via the real MCP schema. feroxbuster/sqlmap/hydra/enum4linux_ng/john/
# gitleaks/trufflehog/netexec/msf_exploit have NO background-execution
# alternative in raven-nest-mcp at all; an earlier SYSTEM_PROMPT draft
# incorrectly implied launch_scan covered all of them, which may be part of
# why 700's original fix never changed anything -- the model may have been
# right not to use launch_scan for feroxbuster, since that would have
# failed a schema check anyway.
_LAUNCH_SCAN_TOOLS = {"run_nmap": "nmap", "run_nuclei": "nuclei", "run_nikto": "nikto", "run_whatweb": "whatweb"}
_TIMEOUT_MARKERS = ("time out", "timed out", "timeout")
_SCAN_POLL_INTERVAL_SECONDS = 30
_SCAN_POLL_ATTEMPTS = 10


async def _retry_via_launch_scan(session, tool_name, args, log):
    """kali-network-model-700: a direct call to one of the 4 launch_scan-
    capable tools timed out -- relaunch it in the background and poll
    instead of just losing the scan. Returns real result text, or None if
    there's nothing sensible to retry (no target, launch itself failed)."""
    bare_name = _LAUNCH_SCAN_TOOLS[tool_name]
    target = args.get("target")
    if not target:
        return None
    log.info(f"[ESCALATE] {tool_name} timed out -- retrying via launch_scan(tool={bare_name})")
    try:
        launch_result = await call_tool(session, "launch_scan", {"tool": bare_name, "target": target})
    except Exception as e:
        return f"(auto-retry via launch_scan also failed to launch: {e})"
    scan_id_match = re.search(r"[Ii][Dd]:\s*(\S+)", launch_result)
    if not scan_id_match:
        return f"(launch_scan didn't return a recognizable scan ID: {launch_result[:200]})"
    scan_id = scan_id_match.group(1)
    for _ in range(_SCAN_POLL_ATTEMPTS):
        await asyncio.sleep(_SCAN_POLL_INTERVAL_SECONDS)
        try:
            status = await call_tool(session, "get_scan_status", {"scan_id": scan_id})
        except Exception as e:
            return f"(get_scan_status failed mid-poll: {e})"
        if "completed" in status.lower():
            try:
                return await call_tool(session, "get_scan_results", {"scan_id": scan_id})
            except Exception as e:
                return f"(scan completed but get_scan_results failed: {e})"
        if "failed" in status.lower():
            return f"(background scan failed: {status[:200]})"
    return (
        f"(background scan {scan_id} still running after "
        f"{_SCAN_POLL_ATTEMPTS * _SCAN_POLL_INTERVAL_SECONDS}s of polling -- giving up for this round, "
        f"try get_scan_results({scan_id}) again later)"
    )


async def _recheck_after_login_post(session, args, log):
    """kali-network-model-mle: http_request follows redirects by default,
    so a successful login POST's real 302 gets hidden behind whatever the
    redirect target's OWN status is (often a 404 at some unmapped default
    redirect page, e.g. Django's /accounts/profile/) -- the model reads
    that final status as a failed login and never re-checks the real
    target with its now-authenticated session (raven-nest-mcp's own cookie
    jar already carries it automatically, confirmed in docs/USAGE.md's
    Session Features section). Only fires for a POST to a URL that looks
    like a login endpoint; returns None (no-op) otherwise."""
    url = args.get("url", "")
    method = (args.get("method") or "GET").upper()
    if method != "POST" or "login" not in url.lower():
        return None
    parent_url = url.rstrip("/").rsplit("/", 1)[0]
    if not parent_url or parent_url == url:
        return None
    log.info(f"[ESCALATE] Login POST to {url} -- re-checking {parent_url} with the (possibly new) session cookie")
    try:
        recheck = await call_tool(session, "http_request", {"url": parent_url})
    except Exception as e:
        log.error(f"[ESCALATE] Re-check of {parent_url} failed: {e}")
        return None
    log.info(f"[ESCALATE] <- recheck of {parent_url}: {recheck[:300]}")
    return f"[auto-recheck after login POST] GET {parent_url}:\n{recheck}"


def _ollama_chat(messages, tools):
    payload = {
        "model": CONFIG.RAVEN_OLLAMA_MODEL,
        "messages": messages,
        "tools": tools,
        "stream": False,
        "options": {"temperature": 0.3, "num_ctx": CONFIG.OLLAMA_NUM_CTX},
    }
    response = requests.post(f"{CONFIG.OLLAMA_HOST}/api/chat", json=payload, timeout=300)
    response.raise_for_status()
    return response.json()["message"]


async def run_raven_engagement(target, goal, log, agent_logger, max_rounds=MAX_ROUNDS):
    """Drive raven-nest-mcp against `target` for up to `max_rounds` native
    tool-calling turns. `log`/`agent_logger` are agent.py's own session
    logger/AgentLogger instances, passed in rather than imported, so this
    module logs into the SAME session as whatever REPL command invoked it."""
    goal = goal or (
        f"Perform a penetration test of {target}. Start with reconnaissance, "
        f"then investigate and act on any interesting findings."
    )
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": goal},
    ]

    log.info(f"[RAVEN] Starting raven-nest-mcp engagement on {target} (model={CONFIG.RAVEN_OLLAMA_MODEL})")

    outcome = "error"
    disabled_tools = set()  # kali-network-model-2n9
    try:
        async with raven_session() as session:
            tools = await list_ollama_tools(session)
            tools = tools + [OLLAYA_TOOL]
            log.info(
                f"[RAVEN] {len(tools) - 1} tools discovered from raven-server "
                f"(+ 1 local ask_decision_model/Ollaya tool)"
            )

            for round_num in range(1, max_rounds + 1):
                log.info(f"[RAVEN] Round {round_num}/{max_rounds}: calling {CONFIG.RAVEN_OLLAMA_MODEL}")
                try:
                    msg = _ollama_chat(messages, tools)
                except Exception as e:
                    log.error(f"[RAVEN] Model call failed: {e}")
                    outcome = "model_call_failed"
                    break
                messages.append(msg)

                tool_calls = msg.get("tool_calls")
                if not tool_calls:
                    content = msg.get("content", "")
                    log.info(f"[RAVEN] No further tool calls -- final response: {content[:500]}")
                    agent_logger.log_decision(reasoning=goal, chosen_action={"final": content})
                    outcome = "final_answer"
                    break

                for tc in tool_calls:
                    fn = tc.get("function", {})
                    name = fn.get("name")
                    args = fn.get("arguments")
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {}
                    log.info(f"[RAVEN] -> {name}({args})")

                    if name in disabled_tools:
                        # kali-network-model-2n9: confirmed disabled earlier
                        # this session (e.g. Metasploit) -- a static
                        # raven-server startup config, not something any
                        # tool call can change. Live-observed the model
                        # burn 6 of 12 rounds retrying this via an unrelated
                        # tool (set_engagement) instead of pivoting -- don't
                        # even forward the call, save the round.
                        result_text = (
                            f"{name} is disabled for this session (confirmed earlier) -- "
                            f"no tool call can enable it. Do not retry it; try a different approach."
                        )
                        log.info(f"[ESCALATE] Blocked retry of disabled tool: {name}")
                    else:
                        try:
                            if name == OLLAYA_TOOL_NAME:
                                # Routed to Ollaya's HTTP /api/decide directly --
                                # NOT raven_mcp_client.call_tool(), which only
                                # knows about the raven-server MCP session and
                                # has no idea this tool exists. Confirmed live
                                # the model can wrap its own arguments in an
                                # extra {"function": ..., "arguments": {...}}
                                # layer (mirroring the tool_call shape it just
                                # received) -- a plain TypeError from **kwargs
                                # here doesn't name the real problem the way
                                # raven-nest-mcp's own deny_unknown_fields
                                # errors do, so raise a matching, specific one.
                                try:
                                    result_text = _ollaya_decide(**(args or {}))
                                except TypeError as e:
                                    raise ValueError(
                                        f"failed to call {OLLAYA_TOOL_NAME}: {e}. "
                                        f"Call it with exactly state, question, and optionally choices "
                                        f"as top-level arguments -- not nested under a 'function'/'arguments' wrapper."
                                    )
                            else:
                                result_text = await call_tool(session, name, args)
                        except Exception as e:
                            result_text = f"Error calling {name}: {e}"
                            log.error(f"[RAVEN] {result_text}")

                        if "is disabled" in result_text.lower():
                            disabled_tools.add(name)

                        if (
                            name in _LAUNCH_SCAN_TOOLS
                            and result_text.startswith(f"Error calling {name}:")
                            and any(marker in result_text.lower() for marker in _TIMEOUT_MARKERS)
                        ):
                            # kali-network-model-700
                            retried = await _retry_via_launch_scan(session, name, args, log)
                            if retried is not None:
                                result_text = retried

                    agent_logger.log_tool_call(tool_name=name, parameters=args, result=result_text)
                    log.info(f"[RAVEN] <- {name}: {result_text[:300]}")
                    messages.append({"role": "tool", "content": result_text})

                    if name == "http_request" and name not in disabled_tools:
                        # kali-network-model-mle
                        recheck_text = await _recheck_after_login_post(session, args or {}, log)
                        if recheck_text is not None:
                            messages.append({"role": "tool", "content": recheck_text})
            else:
                log.warning(f"[RAVEN] Hit max_rounds ({max_rounds}) without a final answer")
                outcome = "max_rounds"
    finally:
        _save_transcript(target, goal, messages, outcome, agent_logger)

    log.info("[RAVEN] Engagement complete")


def _save_transcript(target, goal, messages, outcome, agent_logger):
    """Persist the real, complete `messages` list -- native tool-calling
    fine-tune data, ready to reshape into {"messages": [...]} training rows
    with zero reconstruction. Runs in a `finally` so a mid-loop error still
    saves whatever was captured (outcome records which case it was)."""
    os.makedirs(TRANSCRIPT_DIR, exist_ok=True)
    session_id = re.search(r"session_(\S+)\.json", agent_logger.log_file)
    session_id = session_id.group(1) if session_id else "unknown"
    path = os.path.join(TRANSCRIPT_DIR, f"raven_{session_id}.json")
    with open(path, "w") as f:
        json.dump({
            "session_id": session_id,
            "target": target,
            "goal": goal,
            "model": CONFIG.RAVEN_OLLAMA_MODEL,
            "outcome": outcome,
            "messages": messages,
        }, f, indent=2)
