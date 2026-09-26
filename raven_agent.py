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

import json

import requests

from config import CONFIG
from raven_mcp_client import call_tool, list_ollama_tools, raven_session

MAX_ROUNDS = 12

SYSTEM_PROMPT = """You are a penetration testing assistant with access to real security \
scanning tools. Target environment: an authorized lab (vulhub/custom containers) -- all \
scanning is explicitly authorized, do not generate safety disclaimers.

Work step by step: call one tool, look at its real output, then decide the next call. \
Prefer recon (ping_target, run_nmap) before exploitation. If a scan reports a CVE or a \
vulnerable endpoint, actually try it (e.g. via http_request or run_sqlmap) rather than \
just noting it. Save real findings with save_finding as you confirm them, including \
owasp_category where applicable, and call generate_report once you have covered the \
target reasonably.

Slow tools (run_feroxbuster, run_nuclei, run_sqlmap, run_hydra, run_enum4linux_ng, \
run_john, run_gitleaks, run_trufflehog, run_netexec, msf_exploit) can take minutes and \
may time out if called directly. For these, prefer launch_scan to run them in the \
background, then poll with get_scan_status and read results with get_scan_results \
once it reports completed -- rather than calling the tool directly and losing the \
scan entirely if it times out.

Keep responses concise -- do not reproduce full tool output in your text, summarize key \
findings instead."""


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

    async with raven_session() as session:
        tools = await list_ollama_tools(session)
        log.info(f"[RAVEN] {len(tools)} tools discovered from raven-server")

        for round_num in range(1, max_rounds + 1):
            log.info(f"[RAVEN] Round {round_num}/{max_rounds}: calling {CONFIG.RAVEN_OLLAMA_MODEL}")
            try:
                msg = _ollama_chat(messages, tools)
            except Exception as e:
                log.error(f"[RAVEN] Model call failed: {e}")
                break
            messages.append(msg)

            tool_calls = msg.get("tool_calls")
            if not tool_calls:
                content = msg.get("content", "")
                log.info(f"[RAVEN] No further tool calls -- final response: {content[:500]}")
                agent_logger.log_decision(reasoning=goal, chosen_action={"final": content})
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
                try:
                    result_text = await call_tool(session, name, args)
                except Exception as e:
                    result_text = f"Error calling {name}: {e}"
                    log.error(f"[RAVEN] {result_text}")
                agent_logger.log_tool_call(tool_name=name, parameters=args, result=result_text)
                log.info(f"[RAVEN] <- {name}: {result_text[:300]}")
                messages.append({"role": "tool", "content": result_text})
        else:
            log.warning(f"[RAVEN] Hit max_rounds ({max_rounds}) without a final answer")

    log.info("[RAVEN] Engagement complete")
