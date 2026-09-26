"""MCP client for raven-nest-mcp (github.com/tidynest/raven-nest-mcp),
spawned inside CONFIG.DOCKER_CONTAINER via `docker exec -i` -- reuses the
same execution target every other tool in this repo already runs against,
no new container/topology. See raven_agent.py for the engagement loop that
drives this against Ollama's NATIVE tool-calling API (a different mechanism
from agent.py's grammar-constrained single-shot chain planning -- raven-
nest-mcp's tools are called one at a time, turn by turn, per MCP's own
design; this module is deliberately kept separate from tools.py/agent.py
rather than bolted into them, see kali-network-model-nrk).

Prerequisite (one-time, not automated here): build raven-server on the
orchestrator (`cd ~/raven-nest-mcp && cargo build --release`) and
`docker cp` the binary plus a config.toml into CONFIG.DOCKER_CONTAINER at
CONFIG.RAVEN_BINARY_PATH / CONFIG.RAVEN_CONFIG_PATH.
"""

from contextlib import asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from config import CONFIG


def _server_params():
    return StdioServerParameters(
        command="docker",
        args=[
            "exec", "-i",
            "-e", f"RAVEN_CONFIG={CONFIG.RAVEN_CONFIG_PATH}",
            CONFIG.DOCKER_CONTAINER,
            CONFIG.RAVEN_BINARY_PATH,
        ],
    )


@asynccontextmanager
async def raven_session():
    """One raven-server process per session -- keeps its cookie jar,
    active engagement, and background-scan state alive across every tool
    call in that session (restarting the process would lose all three)."""
    async with stdio_client(_server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def list_ollama_tools(session):
    """Convert raven-nest-mcp's MCP tool list into Ollama's native
    /api/chat `tools` field (OpenAI-style function-calling schema). The
    MCP input_schema is already a draft-2020-12 JSON Schema object --
    confirmed live this needs no translation, it drops straight into
    `function.parameters`."""
    tools = await session.list_tools()
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.input_schema,
            },
        }
        for t in tools.tools
    ]


async def call_tool(session, name, arguments):
    """Call one raven-nest-mcp tool, returning its text content as a
    single string. raven-nest-mcp's own tools always return plain text
    (already includes ANSI-stripped, budget-tracked, structured-parser
    output per its own docs) -- there is no other content type to handle."""
    result = await session.call_tool(name, arguments or {})
    return "\n".join(c.text for c in result.content if hasattr(c, "text"))
