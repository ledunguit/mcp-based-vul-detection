"""Helpers for connecting MCP-Vul to external analyzer servers."""

from __future__ import annotations

import os
import shlex

from .client import MCPClient


def build_remote_client_from_env() -> MCPClient:
    """
    Create a protocol-mode MCP client and connect any external servers declared
    in environment variables.

    Supported variables:

    - `MCP_STATIC_SERVER_URL`
    - `MCP_STATIC_SERVER_CMD`
    - `MCP_STATIC_SERVER_CWD`
    - `MCP_STATIC_SERVER_PYTHONPATH`
    - `MCP_DYNAMIC_SERVER_URL`
    - `MCP_DYNAMIC_SERVER_CMD`
    - `MCP_DYNAMIC_SERVER_CWD`
    - `MCP_DYNAMIC_SERVER_PYTHONPATH`
    """
    client = MCPClient(protocol_mode=True)

    static_url = os.getenv("MCP_STATIC_SERVER_URL", "").strip()
    static_cmd = os.getenv("MCP_STATIC_SERVER_CMD", "").strip()
    dynamic_url = os.getenv("MCP_DYNAMIC_SERVER_URL", "").strip()
    dynamic_cmd = os.getenv("MCP_DYNAMIC_SERVER_CMD", "").strip()

    if static_url:
        client.connect_http("static", static_url)
    elif static_cmd:
        client.connect_subprocess(
            "static",
            shlex.split(static_cmd),
            env=_build_server_env("MCP_STATIC_SERVER_PYTHONPATH"),
            cwd=os.getenv("MCP_STATIC_SERVER_CWD") or None,
        )
    if dynamic_url:
        client.connect_http("dynamic", dynamic_url)
    elif dynamic_cmd:
        client.connect_subprocess(
            "dynamic",
            shlex.split(dynamic_cmd),
            env=_build_server_env("MCP_DYNAMIC_SERVER_PYTHONPATH"),
            cwd=os.getenv("MCP_DYNAMIC_SERVER_CWD") or None,
        )

    return client


def _build_server_env(pythonpath_var: str) -> dict[str, str] | None:
    pythonpath = os.getenv(pythonpath_var, "").strip()
    if not pythonpath:
        return None

    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "").strip()
    env["PYTHONPATH"] = (
        pythonpath if not existing else os.pathsep.join([pythonpath, existing])
    )
    return env
