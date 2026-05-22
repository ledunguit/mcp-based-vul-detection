"""Helpers for connecting MCP-Vul to external analyzer servers."""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Any

from .client import MCPClient


def translate_to_container(val: Any, host_root: str) -> Any:
    if isinstance(val, str):
        if val.startswith(host_root):
            return val.replace(host_root, "/workspace", 1)
        return val
    elif isinstance(val, dict):
        return {k: translate_to_container(v, host_root) for k, v in val.items()}
    elif isinstance(val, list):
        return [translate_to_container(v, host_root) for v in val]
    return val


def translate_to_host(val: Any, host_root: str) -> Any:
    if isinstance(val, str):
        if val.startswith("/workspace"):
            return val.replace("/workspace", host_root, 1)
        return val
    elif isinstance(val, dict):
        return {k: translate_to_host(v, host_root) for k, v in val.items()}
    elif isinstance(val, list):
        return [translate_to_host(v, host_root) for v in val]
    return val


class PathMappingMCPClient(MCPClient):
    def __init__(self, host_root: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.host_root = host_root

    def call_tool(self, tool_name: str, arguments: dict) -> Any:
        translated_args = translate_to_container(arguments, self.host_root)
        result = super().call_tool(tool_name, translated_args)
        return translate_to_host(result, self.host_root)

    async def call_tool_async(self, tool_name: str, arguments: dict) -> Any:
        translated_args = translate_to_container(arguments, self.host_root)
        result = await super().call_tool_async(tool_name, translated_args)
        return translate_to_host(result, self.host_root)

    def call_multiple(self, calls: list[tuple[str, dict]]) -> list[Any]:
        translated_calls = [
            (name, translate_to_container(args, self.host_root))
            for name, args in calls
        ]
        results = super().call_multiple(translated_calls)
        return [translate_to_host(res, self.host_root) for res in results]

    async def call_multiple_async(self, calls: list[tuple[str, dict]]) -> list[Any]:
        translated_calls = [
            (name, translate_to_container(args, self.host_root))
            for name, args in calls
        ]
        results = await super().call_multiple_async(translated_calls)
        return [translate_to_host(res, self.host_root) for res in results]


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
    host_root = str(Path(__file__).resolve().parents[3])
    client = PathMappingMCPClient(host_root=host_root, protocol_mode=True)

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

