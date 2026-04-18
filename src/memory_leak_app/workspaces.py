from __future__ import annotations

import os
from pathlib import Path
from typing import Any


C_CPP_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
EXCLUDED_DIRS = {".git", "build", "dist", "node_modules", "__pycache__", ".venv", "venv"}


class WorkspaceService:
    def __init__(self, allowed_roots: list[str] | None = None):
        self.allowed_roots = [path.resolve() for path in self._load_allowed_roots(allowed_roots)]

    def list_workspaces(self) -> dict[str, Any]:
        workspaces = []
        for root in self.allowed_roots:
            if not root.exists() or not root.is_dir():
                continue
            candidates = [root]
            candidates.extend(path for path in sorted(root.iterdir()) if path.is_dir() and path.name not in EXCLUDED_DIRS)
            for candidate in candidates:
                metadata = self.inspect_workspace(str(candidate), raise_on_invalid=False)
                if metadata.get("valid"):
                    workspaces.append(metadata)
        return {
            "allowed_roots": [str(path) for path in self.allowed_roots],
            "workspaces": workspaces,
        }

    def inspect_workspace(self, path: str, raise_on_invalid: bool = True) -> dict[str, Any]:
        workspace = Path(path).expanduser().resolve()
        valid = workspace.exists() and workspace.is_dir() and self.is_allowed(workspace)
        if not valid:
            if raise_on_invalid:
                raise ValueError(f"Workspace is not allowed or does not exist: {workspace}")
            return {
                "path": str(workspace),
                "name": workspace.name,
                "valid": False,
                "c_cpp_file_count": 0,
            }

        files = self._collect_c_cpp_files(workspace)
        return {
            "path": str(workspace),
            "name": workspace.name,
            "valid": True,
            "c_cpp_file_count": len(files),
            "sample_files": [str(path) for path in files[:20]],
        }

    def is_allowed(self, path: Path) -> bool:
        path = path.resolve()
        for root in self.allowed_roots:
            try:
                path.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    def _collect_c_cpp_files(self, workspace: Path, limit: int = 5000) -> list[Path]:
        files = []
        for path in workspace.rglob("*"):
            if len(files) >= limit:
                break
            if any(part in EXCLUDED_DIRS for part in path.parts):
                continue
            if path.is_file() and path.suffix.lower() in C_CPP_EXTENSIONS:
                files.append(path)
        return sorted(files)

    def _load_allowed_roots(self, configured: list[str] | None) -> list[Path]:
        if configured:
            return [Path(path).expanduser() for path in configured]

        env_value = os.getenv("MEMORY_LEAK_APP_WORKSPACE_ROOTS", "").strip()
        if env_value:
            return [Path(path).expanduser() for path in env_value.split(os.pathsep) if path.strip()]

        thesis_root = Path(__file__).resolve().parents[3]
        demo_root = thesis_root / "demo" / "memory_leak_corpus"
        if demo_root.exists():
            return [demo_root]
        return [thesis_root]
