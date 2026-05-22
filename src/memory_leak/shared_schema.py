"""Load shared leak-centric schemas from the workspace package."""

from __future__ import annotations

import sys
from pathlib import Path


def _ensure_common_schema_importable() -> None:
    current = Path(__file__).resolve()
    workspace_root = current.parents[3]
    common_src = workspace_root / "mcp-memory-common" / "src"
    common_path = str(common_src)
    if common_src.exists() and common_path not in sys.path:
        sys.path.insert(0, common_path)


_ensure_common_schema_importable()

from mcp_memory_common.leak_schema import (  # noqa: E402
    AllocationRecord,
    CleanupObligation,
    CleanupRecord,
    FalsePositiveHint,
    InvestigationVerdict,
    LeakBundle,
    LeakCandidate,
    LeakConfidence,
    LeakEvidence,
    LeakLocation,
    LeakPath,
    LeakSeverity,
    LeakSuggestion,
    MissingCleanupPath,
    OwnershipSummary,
    OwnershipTransfer,
    ReportFinding,
    ToolKind,
    VerdictResult,
)

__all__ = [
    "AllocationRecord",
    "CleanupObligation",
    "CleanupRecord",
    "FalsePositiveHint",
    "InvestigationVerdict",
    "LeakBundle",
    "LeakCandidate",
    "LeakConfidence",
    "LeakEvidence",
    "LeakLocation",
    "LeakPath",
    "LeakSeverity",
    "LeakSuggestion",
    "MissingCleanupPath",
    "OwnershipSummary",
    "OwnershipTransfer",
    "ReportFinding",
    "ToolKind",
    "VerdictResult",
]
