"""Dynamic validation planning for memory leak investigation."""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable

from .shared_schema import LeakBundle


class DynamicAnalysisMode(str, Enum):
    OFF = "off"
    SELECTIVE = "selective"
    AGGRESSIVE = "aggressive"


_GENERIC_BINARY_EXCLUDE_SUFFIXES = {
    ".a",
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".d",
    ".dylib",
    ".h",
    ".hpp",
    ".la",
    ".lo",
    ".o",
    ".obj",
    ".py",
    ".sh",
    ".so",
    ".txt",
}

_EXECUTABLE_MAGIC_HEADERS = {
    b"\x7fELF",
    b"MZ",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
}

_INPUT_CANDIDATE_SUFFIXES = {
    ".cfg",
    ".conf",
    ".csv",
    ".dat",
    ".fasta",
    ".fa",
    ".fastq",
    ".fq",
    ".in",
    ".ini",
    ".json",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

_INPUT_HINT_DIR_NAMES = {
    "cases",
    "corpus",
    "data",
    "example",
    "examples",
    "fixture",
    "fixtures",
    "input",
    "inputs",
    "sample",
    "samples",
    "testdata",
}

_EXECUTABLE_HINT_DIR_NAMES = {
    "bin",
    "build",
    "dist",
    "example",
    "examples",
    "out",
    "test",
    "tests",
}

_WALK_EXCLUDED_DIR_NAMES = {
    ".git",
    ".hg",
    ".idea",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "venv",
}

_METADATA_HINT_FILE_NAMES = {
    "CMakeLists.txt",
    "CTestTestfile.cmake",
    "Makefile",
    "README",
    "README.md",
    "README.txt",
    "makefile",
}

_COMMAND_LINE_PREFIXES = ("$", "./", "bin/", "build/", "cmake --build", "ctest", "make ", "ninja ")


@dataclass
class DynamicExecutionTarget:
    tool: str
    target_path: str
    args: list[str] = field(default_factory=list)
    cwd: str | None = None
    timeout_sec: int = 120
    labels: list[str] = field(default_factory=list)
    reason: str = ""
    source: str = "auto_discovered"
    bundle_ids: list[str] = field(default_factory=list)
    candidate_ids: list[str] = field(default_factory=list)
    score: int = 0
    arg_strategy: str = "default"
    input_paths: list[str] = field(default_factory=list)

    def to_report(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class DynamicValidationPlan:
    requested_mode: str
    effective_mode: str
    tool_preference: str
    round_index: int = 1
    targets: list[DynamicExecutionTarget] = field(default_factory=list)
    skipped_reasons: list[str] = field(default_factory=list)
    discovered_executable_count: int = 0
    discovered_input_count: int = 0
    planning_notes: list[str] = field(default_factory=list)

    def to_report(self) -> dict[str, object]:
        return {
            "requested_mode": self.requested_mode,
            "effective_mode": self.effective_mode,
            "tool_preference": self.tool_preference,
            "round_index": self.round_index,
            "target_count": len(self.targets),
            "discovered_executable_count": self.discovered_executable_count,
            "discovered_input_count": self.discovered_input_count,
            "targets": [target.to_report() for target in self.targets],
            "skipped_reasons": list(self.skipped_reasons),
            "planning_notes": list(self.planning_notes),
        }


class DynamicValidationPlanner:
    """Plan dynamic analyzer executions from current bundles and repo layout."""

    def __init__(
        self,
        available_tools: Iterable[str],
        dynamic_mode: str | None = None,
        tool_preference: str | None = None,
    ) -> None:
        self.available_tools = set(available_tools)
        requested_mode = (dynamic_mode or os.getenv("MEMORY_LEAK_DYNAMIC_MODE", "selective")).strip().lower()
        self.dynamic_mode = (
            requested_mode
            if requested_mode in {mode.value for mode in DynamicAnalysisMode}
            else DynamicAnalysisMode.SELECTIVE.value
        )
        self.tool_preference = (tool_preference or os.getenv("MEMORY_LEAK_DYNAMIC_TOOL_PREFERENCE", "auto")).strip().lower()

    def plan(
        self,
        repo_root: Path,
        bundles: list[LeakBundle],
        binary_hint: str | None = None,
        args_hint: str | list[str] | None = None,
        timeout_sec: int | None = None,
        round_index: int = 1,
        exclude_target_paths: set[str] | None = None,
    ) -> DynamicValidationPlan:
        plan = DynamicValidationPlan(
            requested_mode=self.dynamic_mode,
            effective_mode=self.dynamic_mode,
            tool_preference=self.tool_preference,
            round_index=max(1, round_index),
        )
        if self.dynamic_mode == DynamicAnalysisMode.OFF.value:
            plan.skipped_reasons.append("Dynamic validation mode is disabled.")
            return plan

        runner_tool = self._select_runner_tool()
        if runner_tool is None:
            plan.skipped_reasons.append("No dynamic runner tool is available in the connected MCP servers.")
            plan.effective_mode = DynamicAnalysisMode.OFF.value
            return plan

        ranked_bundles = self._rank_bundles_for_dynamic(bundles)
        if not ranked_bundles:
            plan.skipped_reasons.append("No static bundles require dynamic validation.")
            return plan

        timeout_budget = self._normalize_timeout(timeout_sec)
        discovered_targets = self._discover_targets(repo_root=repo_root, binary_hint=binary_hint)
        excluded_targets = {str(Path(path).resolve()) for path in (exclude_target_paths or set())}
        if excluded_targets:
            discovered_targets = [
                item for item in discovered_targets if str(item[1].resolve()) not in excluded_targets
            ]
            if discovered_targets:
                plan.planning_notes.append(
                    f"Excluded {len(excluded_targets)} previously executed dynamic target(s) from this round."
                )
        plan.discovered_executable_count = len(discovered_targets)
        if not discovered_targets:
            plan.skipped_reasons.append(
                "No executable target was discovered. Provide a dynamic binary hint or build the project before dynamic validation."
            )
            return plan
        input_candidates = self._discover_input_candidates(repo_root=repo_root)
        plan.discovered_input_count = len(input_candidates)
        if args_hint:
            plan.planning_notes.append("Dynamic arguments were provided explicitly and override auto-synthesized inputs.")
        elif input_candidates:
            plan.planning_notes.append("Dynamic planner synthesized workload arguments from repository sample/corpus inputs.")
        else:
            plan.planning_notes.append("No sample input was discovered; planner will fall back to zero-argument execution.")
        if plan.round_index > 1:
            plan.planning_notes.append(f"Round {plan.round_index} reprioritizes unresolved bundles after earlier dynamic attempts.")

        bundle_limit = 5 if self.dynamic_mode == DynamicAnalysisMode.SELECTIVE.value else 15
        selected_bundles = ranked_bundles[:bundle_limit]
        candidate_ids = [bundle.candidate.candidate_id for bundle in selected_bundles]
        bundle_ids = [bundle.bundle_id for bundle in selected_bundles]

        executable_limit = 1 if self.dynamic_mode == DynamicAnalysisMode.SELECTIVE.value else min(3, len(discovered_targets))
        labels = [f"bundle:{bundle_id}" for bundle_id in bundle_ids[:5]]
        labels.extend(f"candidate:{candidate_id}" for candidate_id in candidate_ids[:5])
        labels.append(f"mode:{self.dynamic_mode}")

        for score, path, source in discovered_targets[:executable_limit]:
            args, arg_strategy, input_paths = self._select_args_for_target(
                repo_root=repo_root,
                target_path=path,
                args_hint=args_hint,
                input_candidates=input_candidates,
                prioritized_bundles=selected_bundles,
            )
            plan.targets.append(
                DynamicExecutionTarget(
                    tool=runner_tool,
                    target_path=str(path),
                    args=list(args),
                    cwd=str(path.parent),
                    timeout_sec=timeout_budget,
                    labels=sorted(set([*labels, f"target:{path.name}"])),
                    reason=self._target_reason(source, selected_bundles, arg_strategy, input_paths),
                    source=source,
                    bundle_ids=bundle_ids,
                    candidate_ids=candidate_ids,
                    score=score,
                    arg_strategy=arg_strategy,
                    input_paths=input_paths,
                )
            )

        return plan

    def _select_runner_tool(self) -> str | None:
        if self.tool_preference == "valgrind" and "valgrind.analyze_memcheck" in self.available_tools:
            return "valgrind.analyze_memcheck"
        if self.tool_preference == "lsan" and "lsan.run" in self.available_tools:
            return "lsan.run"
        if self.tool_preference == "asan" and "asan.run" in self.available_tools:
            return "asan.run"

        # Prefer LSan in auto mode when available because it can validate more
        # workloads quickly on sanitizer-instrumented binaries.
        for tool_name in ("lsan.run", "valgrind.analyze_memcheck", "asan.run"):
            if tool_name in self.available_tools:
                return tool_name
        return None

    def _rank_bundles_for_dynamic(self, bundles: list[LeakBundle]) -> list[LeakBundle]:
        scored: list[tuple[int, LeakBundle]] = []
        for bundle in bundles:
            score = self._bundle_dynamic_score(bundle)
            if score <= 0:
                continue
            scored.append((score, bundle))
        scored.sort(
            key=lambda item: (
                -item[0],
                item[1].candidate.file or "",
                item[1].candidate.line or 0,
            )
        )
        return [bundle for _, bundle in scored]

    def _bundle_dynamic_score(self, bundle: LeakBundle) -> int:
        candidate = bundle.candidate
        if any(evidence.tool_kind.value == "dynamic" for evidence in candidate.evidence):
            return 0
        attempt_count = self._dynamic_attempt_count(bundle)
        max_attempts = 2 if self.dynamic_mode == DynamicAnalysisMode.SELECTIVE.value else 3
        if attempt_count >= max_attempts:
            return 0

        score = 0
        if "allocation_without_local_free" in candidate.tags:
            score += 3
        if "global_allocation_without_local_free" in candidate.tags:
            score += 2
        if "path_constraints" in candidate.tags:
            score += 3
        if any(evidence.tool == "memory.leakguard_run" for evidence in candidate.evidence):
            score += 4
        if any(
            constraint.startswith("possible_unfreed_allocation:")
            or constraint.startswith("return_without_cleanup:")
            for constraint in candidate.path_constraints
        ):
            score += 4
        if candidate.line is not None:
            score += 1
        if candidate.file:
            score += 1
        if attempt_count:
            score -= attempt_count * 2
        return score

    def _dynamic_attempt_count(self, bundle: LeakBundle) -> int:
        return sum(
            1
            for evidence in bundle.candidate.evidence
            if evidence.tool_kind.value == "orchestrator" and evidence.kind == "dynamic_validation_attempt"
        )

    def _discover_targets(self, repo_root: Path, binary_hint: str | None) -> list[tuple[int, Path, str]]:
        if binary_hint:
            hinted = self._resolve_hint_path(repo_root, binary_hint)
            if hinted.exists() and hinted.is_file() and os.access(hinted, os.X_OK) and self._is_supported_dynamic_target(hinted):
                return [(10_000, hinted, "user_hint")]

        candidates: list[tuple[int, Path]] = []
        for dirpath, dirnames, filenames in os.walk(repo_root):
            dirnames[:] = [name for name in dirnames if name not in _WALK_EXCLUDED_DIR_NAMES]
            current_dir = Path(dirpath)
            for filename in filenames:
                path = current_dir / filename
                if not path.is_file():
                    continue
                if path.is_symlink():
                    continue
                if filename in _METADATA_HINT_FILE_NAMES:
                    continue
                if not os.access(path, os.X_OK):
                    continue
                if path.suffix.lower() in _GENERIC_BINARY_EXCLUDE_SUFFIXES:
                    continue
                if not self._is_supported_dynamic_target(path):
                    continue
                score = self._executable_rank(repo_root, path)
                if score <= 0:
                    continue
                candidates.append((score, path))

        candidates.sort(key=lambda item: (-item[0], str(item[1])))
        return [(score, path, "auto_discovered") for score, path in candidates]

    def _discover_input_candidates(self, repo_root: Path) -> list[Path]:
        candidates: list[tuple[int, Path]] = []
        for dirpath, dirnames, filenames in os.walk(repo_root):
            dirnames[:] = [name for name in dirnames if name not in _WALK_EXCLUDED_DIR_NAMES]
            current_dir = Path(dirpath)
            for filename in filenames:
                path = current_dir / filename
                if not path.is_file():
                    continue
                if path.is_symlink():
                    continue
                if path.suffix.lower() not in _INPUT_CANDIDATE_SUFFIXES:
                    continue
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                if size <= 0 or size > 5_000_000:
                    continue
                score = self._input_candidate_rank(repo_root, path, size)
                if score <= 0:
                    continue
                candidates.append((score, path))

        candidates.sort(key=lambda item: (-item[0], str(item[1])))
        return [path for _, path in candidates[:25]]

    def _executable_rank(self, repo_root: Path, path: Path) -> int:
        score = 1
        parts = path.relative_to(repo_root).parts if path.is_relative_to(repo_root) else path.parts
        lowered_parts = {part.lower() for part in parts}
        if "bin" in lowered_parts:
            score += 40
        if "build" in lowered_parts:
            score += 10
        if lowered_parts.intersection(_EXECUTABLE_HINT_DIR_NAMES):
            score += 12
        if path.name == repo_root.name:
            score += 20
        if "." not in path.name:
            score += 10
        lowered_name = path.name.lower()
        if any(token in lowered_name for token in ("test", "demo", "example", "sample")):
            score += 8
        if any(token in lowered_name for token in ("fuzz", "bench", "coverage")):
            score -= 5
        if path.stat().st_size > 100_000:
            score += 5
        return score

    def _input_candidate_rank(self, repo_root: Path, path: Path, size: int) -> int:
        score = 1
        parts = path.relative_to(repo_root).parts if path.is_relative_to(repo_root) else path.parts
        lowered_parts = {part.lower() for part in parts}
        if lowered_parts.intersection(_INPUT_HINT_DIR_NAMES):
            score += 30
        if path.suffix.lower() in {".json", ".xml", ".txt", ".cfg", ".ini", ".yaml", ".yml"}:
            score += 10
        if size < 64_000:
            score += 10
        elif size < 512_000:
            score += 5
        lowered_name = path.name.lower()
        if any(token in lowered_name for token in ("sample", "example", "demo", "smoke")):
            score += 8
        if any(token in lowered_name for token in ("expected", "golden", "snapshot")):
            score -= 3
        return score

    def _is_supported_dynamic_target(self, path: Path) -> bool:
        try:
            header = path.read_bytes()[:4]
        except OSError:
            return False
        if header.startswith(b"#!"):
            return True
        return header in _EXECUTABLE_MAGIC_HEADERS

    def _select_args_for_target(
        self,
        repo_root: Path,
        target_path: Path,
        args_hint: str | list[str] | None,
        input_candidates: list[Path],
        prioritized_bundles: list[LeakBundle],
    ) -> tuple[list[str], str, list[str]]:
        explicit_args = self._normalize_args(args_hint)
        if explicit_args:
            return explicit_args, "user_supplied", []

        metadata_args, metadata_inputs = self._discover_metadata_args_for_target(repo_root, target_path)
        if metadata_args:
            return metadata_args, "metadata_command_hint", metadata_inputs

        target_name = target_path.name.lower()
        if any(token in target_name for token in ("test", "unit", "spec")):
            return [], "zero_arg_test_binary", []

        selected_input = self._pick_best_input_for_target(repo_root, target_path, input_candidates, prioritized_bundles)
        if selected_input is not None:
            return [str(selected_input)], "auto_input_file", [str(selected_input)]

        return [], "zero_arg_fallback", []

    def _pick_best_input_for_target(
        self,
        repo_root: Path,
        target_path: Path,
        input_candidates: list[Path],
        prioritized_bundles: list[LeakBundle],
    ) -> Path | None:
        if not input_candidates:
            return None

        hotspot_tokens = self._bundle_hotspot_tokens(prioritized_bundles)
        scored: list[tuple[int, Path]] = []
        for path in input_candidates:
            score = 0
            if path.parent == target_path.parent:
                score += 15
            if self._shared_path_hint(repo_root, target_path, path):
                score += 10
            if hotspot_tokens and hotspot_tokens.intersection(self._path_tokens(path)):
                score += 8
            score += max(0, 20 - min(len(str(path.relative_to(repo_root))) // 10, 20))
            scored.append((score, path))

        scored.sort(key=lambda item: (-item[0], str(item[1])))
        return scored[0][1] if scored else None

    def _bundle_hotspot_tokens(self, bundles: list[LeakBundle]) -> set[str]:
        tokens: set[str] = set()
        for bundle in bundles[:5]:
            candidate = bundle.candidate
            if candidate.file:
                tokens.update(self._path_tokens(Path(candidate.file)))
            if candidate.function:
                tokens.add(candidate.function.lower())
        return tokens

    def _shared_path_hint(self, repo_root: Path, target_path: Path, input_path: Path) -> bool:
        target_tokens = self._path_tokens(target_path.relative_to(repo_root) if target_path.is_relative_to(repo_root) else target_path)
        input_tokens = self._path_tokens(input_path.relative_to(repo_root) if input_path.is_relative_to(repo_root) else input_path)
        return bool(target_tokens and input_tokens and target_tokens.intersection(input_tokens))

    def _path_tokens(self, path: Path) -> set[str]:
        tokens: set[str] = set()
        for part in path.parts:
            normalized = "".join(char.lower() if char.isalnum() else " " for char in part)
            tokens.update(token for token in normalized.split() if len(token) >= 3)
        return tokens

    def _discover_metadata_args_for_target(
        self,
        repo_root: Path,
        target_path: Path,
    ) -> tuple[list[str], list[str]]:
        best_score = -1
        best_args: list[str] = []
        best_inputs: list[str] = []
        for metadata_path in self._metadata_hint_files(repo_root):
            score, args, inputs = self._extract_args_from_metadata_file(repo_root, target_path, metadata_path)
            if score > best_score and args:
                best_score = score
                best_args = args
                best_inputs = inputs
        return best_args, best_inputs

    def _metadata_hint_files(self, repo_root: Path) -> list[Path]:
        files: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(repo_root):
            dirnames[:] = [name for name in dirnames if name not in _WALK_EXCLUDED_DIR_NAMES]
            current_dir = Path(dirpath)
            for filename in filenames:
                if filename not in _METADATA_HINT_FILE_NAMES:
                    continue
                path = current_dir / filename
                if path.is_file() and not path.is_symlink():
                    files.append(path)
        return sorted(files)

    def _extract_args_from_metadata_file(
        self,
        repo_root: Path,
        target_path: Path,
        metadata_path: Path,
    ) -> tuple[int, list[str], list[str]]:
        try:
            content = metadata_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return -1, [], []

        target_aliases = self._target_command_aliases(repo_root, target_path)
        best_score = -1
        best_args: list[str] = []
        best_inputs: list[str] = []
        for line in content.splitlines():
            candidate_commands = self._command_candidates_from_line(line)
            for command_text in candidate_commands:
                raw_tokens = self._extract_args_after_target(command_text, target_aliases)
                if raw_tokens is None:
                    continue
                normalized_args, input_paths = self._normalize_metadata_args(repo_root, target_path, raw_tokens)
                score = self._metadata_hint_score(metadata_path, normalized_args, input_paths)
                if score > best_score:
                    best_score = score
                    best_args = normalized_args
                    best_inputs = input_paths
        return best_score, best_args, best_inputs

    def _target_command_aliases(self, repo_root: Path, target_path: Path) -> set[str]:
        aliases = {target_path.name}
        if target_path.is_relative_to(repo_root):
            relative = target_path.relative_to(repo_root)
            aliases.add(str(relative))
            aliases.add(relative.as_posix())
            aliases.add(f"./{relative.as_posix()}")
        aliases.add(str(target_path))
        aliases.add(target_path.as_posix())
        aliases.add(f"./{target_path.name}")
        return {alias for alias in aliases if alias}

    def _command_candidates_from_line(self, line: str) -> list[str]:
        stripped = line.strip()
        if not stripped:
            return []
        if stripped.startswith("add_test("):
            return self._extract_cmake_command_candidates(stripped)
        if any(stripped.startswith(prefix) for prefix in _COMMAND_LINE_PREFIXES):
            return [stripped.lstrip("$").strip()]
        if ":" in stripped and "\t" in stripped:
            _, recipe = stripped.split("\t", 1)
            return [recipe.strip()]
        if re.search(r"\bCOMMAND\b", stripped):
            return [stripped]
        return []

    def _extract_cmake_command_candidates(self, line: str) -> list[str]:
        matches = re.findall(r"COMMAND\s+([^)]+)", line)
        return [match.strip() for match in matches if match.strip()]

    def _extract_args_after_target(self, command_text: str, target_aliases: set[str]) -> list[str] | None:
        try:
            tokens = shlex.split(command_text)
        except ValueError:
            return None
        normalized_aliases = {alias.replace("\\", "/") for alias in target_aliases}
        for index, token in enumerate(tokens):
            normalized = token.replace("\\", "/")
            if normalized in normalized_aliases or normalized.split("/")[-1] in normalized_aliases:
                return tokens[index + 1 :]
        return None

    def _normalize_metadata_args(
        self,
        repo_root: Path,
        target_path: Path,
        raw_tokens: list[str],
    ) -> tuple[list[str], list[str]]:
        args: list[str] = []
        input_paths: list[str] = []
        for token in raw_tokens:
            normalized = token.strip()
            if not normalized:
                continue
            if normalized.startswith("-"):
                args.append(normalized)
                continue
            resolved = self._resolve_metadata_token(repo_root, target_path, normalized)
            if resolved is not None:
                resolved_text = str(resolved)
                args.append(resolved_text)
                if resolved.is_file():
                    input_paths.append(resolved_text)
                continue
            args.append(normalized)
        return args, input_paths

    def _resolve_metadata_token(
        self,
        repo_root: Path,
        target_path: Path,
        token: str,
    ) -> Path | None:
        candidates = [
            (repo_root / token).resolve(),
            (target_path.parent / token).resolve(),
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None

    def _metadata_hint_score(self, metadata_path: Path, args: list[str], input_paths: list[str]) -> int:
        score = 20
        lowered_name = metadata_path.name.lower()
        if lowered_name == "ctesttestfile.cmake":
            score += 30
        elif lowered_name == "cmakelists.txt":
            score += 25
        elif lowered_name in {"makefile", "makefile.txt", "makefile.am", "makefile.in", "makefile"}:
            score += 20
        elif lowered_name.startswith("readme"):
            score += 10
        if args:
            score += 5
        if input_paths:
            score += 15
        return score

    def _resolve_hint_path(self, repo_root: Path, binary_hint: str) -> Path:
        hinted = Path(binary_hint).expanduser()
        if hinted.is_absolute():
            return hinted.resolve()
        return (repo_root / hinted).resolve()

    def _normalize_args(self, args_hint: str | list[str] | None) -> list[str]:
        if args_hint is None:
            return []
        if isinstance(args_hint, str):
            text = args_hint.strip()
            return shlex.split(text) if text else []
        return [str(arg) for arg in args_hint]

    def _normalize_timeout(self, timeout_sec: int | None) -> int:
        if timeout_sec is not None:
            return max(1, int(timeout_sec))
        return max(1, int(os.getenv("MEMORY_LEAK_DYNAMIC_TIMEOUT_SEC", "120")))

    def _target_reason(
        self,
        source: str,
        bundles: list[LeakBundle],
        arg_strategy: str,
        input_paths: list[str],
    ) -> str:
        reason = "Validate the highest-risk static bundles with a dynamic analyzer."
        if source == "user_hint":
            reason += " Target came from an explicit user-provided executable hint."
        else:
            reason += " Target was auto-discovered from executable artifacts in the workspace."
        if arg_strategy == "user_supplied":
            reason += " Arguments came from the user-supplied dynamic_args."
        elif arg_strategy == "metadata_command_hint" and input_paths:
            reason += f" Planner extracted example arguments from project metadata and resolved input {input_paths[0]}."
        elif arg_strategy == "metadata_command_hint":
            reason += " Planner extracted example arguments from project metadata."
        elif arg_strategy == "auto_input_file" and input_paths:
            reason += f" Planner selected repository input {input_paths[0]} as a smoke workload."
        elif arg_strategy == "zero_arg_test_binary":
            reason += " Planner kept zero-argument execution because the binary looks like a test runner."
        else:
            reason += " Planner fell back to zero-argument execution."
        if bundles:
            hotspot = bundles[0].candidate.file or bundles[0].candidate.summary
            reason += f" Highest-priority hotspot: {hotspot}."
        return reason
