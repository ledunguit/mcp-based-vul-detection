from __future__ import annotations

from pathlib import Path

from src.memory_leak.dynamic_orchestration import DynamicValidationPlanner


class DummyEvidence:
    def __init__(self, tool_kind: str):
        self.tool_kind = type("ToolKind", (), {"value": tool_kind})()
        self.kind = "candidate_discovery"
        self.tool = "memory.candidate_scan"


class DummyCandidate:
    def __init__(self) -> None:
        self.candidate_id = "cand-1"
        self.file = "demo.c"
        self.function = "demo"
        self.summary = "potential leak"
        self.line = 2
        self.tags = ["allocation_without_local_free", "path_constraints"]
        self.path_constraints = ["possible_unfreed_allocation:buf@2"]
        self.evidence = [DummyEvidence("static")]


class DummyBundle:
    def __init__(self) -> None:
        self.bundle_id = "bundle-1"
        self.candidate = DummyCandidate()


def test_dynamic_planner_skips_makefile_and_prefers_real_executable(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    makefile = repo / "Makefile"
    makefile.write_text("all:\n\t./demo\n")
    makefile.chmod(0o755)

    binary = repo / "demo"
    binary.write_bytes(b"\x7fELFfake-binary")
    binary.chmod(0o755)

    planner = DynamicValidationPlanner(["valgrind.analyze_memcheck"])
    targets = planner._discover_targets(repo, binary_hint=None)

    assert [path.name for _, path, _ in targets] == ["demo"]


def test_dynamic_planner_rejects_non_binary_hint(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    makefile = repo / "Makefile"
    makefile.write_text("all:\n\t./demo\n")
    makefile.chmod(0o755)

    planner = DynamicValidationPlanner(["valgrind.analyze_memcheck"])
    targets = planner._discover_targets(repo, binary_hint="Makefile")

    assert targets == []


def test_dynamic_planner_prefers_built_targets_from_dynamic_build(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    build_dir = repo / "build"
    build_dir.mkdir(parents=True)
    built = build_dir / "demo"
    built.write_bytes(b"\x7fELFfake-binary")
    built.chmod(0o755)

    planner = DynamicValidationPlanner(["valgrind.analyze_memcheck"])
    targets = planner._discover_targets(
        repo,
        binary_hint=None,
        dynamic_build_result={
            "built_targets": [
                {
                    "path": str(built),
                    "detected_format": "elf",
                    "executable": True,
                    "compatible": True,
                    "sanitizer_instrumented": False,
                }
            ]
        },
    )

    assert [(path.name, source) for _, path, source in targets] == [("demo", "dynamic_build")]


def test_dynamic_planner_prefers_valgrind_for_unsanitized_auto_builds() -> None:
    planner = DynamicValidationPlanner(["lsan.run", "valgrind.analyze_memcheck", "asan.run"])
    assert (
        planner._select_runner_tool(
            dynamic_build_result={
                "built_targets": [
                    {
                        "path": "/tmp/demo",
                        "detected_format": "elf",
                        "executable": True,
                        "compatible": True,
                        "sanitizer_instrumented": False,
                    }
                ]
            }
        )
        == "valgrind.analyze_memcheck"
    )


def test_dynamic_planner_prefers_lsan_for_sanitized_auto_builds() -> None:
    planner = DynamicValidationPlanner(["lsan.run", "valgrind.analyze_memcheck", "asan.run"])
    assert (
        planner._select_runner_tool(
            dynamic_build_result={
                "built_targets": [
                    {
                        "path": "/tmp/demo",
                        "detected_format": "elf",
                        "executable": True,
                        "compatible": True,
                        "sanitizer_instrumented": True,
                    }
                ]
            }
        )
        == "lsan.run"
    )
