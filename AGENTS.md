# Repository Guidelines

## Active Scope

`MCP-Vul` is the active memory leak control plane for the thesis workspace.
Do not add new multi-CWE analyzer logic here. Static and dynamic analyzer
implementations should live in dedicated MCP server repositories.

Historical multi-CWE MVP material has been moved to:

- `legacy/multi_cwe_mvp/`

That archive is not part of the active runtime, package build, or default tests.

## Project Structure

- `src/memory_leak/`: active orchestration, candidate management, judge,
  reporting, snapshots, and corpus batch runner.
- `src/mcp_protocol/`: generic MCP client/protocol support used by the control
  plane.
- `src/llm_client.py` and `src/config.py`: LLM/runtime configuration used by the
  judge.
- `tests/test_memory_leak_*.py`: active memory leak tests.
- `tests/test_mcp_protocol.py`: active MCP client/protocol tests.
- `docs/MEMORY_LEAK_CONTROL_PLANE.md`: current control-plane design.
- `docs/MEMORY_LEAK_FEATURE_AUDIT.md`: feature audit and legacy archive notes.

## Commands

- `pip install -e ".[dev]"`: install active package and test dependencies.
- `pytest -q`: run active memory leak and MCP protocol tests.
- `python -m src.memory_leak.control_plane /path/to/c-repo --output report.json`: run a repo scan.
- `python -m src.memory_leak.batch_runner ../demo/memory_leak_corpus/corpus_manifest.json --output-dir ../results/corpus`: run corpus evaluation.

## Coding Guidance

- Keep new code leak-centric and evidence-oriented.
- Keep tool outputs structured and compatible with `mcp-memory-common` leak
  schemas when possible.
- Do not import from `legacy/multi_cwe_mvp/` in active code.
- If old multi-CWE behavior is needed for comparison, add explicit archive docs
  or scripts under `legacy/multi_cwe_mvp/`, not active `src/`.
