# MCP-Vul Memory Leak Control Plane

## Current Direction

`MCP-Vul` is no longer treated as a general multi-CWE analyzer platform.

Its new long-term role is:

- central orchestrator for memory leak investigation
- candidate manager across an entire C/C++ repository
- judge and explanation layer
- future CLI / API / application surface for leak scanning

## What Stays in MCP-Vul

- orchestration policy
- investigation state tracking
- candidate deduplication and clustering
- judge logic
- explanation generation
- fix suggestion generation
- repo-level scan workflows

## What Moves Out

Analyzer implementations should not remain embedded in `MCP-Vul`.

They should live in dedicated MCP servers:

- `mcp-memory-static-analysis-server`
  - AST
  - call graph
  - static candidate discovery
  - LeakGuard adapter
- `mcp-dynamic-analysis-server`
  - Valgrind Memcheck
  - ASan / LSan
  - artifact handling
  - normalized dynamic findings

## Why This Split

The split improves:

- extensibility: new tools can be added without changing orchestrator internals
- comparability: static and dynamic findings can be normalized and judged consistently
- deployment: analyzers can run in separate environments and containers
- experimentation: orchestration strategies can evolve independently from analyzer code

## Required Migration Outcome

At the end of migration, `MCP-Vul` should:

1. connect to external MCP servers
2. discover and schedule memory leak investigation tasks
3. aggregate evidence into leak bundles
4. judge each candidate
5. produce human-readable explanations and repair suggestions

## Scope Reduction

The old multi-CWE artifacts have been moved to `legacy/multi_cwe_mvp/` as
historical MVP work. Active development now focuses on memory leak detection
only.

The target verdict set is:

- `confirmed_leak`
- `likely_leak`
- `inconclusive`
- `false_positive`

## Current Executable Slice

The first executable memory leak control-plane slice now exists in
`src/memory_leak/control_plane.py`.

It currently does:

1. connect to external MCP servers through `src.mcp_protocol.remote_bridge`
2. index C/C++ files in a repo via `repo.index_files`
3. run `memory.candidate_scan` across those files
4. enrich candidate-bearing files with `memory.ast_scan`, `memory.function_summary`, `memory.call_graph`, and `memory.path_constraints` when available
5. optionally run `memory.leakguard_run` as a project-level static analyzer and merge its bundles
6. fall back to `memory.leakguard_get_report` when a containerized LeakGuard run has already produced artifacts
7. optionally merge dynamic evidence from `memory.get_leak_bundles`
8. cluster cross-tool findings into shared leak bundles when they point to the same allocation site
9. assign a leak-centric verdict, explanation, and fix suggestions through an LLM-first judge with heuristic fallback and confidence calibration
10. record investigation tasks and tool invocation traces with reasons, status, and duration
11. emit a machine-readable JSON report with clustered leak bundles
12. optionally emit Markdown, HTML, and compact snapshot reports for thesis demos

For the target deployment model, `MCP-Vul` should connect to MCP servers over HTTP.
This matches running static and dynamic analyzers in separate Docker Compose stacks.

Preferred environment variables:

- `MCP_STATIC_SERVER_URL`
- `MCP_DYNAMIC_SERVER_URL`

Example:

```bash
export MCP_STATIC_SERVER_URL="http://memory-static-analysis:8081/mcp"
export MCP_DYNAMIC_SERVER_URL="http://dynamic-analysis:8080/mcp"

python -m src.memory_leak.control_plane /path/to/c-repo --limit 200
```

Judge mode can be switched with:

- `MEMORY_LEAK_JUDGE_MODE=heuristic`
- `MEMORY_LEAK_JUDGE_MODE=llm`

If a project-level analyzer such as LeakGuard needs a build step, pass:

```bash
python -m src.memory_leak.control_plane /path/to/c-repo \
  --limit 200 \
  --build-command "make CC=clang -j8"
```

To write both machine-readable and human-readable reports:

```bash
python -m src.memory_leak.control_plane /path/to/c-repo \
  --limit 200 \
  --output results/memory-leak-report.json \
  --markdown-output results/memory-leak-report.md \
  --html-output results/memory-leak-report.html \
  --snapshot-output results/memory-leak-snapshot.json
```

The LLM judge is calibrated after parsing:

- `confirmed_leak` requires dynamic evidence; without it, the verdict is
  downgraded to `likely_leak`
- dynamic evidence can upgrade an overly conservative LLM verdict to
  `confirmed_leak`
- high confidence from weak, uncorroborated evidence is lowered

The control plane now uses `memory-leak-investigation-policy/v1`:

- always index files and run lexical candidate discovery
- only run expensive per-file static expansion when a file has candidates
- use LeakGuard project-level evidence when the static MCP server exposes it
- merge supplied dynamic run bundles before judging
- record every tool call in `tool_invocations`
- record per-file investigation state in `investigation_tasks`

Snapshots can be compared with:

```bash
python -m src.memory_leak.compare_snapshots \
  results/static-only-snapshot.json \
  results/orchestrated-snapshot.json \
  --output results/comparison.json
```

Corpus manifests can be run with:

```bash
python -m src.memory_leak.batch_runner \
  ../demo/memory_leak_corpus/corpus_manifest.json \
  --output-dir ../results/corpus
```

## Web Application Surface

`src.memory_leak_app.server` provides a lightweight web application around the
control plane. It intentionally uses the Python standard library so the thesis
demo can run without adding a frontend/backend framework dependency.

The app provides:

- workspace discovery from configured allowed roots
- scan job creation
- scan status lookup
- progress and log streaming through Server-Sent Events
- persistent scan artifacts under `MEMORY_LEAK_APP_ARTIFACT_DIR`
- JSON, Markdown, HTML, and snapshot report retrieval
- a minimal browser UI for workspace selection, scan launch, live progress, and
  report viewing

Run locally:

```bash
python -m src.memory_leak_app.server --host 127.0.0.1 --port 8090
```

Recommended workspace-level script:

```bash
../scripts/run_memory_leak_app.sh
```

Local development fallback variables for running servers directly from the workspace source tree:

- `MCP_STATIC_SERVER_CMD`
- `MCP_STATIC_SERVER_CWD`
- `MCP_STATIC_SERVER_PYTHONPATH`
- `MCP_DYNAMIC_SERVER_CMD`
- `MCP_DYNAMIC_SERVER_CWD`
- `MCP_DYNAMIC_SERVER_PYTHONPATH`

Example:

```bash
export MCP_STATIC_SERVER_CMD="python -m mcp_memory_static_analysis_server.app"
export MCP_STATIC_SERVER_CWD="/Users/zed/Documents/Master/Thesis/mcp-memory-static-analysis-server"
export MCP_STATIC_SERVER_PYTHONPATH="/Users/zed/Documents/Master/Thesis/mcp-memory-static-analysis-server/src"

export MCP_DYNAMIC_SERVER_CMD="python -m mcp_dynamic_analysis_server.app"
export MCP_DYNAMIC_SERVER_CWD="/Users/zed/Documents/Master/Thesis/mcp-dynamic-analysis-server"
export MCP_DYNAMIC_SERVER_PYTHONPATH="/Users/zed/Documents/Master/Thesis/mcp-dynamic-analysis-server/src:/Users/zed/Documents/Master/Thesis/mcp-memory-common/src"

python -m src.memory_leak.control_plane /path/to/c-repo --limit 200
```
