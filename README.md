# MCP-Vul Memory Leak Control Plane

`MCP-Vul` is now the orchestration layer for a thesis system focused on
finding and explaining memory leaks in C/C++ repositories.

It is no longer the active home for general multi-CWE detection. Historical
multi-CWE MVP code has been moved under `legacy/multi_cwe_mvp/` for reference,
while the default build, tests, docs, and CLI surface now target memory leak
investigation only.

## Active Scope

- Connect to static and dynamic MCP analyzer servers over HTTP or stdio.
- Scan a C/C++ repository for memory leak candidates.
- Expand candidates with static context, LeakGuard findings, and dynamic run
  evidence when available.
- Cluster related findings into leak bundles.
- Use a judge layer to produce verdicts, explanations, missing evidence, and
  repair suggestions.
- Emit JSON, Markdown, HTML, and snapshot reports for thesis evaluation.

## Main Commands

Run a single repository scan:

```bash
mcp-vul-memory-scan /path/to/c-repo \
  --limit 500 \
  --output results/report.json \
  --markdown-output results/report.md \
  --html-output results/report.html \
  --snapshot-output results/snapshot.json
```

Run a corpus manifest:

```bash
mcp-vul-memory-batch ../demo/memory_leak_corpus/corpus_manifest.json \
  --output-dir ../results/corpus
```

Compare two experiment snapshots:

```bash
mcp-vul-memory-compare results/static-only/snapshot.json results/orchestrated/snapshot.json
```

Run the web application:

```bash
mcp-vul-memory-app --host 127.0.0.1 --port 8090
```

From the thesis workspace root, the same app can run inside Docker with:

```bash
docker compose --env-file .env.example -f docker-compose.thesis-demo.yml up --build memory-app
```

The app exposes:

- `GET /`: workspace selection, progress timeline, and report viewer UI
- `GET /api/workspaces`
- `POST /api/workspaces/validate`
- `POST /api/scans`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/events`
- `GET /api/scans/{scan_id}/report?format=json|markdown|html|snapshot`
- `POST /api/scans/{scan_id}/cancel`

Useful app environment variables:

- `MEMORY_LEAK_APP_WORKSPACE_ROOTS`: allowed workspace roots separated by `:`
- `MEMORY_LEAK_APP_ARTIFACT_DIR`: where scan events and reports are stored
- `MCP_STATIC_SERVER_URL`: static MCP server URL
- `MCP_DYNAMIC_SERVER_URL`: dynamic MCP server URL
- `MEMORY_LEAK_JUDGE_MODE`: `heuristic` or `llm`
- `MEMORY_LEAK_JUDGE_BATCH_SIZE`: number of leak bundles grouped into one LLM
  judge request when `llm_assisted` mode is used
- `MEMORY_LEAK_JUDGE_SCOPE`: `selective` to send only ambiguous bundles to the
  LLM, or `all` to force legacy all-bundle judging
- `MEMORY_LEAK_STATIC_EXPANSION_MODE`: `minimal`, `balanced`, or `full`
- `MEMORY_LEAK_FILE_ANALYSIS_CONCURRENCY`: number of files analyzed in parallel
  during lexical candidate discovery
- `MEMORY_LEAK_STATIC_TOOL_CONCURRENCY`: number of static MCP tools called in
  parallel for a candidate-bearing file

App scan jobs now run in a dedicated worker process by default. This lets the UI
cancel an in-flight orchestration run by terminating the worker process, while
still keeping scan events and artifacts on disk. Remote analyzer containers may
still need explicit server-side cancellation support if they spawn long-running
tool subprocesses after the request has been sent.

Failure responses and failed scan summaries include:

- `error_code`
- `error_category`
- `error`
- `remediation`
- `error_detail`

## MCP Server Configuration

Preferred deployment uses separate Docker Compose stacks for analyzer servers.

```bash
export MCP_STATIC_SERVER_URL="http://localhost:8081/mcp"
export MCP_DYNAMIC_SERVER_URL="http://localhost:8080/mcp"
```

The orchestrator expects memory-leak-oriented tools such as:

- `repo.index_files`
- `memory.candidate_scan`
- `memory.ast_scan`
- `memory.function_summary`
- `memory.call_graph`
- `memory.path_constraints`
- `memory.interprocedural_flow`
- `memory.call_path_summary`
- `memory.leakguard_run`
- `memory.leakguard_get_report`
- `memory.get_leak_bundles`

## Active Package Layout

- `src/memory_leak/`: active memory leak control plane, policy, judge,
  reporting, snapshots, and batch evaluation runner.
- `src/mcp_protocol/`: MCP client/protocol support used by the active control
  plane.
- `src/llm_client.py`: shared LLM client used by the judge.

## Legacy MVP Code

The historical multi-CWE MVP code is archived under `legacy/multi_cwe_mvp/`.
It is not part of the default memory-leak build/test surface:

- `legacy/multi_cwe_mvp/src/`
- `legacy/multi_cwe_mvp/tests/`
- `legacy/multi_cwe_mvp/experiments/`
- `legacy/multi_cwe_mvp/docs/`
- `legacy/multi_cwe_mvp/data/`
- `legacy/multi_cwe_mvp/results/`

This archive can later be moved to a separate repository if thesis comparison
material no longer needs to live beside the active implementation.

See [docs/MEMORY_LEAK_CONTROL_PLANE.md](docs/MEMORY_LEAK_CONTROL_PLANE.md) and
[docs/MEMORY_LEAK_FEATURE_AUDIT.md](docs/MEMORY_LEAK_FEATURE_AUDIT.md).
