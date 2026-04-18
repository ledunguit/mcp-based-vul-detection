APP_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Memory Leak Investigator</title>
  <style>
    :root {
      --ink: #17202a;
      --muted: #52616f;
      --line: #d9e2ec;
      --surface: #fffdf7;
      --accent: #b85c38;
      --accent-2: #2f6f6d;
      --soft: #f4efe6;
    }
    body {
      margin: 0;
      color: var(--ink);
      font-family: Avenir Next, Gill Sans, Trebuchet MS, sans-serif;
      background:
        radial-gradient(circle at top left, rgba(184, 92, 56, .18), transparent 34rem),
        linear-gradient(135deg, #fffaf0 0%, #eef6f5 100%);
    }
    main { max-width: 1180px; margin: 0 auto; padding: 32px 20px 56px; }
    header { display: flex; justify-content: space-between; gap: 24px; align-items: end; margin-bottom: 28px; }
    h1 { font-family: Georgia, serif; font-size: clamp(2rem, 5vw, 4.5rem); line-height: .92; margin: 0; color: #102a43; }
    h2 { margin: 0 0 14px; font-size: 1rem; letter-spacing: .08em; text-transform: uppercase; color: var(--accent); }
    .subtitle { max-width: 520px; color: var(--muted); font-size: 1.03rem; }
    .grid { display: grid; grid-template-columns: 420px 1fr; gap: 18px; align-items: start; }
    .card { background: rgba(255, 253, 247, .88); border: 1px solid var(--line); border-radius: 22px; padding: 18px; box-shadow: 0 18px 50px rgba(16, 42, 67, .08); }
    label { display: block; font-weight: 700; margin: 12px 0 6px; }
    select, input, textarea { width: 100%; box-sizing: border-box; border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; font: inherit; background: white; }
    textarea { min-height: 62px; resize: vertical; }
    button { border: 0; border-radius: 999px; padding: 11px 18px; font-weight: 800; background: var(--accent); color: white; cursor: pointer; }
    button.secondary { background: var(--accent-2); }
    button:disabled { opacity: .5; cursor: not-allowed; }
    .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    .meta { color: var(--muted); font-size: .92rem; }
    .status { display: inline-flex; padding: 5px 10px; border-radius: 999px; background: var(--soft); font-weight: 800; }
    .timeline { display: grid; gap: 8px; max-height: 360px; overflow: auto; padding-right: 4px; }
    .event { border-left: 4px solid var(--accent-2); background: white; border-radius: 12px; padding: 9px 11px; }
    .event strong { display: block; }
    .report { max-height: 560px; overflow: auto; background: white; border-radius: 14px; border: 1px solid var(--line); padding: 14px; }
    pre { white-space: pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .86rem; }
    .metrics { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin: 14px 0; }
    .metric { background: white; border: 1px solid var(--line); border-radius: 16px; padding: 12px; }
    .metric b { font-size: 1.6rem; display: block; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } header { display: block; } }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>Memory Leak<br>Investigator</h1>
      </div>
      <p class="subtitle">Select a mounted C/C++ workspace, launch an MCP-Vul investigation, watch analyzer progress, then inspect the final evidence-backed report.</p>
    </header>
    <section class="grid">
      <div class="card">
        <h2>Workspace</h2>
        <label for="workspace">Allowed workspace</label>
        <select id="workspace"></select>
        <p id="workspaceMeta" class="meta">Loading workspaces...</p>
        <label for="customPath">Or explicit allowed path</label>
        <input id="customPath" placeholder="/workspace/project">
        <label for="buildCommand">Optional build command</label>
        <textarea id="buildCommand" placeholder="make CC=clang"></textarea>
        <label for="limit">File limit</label>
        <input id="limit" type="number" min="1" max="200000" value="500">
        <label for="dynamicRunIds">Dynamic run IDs, comma separated</label>
        <input id="dynamicRunIds" placeholder="run-1, run-2">
        <div class="row" style="margin-top: 16px">
          <button id="startBtn">Start Scan</button>
          <button id="cancelBtn" class="secondary" disabled>Cancel</button>
        </div>
      </div>
      <div class="card">
        <h2>Progress</h2>
        <div class="row">
          <span id="scanId" class="meta">No scan yet</span>
          <span id="status" class="status">idle</span>
        </div>
        <div class="metrics">
          <div class="metric"><b id="bundleCount">-</b><span>Bundles</span></div>
          <div class="metric"><b id="candidateCount">-</b><span>Candidates</span></div>
          <div class="metric"><b id="evidenceCount">-</b><span>Evidence</span></div>
        </div>
        <div id="events" class="timeline"></div>
      </div>
    </section>
    <section class="card" style="margin-top: 18px">
      <div class="row" style="justify-content: space-between">
        <h2>Report</h2>
        <div class="row">
          <button class="secondary" onclick="loadReport('markdown')">Markdown</button>
          <button class="secondary" onclick="loadReport('json')">JSON</button>
          <button class="secondary" onclick="loadReport('snapshot')">Snapshot</button>
          <button class="secondary" onclick="openHtmlReport()">HTML</button>
        </div>
      </div>
      <div class="report"><pre id="report">Run a scan to generate a report.</pre></div>
    </section>
  </main>
  <script>
    let currentScanId = null;
    let eventSource = null;

    async function api(path, options = {}) {
      const res = await fetch(path, {
        ...options,
        headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    }

    async function loadWorkspaces() {
      const data = await api('/api/workspaces');
      const select = document.getElementById('workspace');
      select.innerHTML = '';
      for (const workspace of data.workspaces) {
        const opt = document.createElement('option');
        opt.value = workspace.path;
        opt.textContent = `${workspace.name} (${workspace.c_cpp_file_count} C/C++ files)`;
        select.appendChild(opt);
      }
      document.getElementById('workspaceMeta').textContent = data.allowed_roots.join(' | ');
    }

    async function startScan() {
      const selected = document.getElementById('workspace').value;
      const custom = document.getElementById('customPath').value.trim();
      const payload = {
        workspace_path: custom || selected,
        file_limit: Number(document.getElementById('limit').value || 500),
        build_command: document.getElementById('buildCommand').value.trim() || null,
        dynamic_run_ids: document.getElementById('dynamicRunIds').value.split(',').map(s => s.trim()).filter(Boolean)
      };
      const data = await api('/api/scans', { method: 'POST', body: JSON.stringify(payload) });
      currentScanId = data.scan_id;
      document.getElementById('scanId').textContent = `Scan ${currentScanId}`;
      document.getElementById('status').textContent = data.status;
      document.getElementById('events').innerHTML = '';
      document.getElementById('cancelBtn').disabled = false;
      connectEvents();
    }

    function connectEvents() {
      if (eventSource) eventSource.close();
      eventSource = new EventSource(`/api/scans/${currentScanId}/events`);
      eventSource.onmessage = (msg) => {
        const event = JSON.parse(msg.data);
        renderEvent(event);
        refreshStatus();
        if (['completed', 'failed', 'cancelled'].includes(event.type)) {
          eventSource.close();
          document.getElementById('cancelBtn').disabled = true;
          loadReport('markdown');
        }
      };
    }

    function renderEvent(event) {
      const div = document.createElement('div');
      div.className = 'event';
      const title = event.tool || event.phase || event.type;
      const detail = event.message || event.reason || event.subject || '';
      div.innerHTML = `<strong>${event.event_id}. ${title}</strong><span class="meta">${event.type} ${event.status || ''} ${event.duration_ms || ''}</span><div>${detail}</div>`;
      document.getElementById('events').prepend(div);
    }

    async function refreshStatus() {
      if (!currentScanId) return;
      const data = await api(`/api/scans/${currentScanId}`);
      document.getElementById('status').textContent = data.status;
      document.getElementById('bundleCount').textContent = data.bundle_count ?? '-';
      document.getElementById('candidateCount').textContent = data.candidate_count ?? '-';
      document.getElementById('evidenceCount').textContent = data.evidence_count ?? '-';
    }

    async function cancelScan() {
      if (!currentScanId) return;
      await api(`/api/scans/${currentScanId}/cancel`, { method: 'POST', body: '{}' });
      await refreshStatus();
    }

    async function loadReport(format) {
      if (!currentScanId) return;
      const res = await fetch(`/api/scans/${currentScanId}/report?format=${format}`);
      document.getElementById('report').textContent = await res.text();
    }

    function openHtmlReport() {
      if (!currentScanId) return;
      window.open(`/api/scans/${currentScanId}/report?format=html`, '_blank');
    }

    document.getElementById('startBtn').addEventListener('click', () => startScan().catch(err => alert(err.message)));
    document.getElementById('cancelBtn').addEventListener('click', () => cancelScan().catch(err => alert(err.message)));
    loadWorkspaces().catch(err => { document.getElementById('workspaceMeta').textContent = err.message; });
  </script>
</body>
</html>
"""
