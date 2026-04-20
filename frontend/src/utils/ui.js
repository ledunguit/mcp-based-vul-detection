export function formatClock(epochSeconds) {
  const date = new Date((epochSeconds || Date.now() / 1000) * 1000);
  const time = date.toLocaleTimeString('en-GB', { hour12: false });
  const millis = String(date.getMilliseconds()).padStart(3, '0');
  return `${time}.${millis}`;
}

export function describeMode(data) {
  const mode = data?.analysis_mode || 'no_llm';
  const judge = data?.judge_summary || {};
  if (mode === 'llm_assisted') {
    const effective = judge.effective_mode || 'pending';
    const provider = judge.provider ? ` via ${judge.provider}` : '';
    return `Mode: llm_assisted | Orchestration: deterministic_policy | Judge: ${effective}${provider}`;
  }
  return 'Mode: no_llm | Orchestration: deterministic_policy | Judge: heuristic';
}

export function describeEvent(event) {
  const label = (event.tool || event.phase || event.error_code || event.type || 'event').toUpperCase();
  const message = event.message || event.error || event.reason || event.subject || 'event received';
  const lines = [`[${formatClock(event.timestamp)}] ${label} | ${message}`];
  if (event.subject && event.subject !== message) {
    lines.push(`  subject: ${event.subject}`);
  }
  if (event.reason) {
    lines.push(`  reason: ${event.reason}`);
  }
  if (event.workspace_path) {
    lines.push(`  workspace: ${event.workspace_path}`);
  }
  if (event.analysis_mode) {
    lines.push(`  analysis_mode: ${event.analysis_mode}`);
  }
  if (event.build_command) {
    lines.push(`  build_command: ${event.build_command}`);
  }
  if (event.dynamic_run_ids?.length) {
    lines.push(`  dynamic_run_ids: ${event.dynamic_run_ids.join(', ')}`);
  }
  if (event.status) {
    lines.push(`  status: ${event.status}`);
  }
  if (event.duration_ms !== undefined) {
    lines.push(`  duration_ms: ${event.duration_ms}`);
  }
  if (event.bundle_count !== undefined && event.bundle_count !== null) {
    lines.push(`  bundles: ${event.bundle_count}`);
  }
  if (event.candidate_count !== undefined && event.candidate_count !== null) {
    lines.push(`  candidates: ${event.candidate_count}`);
  }
  if (event.evidence_count !== undefined && event.evidence_count !== null) {
    lines.push(`  evidence: ${event.evidence_count}`);
  }
  if (event.worker_pid) {
    lines.push(`  worker_pid: ${event.worker_pid}`);
  }
  if (event.remediation) {
    lines.push(`  remediation: ${event.remediation}`);
  }
  if (event.detail) {
    String(event.detail)
      .trim()
      .split('\n')
      .slice(0, 3)
      .forEach((line) => lines.push(`  detail: ${line}`));
  }
  return lines;
}

export function badgeClass(status) {
  const value = status || 'idle';
  if (value === 'completed') {
    return 'badge badge-success badge-soft';
  }
  if (value === 'failed') {
    return 'badge badge-error badge-soft';
  }
  if (value === 'cancelled') {
    return 'badge badge-warning badge-soft';
  }
  return 'badge badge-info badge-soft';
}

export function cardBorderClass(status) {
  const value = status || 'idle';
  if (value === 'completed') {
    return 'border-success/40';
  }
  if (value === 'failed') {
    return 'border-error/40';
  }
  if (value === 'cancelled') {
    return 'border-warning/40';
  }
  return 'border-info/40';
}
