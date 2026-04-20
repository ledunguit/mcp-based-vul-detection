import { buildVerdictCounts } from './reportFormat';

export function OverviewView({ selectedScan, reportData }) {
  const bundles = reportData?.bundles || [];
  const counts = buildVerdictCounts(bundles);
  const performance = reportData?.performance_summary || {};
  const perTool = Object.entries(performance.per_tool || {})
    .sort((a, b) => b[1].total_duration_ms - a[1].total_duration_ms)
    .slice(0, 5);
  const judgeSummary = reportData?.judge_summary || selectedScan?.judge_summary || {};

  return (
    <div className="flex flex-col gap-4">
      <div className="stats stats-vertical border border-base-300 bg-base-100 shadow-sm xl:stats-horizontal">
        <div className="stat">
          <div className="stat-title">Repository</div>
          <div className="stat-value text-lg">{reportData?.repo_path || selectedScan?.workspace_path || 'n/a'}</div>
        </div>
        <div className="stat">
          <div className="stat-title">Bundles</div>
          <div className="stat-value">{reportData?.bundle_count ?? '-'}</div>
        </div>
        <div className="stat">
          <div className="stat-title">Evidence</div>
          <div className="stat-value">{reportData?.evidence_count ?? '-'}</div>
        </div>
        <div className="stat">
          <div className="stat-title">Mode</div>
          <div className="stat-value text-lg">{reportData?.analysis_mode || selectedScan?.analysis_mode || 'n/a'}</div>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="card border border-base-300 bg-base-100 shadow-sm">
          <div className="card-body">
            <h3 className="card-title text-lg">Verdict Distribution</h3>
            <div className="flex flex-wrap gap-3">
              {Object.entries(counts).length ? (
                Object.entries(counts).map(([verdict, count]) => (
                  <div key={verdict} className="rounded-box border border-base-300 bg-base-200/60 px-4 py-3">
                    <p className="text-xs uppercase tracking-[0.2em] text-base-content/50">{verdict}</p>
                    <p className="mt-1 text-2xl font-bold">{count}</p>
                  </div>
                ))
              ) : (
                <p className="text-sm text-base-content/60">No findings loaded.</p>
              )}
            </div>
          </div>
        </div>

        <div className="card border border-base-300 bg-base-100 shadow-sm">
          <div className="card-body">
            <h3 className="card-title text-lg">Judge Summary</h3>
            <div className="grid gap-3 md:grid-cols-2">
              <div className="rounded-box border border-base-300 bg-base-200/60 p-4">
                <p className="text-xs uppercase tracking-[0.2em] text-base-content/45">Effective mode</p>
                <p className="mt-2 text-lg font-semibold">{judgeSummary.effective_mode || 'n/a'}</p>
              </div>
              <div className="rounded-box border border-base-300 bg-base-200/60 p-4">
                <p className="text-xs uppercase tracking-[0.2em] text-base-content/45">Provider</p>
                <p className="mt-2 text-lg font-semibold">{judgeSummary.provider || 'heuristic'}</p>
              </div>
              <div className="rounded-box border border-base-300 bg-base-200/60 p-4">
                <p className="text-xs uppercase tracking-[0.2em] text-base-content/45">LLM success</p>
                <p className="mt-2 text-lg font-semibold">{judgeSummary.llm_success_count ?? 0}</p>
              </div>
              <div className="rounded-box border border-base-300 bg-base-200/60 p-4">
                <p className="text-xs uppercase tracking-[0.2em] text-base-content/45">LLM skipped</p>
                <p className="mt-2 text-lg font-semibold">{judgeSummary.llm_skipped_count ?? 0}</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="card border border-base-300 bg-base-100 shadow-sm">
        <div className="card-body">
          <h3 className="card-title text-lg">Performance Hotspots</h3>
          {perTool.length ? (
            <div className="overflow-auto">
              <table className="table">
                <thead>
                  <tr>
                    <th>Tool</th>
                    <th>Calls</th>
                    <th>Total ms</th>
                    <th>Avg ms</th>
                    <th>Max ms</th>
                  </tr>
                </thead>
                <tbody>
                  {perTool.map(([tool, stats]) => (
                    <tr key={tool}>
                      <td>{tool}</td>
                      <td>{stats.calls}</td>
                      <td>{stats.total_duration_ms}</td>
                      <td>{stats.avg_duration_ms}</td>
                      <td>{stats.max_duration_ms}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-base-content/60">Performance data will appear after loading a completed report.</p>
          )}
        </div>
      </div>
    </div>
  );
}
