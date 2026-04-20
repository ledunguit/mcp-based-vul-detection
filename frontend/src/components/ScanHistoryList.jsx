import { badgeClass, cardBorderClass, formatClock } from '../utils/ui';

const TERMINAL_STATES = new Set(['completed', 'failed', 'cancelled']);

export function ScanHistoryList({
  recentScans,
  selectedScanId,
  terminalScanCount,
  deletingScans,
  onRefresh,
  onSelectScan,
  onRequestDeleteScan,
  onRequestDeleteTerminalScans,
}) {
  return (
    <div className="card border border-base-300 bg-base-100 shadow-xl">
      <div className="card-body gap-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="card-title text-2xl">Scan History</h2>
            <p className="text-sm text-base-content/65">Open a previous or running investigation.</p>
          </div>
          <div className="flex gap-2">
            <button type="button" className="btn btn-ghost btn-sm" onClick={onRefresh}>
              Refresh
            </button>
            <button
              type="button"
              className="btn btn-outline btn-error btn-sm"
              onClick={onRequestDeleteTerminalScans}
              disabled={deletingScans || !terminalScanCount}
            >
              Delete Old
            </button>
          </div>
        </div>

        <div className="flex max-h-[48rem] flex-col gap-3 overflow-auto pr-1">
          {recentScans.length ? (
            recentScans.map((scan) => (
              <div
                key={scan.scan_id}
                className={`card border bg-base-200/55 text-left shadow-sm transition hover:shadow-md ${cardBorderClass(scan.status)} ${
                  selectedScanId === scan.scan_id ? 'ring-2 ring-primary/50' : ''
                }`}
              >
                <div className="card-body gap-3 p-4">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-bold">{scan.scan_id}</span>
                    <span className={badgeClass(scan.status)}>{scan.status}</span>
                  </div>
                  <button type="button" className="text-left" onClick={() => onSelectScan(scan)}>
                    <p className="truncate text-sm text-base-content/75">{scan.workspace_path}</p>
                  </button>
                  <div className="flex items-center justify-between gap-2 text-xs text-base-content/55">
                    <span>created {formatClock(scan.created_at)}</span>
                    <span className="badge badge-outline badge-sm">{scan.analysis_mode || 'no_llm'}</span>
                  </div>
                  <div className="flex justify-end">
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm text-error"
                      onClick={() => onRequestDeleteScan(scan)}
                      disabled={deletingScans || !TERMINAL_STATES.has(scan.status)}
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="rounded-box border border-dashed border-base-300 p-6 text-sm text-base-content/60">
              No persisted scans yet.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
