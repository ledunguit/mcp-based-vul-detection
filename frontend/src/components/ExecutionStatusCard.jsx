import { formatClock } from '../utils/ui';

export function ExecutionStatusCard({ selectedScan, lastEvent, activeScan, onCancel, onOpenReport }) {
  return (
    <div className="card border border-base-300 bg-base-100 shadow-xl">
      <div className="card-body gap-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <h2 className="card-title text-2xl">Execution Status</h2>
            <p className="text-sm text-base-content/65">Live state for the selected scan.</p>
          </div>
          <div className="flex flex-col gap-3 lg:flex-row">
            <button type="button" className="btn btn-warning" onClick={onCancel} disabled={!activeScan}>
              Cancel
            </button>
            <button type="button" className="btn btn-outline" onClick={onOpenReport} disabled={!selectedScan}>
              Open Report
            </button>
          </div>
        </div>

        <div className="stats stats-vertical border border-base-300 bg-base-200/60 shadow-sm xl:stats-horizontal">
          <div className="stat">
            <div className="stat-title">Selected scan</div>
            <div className="stat-value text-lg">{selectedScan ? selectedScan.scan_id : 'No scan selected'}</div>
          </div>
          <div className="stat">
            <div className="stat-title">Workspace</div>
            <div className="stat-value text-base">{selectedScan?.workspace_path || 'n/a'}</div>
          </div>
          <div className="stat">
            <div className="stat-title">Last event</div>
            <div className="stat-value text-base">{lastEvent ? `${lastEvent.type} at ${formatClock(lastEvent.timestamp)}` : 'n/a'}</div>
          </div>
        </div>

        <div className="stats stats-vertical border border-base-300 bg-base-200/60 shadow-sm md:stats-horizontal">
          <div className="stat">
            <div className="stat-title">Bundles</div>
            <div className="stat-value">{selectedScan?.bundle_count ?? '-'}</div>
          </div>
          <div className="stat">
            <div className="stat-title">Candidates</div>
            <div className="stat-value">{selectedScan?.candidate_count ?? '-'}</div>
          </div>
          <div className="stat">
            <div className="stat-title">Evidence</div>
            <div className="stat-value">{selectedScan?.evidence_count ?? '-'}</div>
          </div>
        </div>
      </div>
    </div>
  );
}
