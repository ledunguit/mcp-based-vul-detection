import { badgeClass, describeMode } from '../utils/ui';

export function AppHeader({ theme, onToggleTheme, selectedScan }) {
  return (
    <section className="hero overflow-hidden rounded-box border border-base-300 bg-base-100/85 shadow-2xl backdrop-blur">
      <div className="hero-content flex-col items-stretch gap-6 lg:flex-row lg:items-start lg:justify-between">
        <div className="max-w-3xl">
          <div className="badge badge-primary badge-outline mb-3">MCP-Vul Memory Leak Console</div>
          <h1 className="text-4xl font-black tracking-tight lg:text-6xl">Memory Leak Investigator</h1>
          <p className="mt-3 max-w-2xl text-sm leading-7 text-base-content/70 lg:text-base">
            Configure a target repo, let the orchestrator coordinate static and dynamic analyzers, then review the
            final evidence-backed leak report.
          </p>
        </div>

        <div className="flex w-full max-w-md flex-col gap-3">
          <div className="card border border-base-300 bg-base-200/70 shadow-lg">
            <div className="card-body gap-2 p-5">
              <div className="flex items-center justify-between gap-3">
                <span className={badgeClass(selectedScan?.status)}>{selectedScan?.status || 'idle'}</span>
                <span className="text-xs uppercase tracking-[0.2em] text-base-content/50">current selection</span>
              </div>
              <h2 className="card-title text-lg">{selectedScan ? `Scan ${selectedScan.scan_id}` : 'No active selection'}</h2>
              <p className="text-sm text-base-content/70">{selectedScan?.workspace_path || 'Choose a workspace and start a scan.'}</p>
              <p className="text-xs text-base-content/50">{describeMode(selectedScan)}</p>
            </div>
          </div>

          <button type="button" className="btn btn-outline" onClick={onToggleTheme}>
            {theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          </button>
        </div>
      </div>
    </section>
  );
}
