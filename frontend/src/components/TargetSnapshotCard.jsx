export function TargetSnapshotCard({ selectedWorkspace, customPath, workspacePath, analysisMode }) {
  return (
    <div className="card border border-base-300 bg-base-100 shadow-xl">
      <div className="card-body gap-4">
        <h2 className="card-title text-2xl">Target Snapshot</h2>
        <div className="stats stats-vertical border border-base-300 bg-base-200/60 shadow-sm lg:stats-horizontal">
          <div className="stat">
            <div className="stat-title">Workspace</div>
            <div className="stat-value text-lg">{selectedWorkspace?.name || customPath.trim() || 'Not selected'}</div>
          </div>
          <div className="stat">
            <div className="stat-title">C/C++ files</div>
            <div className="stat-value text-lg">{selectedWorkspace?.c_cpp_file_count ?? '-'}</div>
          </div>
          <div className="stat">
            <div className="stat-title">Judge mode</div>
            <div className="stat-value text-lg">{analysisMode}</div>
          </div>
        </div>

        <div className="rounded-box border border-base-300 bg-base-200/60 p-4">
          <p className="text-xs font-bold uppercase tracking-[0.24em] text-base-content/50">Mounted path</p>
          <code className="mt-2 block overflow-auto text-sm">{customPath.trim() || workspacePath || 'n/a'}</code>
        </div>

        <div className="rounded-box border border-base-300 bg-base-200/60 p-4">
          <p className="text-xs font-bold uppercase tracking-[0.24em] text-base-content/50">Sample files</p>
          {selectedWorkspace?.sample_files?.length ? (
            <ul className="mt-3 flex flex-col gap-2 text-sm text-base-content/75">
              {selectedWorkspace.sample_files.slice(0, 6).map((file) => (
                <li key={file} className="truncate">
                  {file}
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-3 text-sm text-base-content/60">No indexed sample files for this workspace yet.</p>
          )}
        </div>
      </div>
    </div>
  );
}
