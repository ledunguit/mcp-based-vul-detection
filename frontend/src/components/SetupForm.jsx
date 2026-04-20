export function SetupForm({
  loadingWorkspaces,
  workspaces,
  workspacePath,
  setWorkspacePath,
  allowedRoots,
  customPath,
  setCustomPath,
  analysisMode,
  setAnalysisMode,
  fileLimit,
  setFileLimit,
  buildCommand,
  setBuildCommand,
  dynamicRunIds,
  setDynamicRunIds,
  activeScan,
  onStartScan,
  onGoActivity,
}) {
  const canStartScan = !activeScan && Boolean(customPath.trim() || workspacePath);

  return (
    <div className="card border border-base-300 bg-base-100 shadow-xl">
      <div className="card-body gap-4">
        <div className="flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <h2 className="card-title text-2xl">Scan Setup</h2>
            <p className="text-sm text-base-content/65">Define the target repository and investigation strategy.</p>
          </div>
          <div className="badge badge-info badge-soft">{loadingWorkspaces ? 'loading' : `${workspaces.length} mounted`}</div>
        </div>

        <fieldset className="fieldset">
          <legend className="fieldset-legend">Allowed workspace</legend>
          <select className="select select-bordered w-full" value={workspacePath} onChange={(event) => setWorkspacePath(event.target.value)}>
            {workspaces.map((workspace) => (
              <option key={workspace.path} value={workspace.path}>
                {workspace.name} ({workspace.c_cpp_file_count} C/C++ files)
              </option>
            ))}
          </select>
          <p className="label text-xs text-base-content/50">{loadingWorkspaces ? 'Loading workspaces...' : allowedRoots.join(' | ')}</p>
        </fieldset>

        <fieldset className="fieldset">
          <legend className="fieldset-legend">Or explicit allowed path</legend>
          <input className="input input-bordered w-full" placeholder="/workspace/project" value={customPath} onChange={(event) => setCustomPath(event.target.value)} />
        </fieldset>

        <div className="grid gap-4 lg:grid-cols-2">
          <fieldset className="fieldset">
            <legend className="fieldset-legend">Analysis mode</legend>
            <select className="select select-bordered w-full" value={analysisMode} onChange={(event) => setAnalysisMode(event.target.value)}>
              <option value="no_llm">No LLM</option>
              <option value="llm_assisted">LLM-assisted judge</option>
            </select>
          </fieldset>

          <fieldset className="fieldset">
            <legend className="fieldset-legend">File limit</legend>
            <input className="input input-bordered w-full" type="number" min="1" max="200000" value={fileLimit} onChange={(event) => setFileLimit(event.target.value)} />
          </fieldset>
        </div>

        <fieldset className="fieldset">
          <legend className="fieldset-legend">Optional build command</legend>
          <textarea className="textarea textarea-bordered min-h-28 w-full" placeholder="make CC=clang" value={buildCommand} onChange={(event) => setBuildCommand(event.target.value)} />
        </fieldset>

        <fieldset className="fieldset">
          <legend className="fieldset-legend">Dynamic run IDs</legend>
          <input className="input input-bordered w-full" placeholder="run-1, run-2" value={dynamicRunIds} onChange={(event) => setDynamicRunIds(event.target.value)} />
        </fieldset>

        <div className="flex flex-col gap-3 lg:flex-row lg:justify-end">
          <button type="button" className="btn btn-primary" onClick={onStartScan} disabled={!canStartScan}>
            Start Scan
          </button>
          <button type="button" className="btn btn-outline" onClick={onGoActivity}>
            Go to Activity
          </button>
        </div>
      </div>
    </div>
  );
}
